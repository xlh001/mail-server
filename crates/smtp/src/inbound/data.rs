/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ArcSeal, AuthResult, DkimSign};
use crate::{
    core::{Session, SessionAddress, State},
    inbound::milter::Modification,
    queue::{
        self, Message, MessageSource, MessageWrapper, QueueEnvelope, Schedule, quota::HasQueueQuota,
    },
    reporting::analysis::AnalyzeReport,
    scripts::ScriptResult,
};
use common::{
    config::{
        smtp::{
            auth::VerifyStrategy,
            queue::{QueueExpiry, QueueName},
            session::Stage,
        },
        spamfilter::SpamFilterAction,
    },
    listener::SessionStream,
    psl,
    scripts::ScriptModification,
};
use mail_auth::{
    AuthenticatedMessage, AuthenticationResults, DkimResult, DmarcResult, ReceivedSpf,
    common::{headers::HeaderWriter, verify::VerifySignature},
    dmarc::{self, verify::DmarcParameters},
};
use mail_builder::headers::{date::Date, message_id::generate_message_id_header};
use mail_parser::MessageParser;
use sieve::runtime::Variable;
use smtp_proto::{
    MAIL_BY_RETURN, RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE, RCPT_NOTIFY_NEVER, RCPT_NOTIFY_SUCCESS,
};
use std::{
    borrow::Cow,
    time::{Instant, SystemTime},
};
use trc::SmtpEvent;
use utils::config::Rate;

impl<T: SessionStream> Session<T> {
    pub async fn queue_message(&mut self) -> Cow<'static, [u8]> {
        // Parse message
        let raw_message = std::mem::take(&mut self.data.message);
        let parsed_message = match MessageParser::new()
            .parse(&raw_message)
            .filter(|p| p.headers().iter().any(|h| !h.name.is_other()))
        {
            Some(parsed_message) => parsed_message,
            None => {
                trc::event!(
                    Smtp(SmtpEvent::MessageParseFailed),
                    SpanId = self.data.session_id,
                );

                return (&b"550 5.7.7 Failed to parse message.\r\n"[..]).into();
            }
        };

        // Authenticate message
        let auth_message = AuthenticatedMessage::from_parsed(
            &parsed_message,
            self.server.core.smtp.mail_auth.dkim.strict,
        );
        let has_date_header = auth_message.has_date_header();
        let has_message_id_header = auth_message.has_message_id_header();

        // Loop detection
        let dc = &self.server.core.smtp.session.data;
        let ac = &self.server.core.smtp.mail_auth;
        let rc = &self.server.core.smtp.report;
        if auth_message.received_headers_count()
            > self
                .server
                .eval_if(&dc.max_received_headers, self, self.data.session_id)
                .await
                .unwrap_or(50)
        {
            trc::event!(
                Smtp(SmtpEvent::LoopDetected),
                SpanId = self.data.session_id,
                Total = auth_message.received_headers_count(),
            );

            return (&b"450 4.4.6 Too many Received headers. Possible loop detected.\r\n"[..])
                .into();
        }

        // Verify DKIM
        let dkim = self
            .server
            .eval_if(&ac.dkim.verify, self, self.data.session_id)
            .await
            .unwrap_or(VerifyStrategy::Relaxed);
        let dmarc = self
            .server
            .eval_if(&ac.dmarc.verify, self, self.data.session_id)
            .await
            .unwrap_or(VerifyStrategy::Relaxed);
        let dkim_output = if dkim.verify() || dmarc.verify() {
            let time = Instant::now();
            let dkim_output = self
                .server
                .core
                .smtp
                .resolvers
                .dns
                .verify_dkim(self.server.inner.cache.build_auth_parameters(&auth_message))
                .await;
            let pass = dkim_output
                .iter()
                .any(|d| matches!(d.result(), DkimResult::Pass));
            let strict = dkim.is_strict();
            let rejected = strict && !pass;

            // Send reports for failed signatures
            if let Some(rate) = self
                .server
                .eval_if::<Rate, _>(&rc.dkim.send, self, self.data.session_id)
                .await
            {
                for output in &dkim_output {
                    if let Some(rcpt) = output.failure_report_addr() {
                        self.send_dkim_report(rcpt, &auth_message, &rate, rejected, output)
                            .await;
                    }
                }
            }

            trc::event!(
                Smtp(if pass {
                    SmtpEvent::DkimPass
                } else {
                    SmtpEvent::DkimFail
                }),
                SpanId = self.data.session_id,
                Strict = strict,
                Result = dkim_output.iter().map(trc::Error::from).collect::<Vec<_>>(),
                Elapsed = time.elapsed(),
            );

            if rejected {
                // 'Strict' mode violates the advice of Section 6.1 of RFC6376
                return if dkim_output
                    .iter()
                    .any(|d| matches!(d.result(), DkimResult::TempError(_)))
                {
                    (&b"451 4.7.20 No passing DKIM signatures found.\r\n"[..]).into()
                } else {
                    (&b"550 5.7.20 No passing DKIM signatures found.\r\n"[..]).into()
                };
            }

            dkim_output
        } else {
            vec![]
        };

        // Verify ARC
        let arc = self
            .server
            .eval_if(&ac.arc.verify, self, self.data.session_id)
            .await
            .unwrap_or(VerifyStrategy::Relaxed);
        let arc_sealer = self
            .server
            .eval_if::<String, _>(&ac.arc.seal, self, self.data.session_id)
            .await
            .and_then(|name| self.server.get_arc_sealer(&name, self.data.session_id));
        let arc_output = if arc.verify() || arc_sealer.is_some() {
            let time = Instant::now();
            let arc_output = self
                .server
                .core
                .smtp
                .resolvers
                .dns
                .verify_arc(self.server.inner.cache.build_auth_parameters(&auth_message))
                .await;

            let strict = arc.is_strict();
            let pass = matches!(arc_output.result(), DkimResult::Pass | DkimResult::None);

            trc::event!(
                Smtp(if pass {
                    SmtpEvent::ArcPass
                } else {
                    SmtpEvent::ArcFail
                }),
                SpanId = self.data.session_id,
                Strict = strict,
                Result = trc::Error::from(arc_output.result()),
                Elapsed = time.elapsed(),
            );

            if strict && !pass {
                return if matches!(arc_output.result(), DkimResult::TempError(_)) {
                    (&b"451 4.7.29 ARC validation failed.\r\n"[..]).into()
                } else {
                    (&b"550 5.7.29 ARC validation failed.\r\n"[..]).into()
                };
            }

            arc_output.into()
        } else {
            None
        };

        // Build authentication results header
        let mail_from = self.data.mail_from.as_ref().unwrap();
        let mut auth_results = AuthenticationResults::new(&self.hostname);
        if !dkim_output.is_empty() {
            auth_results = auth_results.with_dkim_results(&dkim_output, auth_message.from())
        }
        if let Some(spf_ehlo) = &self.data.spf_ehlo {
            auth_results = auth_results.with_spf_ehlo_result(
                spf_ehlo,
                self.data.remote_ip,
                &self.data.helo_domain,
            );
        }
        if let Some(spf_mail_from) = &self.data.spf_mail_from {
            auth_results = auth_results.with_spf_mailfrom_result(
                spf_mail_from,
                self.data.remote_ip,
                &mail_from.address,
                &self.data.helo_domain,
            );
        }
        if let Some(iprev) = &self.data.iprev {
            auth_results = auth_results.with_iprev_result(iprev, self.data.remote_ip);
        }

        // Verify DMARC
        let is_report = self.is_report();
        let (dmarc_result, dmarc_policy) = match &self.data.spf_mail_from {
            Some(spf_output) if dmarc.verify() => {
                let time = Instant::now();
                let dmarc_output =
                    self.server
                        .core
                        .smtp
                        .resolvers
                        .dns
                        .verify_dmarc(self.server.inner.cache.build_auth_parameters(
                            DmarcParameters {
                                message: &auth_message,
                                dkim_output: &dkim_output,
                                rfc5321_mail_from_domain: if !mail_from.domain.is_empty() {
                                    &mail_from.domain
                                } else {
                                    &self.data.helo_domain
                                },
                                spf_output,
                                domain_suffix_fn: |domain| {
                                    psl::domain_str(domain).unwrap_or(domain)
                                },
                            },
                        ))
                        .await;

                let pass = matches!(dmarc_output.spf_result(), DmarcResult::Pass)
                    || matches!(dmarc_output.dkim_result(), DmarcResult::Pass);
                let strict = dmarc.is_strict();
                let rejected = strict && dmarc_output.policy() == dmarc::Policy::Reject && !pass;
                let is_temp_fail = rejected
                    && matches!(dmarc_output.spf_result(), DmarcResult::TempError(_))
                    || matches!(dmarc_output.dkim_result(), DmarcResult::TempError(_));

                // Add to DMARC output to the Authentication-Results header
                auth_results = auth_results.with_dmarc_result(&dmarc_output);
                let dmarc_result = if pass {
                    DmarcResult::Pass
                } else if dmarc_output.spf_result() != &DmarcResult::None {
                    dmarc_output.spf_result().clone()
                } else if dmarc_output.dkim_result() != &DmarcResult::None {
                    dmarc_output.dkim_result().clone()
                } else {
                    DmarcResult::None
                };
                let dmarc_policy = dmarc_output.policy();

                trc::event!(
                    Smtp(if pass {
                        SmtpEvent::DmarcPass
                    } else {
                        SmtpEvent::DmarcFail
                    }),
                    SpanId = self.data.session_id,
                    Strict = strict,
                    Domain = dmarc_output.domain().to_string(),
                    Policy = dmarc_policy.to_string(),
                    Result = trc::Error::from(&dmarc_result),
                    Elapsed = time.elapsed(),
                );

                // Send DMARC report
                if dmarc_output.requested_reports() && !is_report {
                    self.send_dmarc_report(
                        &auth_message,
                        &auth_results,
                        rejected,
                        dmarc_output,
                        &dkim_output,
                        &arc_output,
                    )
                    .await;
                }

                if rejected {
                    return if is_temp_fail {
                        (&b"451 4.7.1 Email temporarily rejected per DMARC policy.\r\n"[..]).into()
                    } else {
                        (&b"550 5.7.1 Email rejected per DMARC policy.\r\n"[..]).into()
                    };
                }

                (dmarc_result.into(), dmarc_policy.into())
            }
            _ => (None, None),
        };

        // Analyze reports
        if is_report {
            if !rc.analysis.forward {
                self.server.analyze_report(
                    mail_parser::Message {
                        html_body: parsed_message.html_body,
                        text_body: parsed_message.text_body,
                        attachments: parsed_message.attachments,
                        parts: parsed_message
                            .parts
                            .into_iter()
                            .map(|p| p.into_owned())
                            .collect(),
                        raw_message: b"".into(),
                    },
                    self.data.session_id,
                );
                self.data.messages_sent += 1;
                return (b"250 2.0.0 Message queued for delivery.\r\n"[..]).into();
            } else {
                self.server.analyze_report(
                    mail_parser::Message {
                        html_body: parsed_message.html_body.clone(),
                        text_body: parsed_message.text_body.clone(),
                        attachments: parsed_message.attachments.clone(),
                        parts: parsed_message
                            .parts
                            .iter()
                            .map(|p| p.clone().into_owned())
                            .collect(),
                        raw_message: b"".into(),
                    },
                    self.data.session_id,
                );
            }
        }

        // Add Received header
        let message_id = self.server.inner.data.queue_id_gen.generate();
        let mut headers = Vec::with_capacity(64);
        if self
            .server
            .eval_if(&dc.add_received, self, self.data.session_id)
            .await
            .unwrap_or(true)
        {
            self.write_received(&mut headers, message_id)
        }

        // Add authentication results header
        if self
            .server
            .eval_if(&dc.add_auth_results, self, self.data.session_id)
            .await
            .unwrap_or(true)
        {
            auth_results.write_header(&mut headers);
        }

        // Add Received-SPF header
        if let Some(spf_output) = &self.data.spf_mail_from {
            if self
                .server
                .eval_if(&dc.add_received_spf, self, self.data.session_id)
                .await
                .unwrap_or(true)
            {
                ReceivedSpf::new(
                    spf_output,
                    self.data.remote_ip,
                    &self.data.helo_domain,
                    &mail_from.address_lcase,
                    &self.hostname,
                )
                .write_header(&mut headers);
            }
        }

        // ARC Seal
        if let (Some(arc_sealer), Some(arc_output)) = (arc_sealer, &arc_output) {
            if !dkim_output.is_empty() && arc_output.can_be_sealed() {
                match arc_sealer.seal(&auth_message, &auth_results, arc_output) {
                    Ok(set) => {
                        set.write_header(&mut headers);
                    }
                    Err(err) => {
                        trc::error!(
                            trc::Error::from(err)
                                .span_id(self.data.session_id)
                                .details("Failed to ARC seal message")
                        );
                    }
                }
            }
        }

        // Run SPAM filter
        if self.server.core.spam.enabled
            && self
                .server
                .eval_if(&dc.spam_filter, self, self.data.session_id)
                .await
                .unwrap_or(true)
        {
            match self
                .spam_classify(
                    &parsed_message,
                    &dkim_output,
                    (&arc_output).into(),
                    dmarc_result.as_ref(),
                    dmarc_policy.as_ref(),
                )
                .await
            {
                SpamFilterAction::Allow(spam_headers) => {
                    if !spam_headers.is_empty() {
                        headers.extend_from_slice(spam_headers.as_bytes());
                    }
                }
                SpamFilterAction::Discard => {
                    self.data.messages_sent += 1;
                    return (b"250 2.0.0 Message queued for delivery.\r\n"[..]).into();
                }
                SpamFilterAction::Reject => {
                    self.data.messages_sent += 1;
                    return (b"550 5.7.1 Message rejected due to excessive spam score.\r\n"[..])
                        .into();
                }
            }
        }

        // Run Milter filters
        let mut modifications = Vec::new();
        match self.run_milters(Stage::Data, (&auth_message).into()).await {
            Ok(modifications_) => {
                if !modifications_.is_empty() {
                    modifications = modifications_;
                }
            }
            Err(response) => {
                return response.into_bytes();
            }
        };

        // Run MTA Hooks
        match self
            .run_mta_hooks(Stage::Data, (&auth_message).into(), message_id.into())
            .await
        {
            Ok(modifications_) => {
                if !modifications_.is_empty() {
                    modifications.retain(|m| !matches!(m, Modification::ReplaceBody { .. }));
                    modifications.extend(modifications_);
                }
            }
            Err(response) => {
                return response.into_bytes();
            }
        };

        // Apply modifications
        let mut edited_message = if !modifications.is_empty() {
            self.data
                .apply_milter_modifications(modifications, &auth_message)
        } else {
            None
        };

        // Sieve filtering
        if let Some((script, script_id)) = self
            .server
            .eval_if::<String, _>(&dc.script, self, self.data.session_id)
            .await
            .and_then(|name| {
                self.server
                    .get_trusted_sieve_script(&name, self.data.session_id)
                    .map(|s| (s, name))
            })
        {
            let params = self
                .build_script_parameters("data")
                .with_auth_headers(&headers)
                .set_variable(
                    "arc.result",
                    arc_output
                        .as_ref()
                        .map(|a| a.result().as_str())
                        .unwrap_or_default(),
                )
                .set_variable(
                    "dkim.result",
                    dkim_output
                        .iter()
                        .find(|r| matches!(r.result(), DkimResult::Pass))
                        .or_else(|| dkim_output.first())
                        .map(|r| r.result().as_str())
                        .unwrap_or_default(),
                )
                .set_variable(
                    "dkim.domains",
                    dkim_output
                        .iter()
                        .filter_map(|r| {
                            if matches!(r.result(), DkimResult::Pass) {
                                r.signature()
                                    .map(|s| Variable::from(s.domain().to_lowercase()))
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>(),
                )
                .set_variable(
                    "dmarc.result",
                    dmarc_result
                        .as_ref()
                        .map(|a| a.as_str())
                        .unwrap_or_default(),
                )
                .set_variable(
                    "dmarc.policy",
                    dmarc_policy
                        .as_ref()
                        .map(|a| a.as_str())
                        .unwrap_or_default(),
                )
                .with_message(parsed_message);

            let modifications = match self.run_script(script_id, script.clone(), params).await {
                ScriptResult::Accept { modifications } => modifications,
                ScriptResult::Replace {
                    message,
                    modifications,
                } => {
                    edited_message = message.into();
                    modifications
                }
                ScriptResult::Reject(message) => {
                    return message.as_bytes().to_vec().into();
                }
                ScriptResult::Discard => {
                    return (b"250 2.0.0 Message queued for delivery.\r\n"[..]).into();
                }
            };

            // Apply modifications
            for modification in modifications {
                match modification {
                    ScriptModification::AddHeader { name, value } => {
                        headers.extend_from_slice(name.as_bytes());
                        headers.extend_from_slice(b": ");
                        headers.extend_from_slice(value.as_bytes());
                        if !value.ends_with('\n') {
                            headers.extend_from_slice(b"\r\n");
                        }
                    }
                    ScriptModification::SetEnvelope { name, value } => {
                        self.data.apply_envelope_modification(name, value);
                    }
                }
            }
        }

        // Build message
        let mail_from = self.data.mail_from.clone().unwrap();
        let rcpt_to = std::mem::take(&mut self.data.rcpt_to);
        let mut message = self
            .build_message(mail_from, rcpt_to, message_id, self.data.session_id)
            .await;

        // Add Return-Path
        if self
            .server
            .eval_if(&dc.add_return_path, self, self.data.session_id)
            .await
            .unwrap_or(true)
        {
            headers.extend_from_slice(b"Return-Path: <");
            headers.extend_from_slice(message.message.return_path.as_bytes());
            headers.extend_from_slice(b">\r\n");
        }

        // Add any missing headers
        if !has_date_header
            && self
                .server
                .eval_if(&dc.add_date, self, self.data.session_id)
                .await
                .unwrap_or(true)
        {
            headers.extend_from_slice(b"Date: ");
            headers.extend_from_slice(Date::now().to_rfc822().as_bytes());
            headers.extend_from_slice(b"\r\n");
        }
        if !has_message_id_header
            && self
                .server
                .eval_if(&dc.add_message_id, self, self.data.session_id)
                .await
                .unwrap_or(true)
        {
            headers.extend_from_slice(b"Message-ID: ");
            let _ = generate_message_id_header(&mut headers, &self.hostname);
            headers.extend_from_slice(b"\r\n");
        }

        // DKIM sign
        let raw_message = edited_message.as_deref().unwrap_or(raw_message.as_slice());
        for signer in self
            .server
            .eval_if::<Vec<String>, _>(&ac.dkim.sign, self, self.data.session_id)
            .await
            .unwrap_or_default()
        {
            if let Some(signer) = self.server.get_dkim_signer(&signer, self.data.session_id) {
                match signer.sign_chained(&[headers.as_ref(), raw_message]) {
                    Ok(signature) => {
                        signature.write_header(&mut headers);
                    }
                    Err(err) => {
                        trc::error!(
                            trc::Error::from(err)
                                .span_id(self.data.session_id)
                                .details("Failed to DKIM sign message")
                        );
                    }
                }
            }
        }

        // Update size
        message.message.size = (raw_message.len() + headers.len()) as u64;

        // Verify queue quota
        if self.server.has_quota(&mut message).await {
            // Prepare webhook event
            let queue_id = message.queue_id;

            // Queue message
            let source = if !self.is_authenticated() {
                MessageSource::Unauthenticated(
                    dmarc_result.is_some_and(|result| result == DmarcResult::Pass),
                )
            } else {
                MessageSource::Authenticated
            };
            if message
                .queue(
                    Some(&headers),
                    raw_message,
                    self.data.session_id,
                    &self.server,
                    source,
                )
                .await
            {
                self.state = State::Accepted(queue_id);
                self.data.messages_sent += 1;
                format!("250 2.0.0 Message queued with id {queue_id:x}.\r\n")
                    .into_bytes()
                    .into()
            } else {
                (b"451 4.3.5 Unable to accept message at this time.\r\n"[..]).into()
            }
        } else {
            (b"452 4.3.1 Mail system full, try again later.\r\n"[..]).into()
        }
    }

    pub async fn build_message(
        &self,
        mail_from: SessionAddress,
        mut rcpt_to: Vec<SessionAddress>,
        queue_id: u64,
        span_id: u64,
    ) -> MessageWrapper {
        // Build message
        let created = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let mut message = Message {
            created,
            return_path: mail_from.address,
            return_path_lcase: mail_from.address_lcase,
            return_path_domain: mail_from.domain,
            recipients: Vec::with_capacity(rcpt_to.len()),
            flags: mail_from.flags,
            priority: self.data.priority,
            size: 0,
            env_id: mail_from.dsn_info,
            blob_hash: Default::default(),
            quota_keys: Vec::new(),
            received_from_ip: self.data.remote_ip,
            received_via_port: self.data.local_port,
        };

        // Add recipients
        let future_release = self.data.future_release;
        rcpt_to.sort_unstable();
        for rcpt in rcpt_to {
            message.recipients.push(queue::Recipient {
                address: rcpt.address,
                address_lcase: rcpt.address_lcase,
                status: queue::Status::Scheduled,
                flags: if rcpt.flags
                    & (RCPT_NOTIFY_DELAY
                        | RCPT_NOTIFY_FAILURE
                        | RCPT_NOTIFY_SUCCESS
                        | RCPT_NOTIFY_NEVER)
                    != 0
                {
                    rcpt.flags
                } else {
                    rcpt.flags | RCPT_NOTIFY_DELAY | RCPT_NOTIFY_FAILURE
                },
                orcpt: rcpt.dsn_info,
                retry: Schedule::now(),
                notify: Schedule::now(),
                expires: QueueExpiry::Count(0),
                queue: QueueName::default(),
            });

            let envelope = QueueEnvelope::new(&message, message.recipients.last().unwrap());

            // Set next retry time
            let retry = if self.data.future_release == 0 {
                queue::Schedule::now()
            } else {
                queue::Schedule::later(future_release)
            };

            // Resolve queue
            let queue = self.server.get_queue_or_default(
                &self
                    .server
                    .eval_if::<String, _>(
                        &self.server.core.smtp.queue.queue,
                        &envelope,
                        self.data.session_id,
                    )
                    .await
                    .unwrap_or_else(|| "default".to_string()),
                self.data.session_id,
            );

            // Set expiration and notification times
            let num_intervals = std::cmp::max(queue.notify.len(), 1);
            let next_notify = queue.notify.first().copied().unwrap_or(86400);
            let (notify, expires) = if self.data.delivery_by == 0 {
                (
                    queue::Schedule::later(future_release + next_notify),
                    match queue.expiry {
                        QueueExpiry::Duration(time) => QueueExpiry::Duration(future_release + time),
                        QueueExpiry::Count(count) => QueueExpiry::Count(count),
                    },
                )
            } else if (message.flags & MAIL_BY_RETURN) != 0 {
                (
                    queue::Schedule::later(future_release + next_notify),
                    QueueExpiry::Duration(self.data.delivery_by as u64),
                )
            } else {
                let (notify, expires) = match queue.expiry {
                    QueueExpiry::Duration(expire_secs) => (
                        (if self.data.delivery_by.is_positive() {
                            let notify_at = self.data.delivery_by as u64;
                            if expire_secs > notify_at {
                                notify_at
                            } else {
                                next_notify
                            }
                        } else {
                            let notify_at = -self.data.delivery_by as u64;
                            if expire_secs > notify_at {
                                expire_secs - notify_at
                            } else {
                                next_notify
                            }
                        }),
                        QueueExpiry::Duration(expire_secs),
                    ),
                    QueueExpiry::Count(_) => (
                        next_notify,
                        QueueExpiry::Duration(self.data.delivery_by.unsigned_abs()),
                    ),
                };

                let mut notify = queue::Schedule::later(future_release + notify);
                notify.inner = (num_intervals - 1) as u32; // Disable further notification attempts

                (notify, expires)
            };

            // Update recipient
            let recipient = message.recipients.last_mut().unwrap();
            recipient.retry = retry;
            recipient.notify = notify;
            recipient.expires = expires;
            recipient.queue = queue.virtual_queue;
        }

        MessageWrapper {
            queue_id,
            queue_name: QueueName::default(),
            is_multi_queue: false,
            span_id,
            message,
        }
    }

    pub async fn can_send_data(&mut self) -> Result<bool, ()> {
        if !self.data.rcpt_to.is_empty() {
            if self.data.messages_sent
                < self
                    .server
                    .eval_if(
                        &self.server.core.smtp.session.data.max_messages,
                        self,
                        self.data.session_id,
                    )
                    .await
                    .unwrap_or(10)
            {
                Ok(true)
            } else {
                trc::event!(
                    Smtp(SmtpEvent::TooManyMessages),
                    SpanId = self.data.session_id,
                    Limit = self.data.messages_sent
                );

                self.write(b"452 4.4.5 Maximum number of messages per session exceeded.\r\n")
                    .await?;
                Ok(false)
            }
        } else {
            trc::event!(
                Smtp(SmtpEvent::RcptToMissing),
                SpanId = self.data.session_id,
            );

            self.write(b"503 5.5.1 RCPT is required first.\r\n").await?;
            Ok(false)
        }
    }

    fn write_received(&self, headers: &mut Vec<u8>, id: u64) {
        headers.extend_from_slice(b"Received: from ");
        headers.extend_from_slice(self.data.helo_domain.as_bytes());
        headers.extend_from_slice(b" (");
        headers.extend_from_slice(
            self.data
                .iprev
                .as_ref()
                .and_then(|ir| ir.ptr.as_ref())
                .and_then(|ptr| ptr.first().map(|s| s.strip_suffix('.').unwrap_or(s)))
                .unwrap_or("unknown")
                .as_bytes(),
        );
        headers.extend_from_slice(b" [");
        headers.extend_from_slice(self.data.remote_ip.to_string().as_bytes());
        headers.extend_from_slice(b"]");
        if self.data.asn_geo_data.asn.is_some() || self.data.asn_geo_data.country.is_some() {
            headers.extend_from_slice(b" (");
            if let Some(asn) = &self.data.asn_geo_data.asn {
                headers.extend_from_slice(b"AS");
                headers.extend_from_slice(asn.id.to_string().as_bytes());
                if let Some(name) = &asn.name {
                    headers.extend_from_slice(b" ");
                    headers.extend_from_slice(name.as_bytes());
                }
            }
            if let Some(country) = &self.data.asn_geo_data.country {
                if self.data.asn_geo_data.asn.is_some() {
                    headers.extend_from_slice(b", ");
                }
                headers.extend_from_slice(country.as_bytes());
            }
            headers.extend_from_slice(b")");
        }
        headers.extend_from_slice(b")\r\n\t");
        if self.stream.is_tls() {
            let (version, cipher) = self.stream.tls_version_and_cipher();
            headers.extend_from_slice(b"(using ");
            headers.extend_from_slice(version.as_bytes());
            headers.extend_from_slice(b" with cipher ");
            headers.extend_from_slice(cipher.as_bytes());
            headers.extend_from_slice(b")\r\n\t");
        }
        headers.extend_from_slice(b"by ");
        headers.extend_from_slice(self.hostname.as_bytes());
        headers.extend_from_slice(b" (Stalwart SMTP) with ");
        headers.extend_from_slice(match (self.stream.is_tls(), !self.is_authenticated()) {
            (true, true) => b"ESMTPS",
            (true, false) => b"ESMTPSA",
            (false, true) => b"ESMTP",
            (false, false) => b"ESMTPA",
        });
        headers.extend_from_slice(b" id ");
        headers.extend_from_slice(format!("{id:X}").as_bytes());
        headers.extend_from_slice(b";\r\n\t");
        headers.extend_from_slice(Date::now().to_rfc822().as_bytes());
        headers.extend_from_slice(b"\r\n");
    }
}
