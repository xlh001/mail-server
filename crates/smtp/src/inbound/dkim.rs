/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::queue::{MessageWrapper, Metadata, spool::QueueParams};
use common::{
    Server,
    config::smtp::auth::{Dkim1Signer, DkimSigners},
    expr::{functions::ResolveVariable, if_block::IfBlock},
};
use mail_auth::{
    AuthenticatedMessage,
    common::headers::HeaderWriter,
    dkim2::{Hop, MessageInstance},
};
use mail_parser::{Address, parsers::MessageStream};
use std::{collections::HashSet, sync::Arc};
use utils::sanitize_email;

pub(crate) trait DkimSign: Sync + Send {
    fn sign_message(
        &self,
        message: &mut MessageWrapper,
        params: &mut QueueParams<'_, '_>,
    ) -> impl Future<Output = Option<Vec<u8>>> + Send;

    fn eval_signers(
        &self,
        if_block: &IfBlock,
        resolver: &impl ResolveVariable,
        session_id: u64,
    ) -> impl Future<Output = Option<Arc<DkimSigners>>> + Send;
}

impl DkimSign for Server {
    async fn sign_message(
        &self,
        message: &mut MessageWrapper,
        params: &mut QueueParams<'_, '_>,
    ) -> Option<Vec<u8>> {
        let signers = params.dkim_signers.as_ref().unwrap();
        let raw_message = params.raw_message;

        // DKIM1 signing
        let mut headers = Vec::with_capacity(64);
        for signer in &signers.dkim1 {
            let result = match (signer, params.raw_headers) {
                (Dkim1Signer::RsaSha256(signer), None) => signer.sign(raw_message),
                (Dkim1Signer::Ed25519Sha256(signer), None) => signer.sign(raw_message),
                (Dkim1Signer::RsaSha256(signer), Some(headers)) => {
                    signer.sign_chained([headers, raw_message].iter().copied())
                }
                (Dkim1Signer::Ed25519Sha256(signer), Some(headers)) => {
                    signer.sign_chained([headers, raw_message].iter().copied())
                }
            };

            match result {
                Ok(signature) => {
                    signature.write_header(&mut headers);
                }
                Err(err) => {
                    trc::error!(
                        trc::Error::from(err)
                            .span_id(params.session_id)
                            .details("Failed to sign message")
                            .caused_by(trc::location!())
                    );
                }
            }
        }

        // DKIM2 signing
        if let Some(signer) = &signers.dkim2
            && let Some(modified) =
                AuthenticatedMessage::parse_with_opts(raw_message, params.raw_headers, true)
        {
            // Generate message instance
            let original = params.original_authenticated_message.take().or_else(|| {
                params
                    .original_raw_message
                    .and_then(AuthenticatedMessage::parse)
            });
            let instance = MessageInstance::from_message(&modified, original.as_ref());
            if let Some(instance) = &instance {
                instance.write(&mut headers);
            }

            // Obtain disclosed and undisclosed recipients
            let envelopes = message.undisclosed_recipients(&modified);

            // Generate DKIM2 signature for disclosed recipients
            if !envelopes.disclosed_recipients.is_empty() {
                match signer.sign_with_message_instance(
                    &modified,
                    instance.as_ref(),
                    Hop::real(
                        message.message.return_path.as_ref(),
                        envelopes.disclosed_recipients,
                    ),
                ) {
                    Ok(signature) => {
                        if envelopes.undisclosed_recipients.is_empty() {
                            // Happy path: no undisclosed recipients, serialize signature straight to blob
                            signature.write(&mut headers);
                        } else {
                            // Undisclosed recipients present, serialize signature to metadata
                            let mut header = Vec::with_capacity(64);
                            signature.write(&mut header);
                            params.metadata.push(Metadata::Headers {
                                value: header.into_boxed_slice(),
                                id: u64::MAX,
                            });
                        }
                    }
                    Err(err) => {
                        trc::error!(
                            trc::Error::from(err)
                                .span_id(params.session_id)
                                .details("Failed to DKIM2 sign message")
                        );
                    }
                }
            }

            // Generate DKIM2 signature for undisclosed recipients
            for (pos, rcpt) in envelopes.undisclosed_recipients {
                match signer.sign_with_message_instance(
                    &modified,
                    instance.as_ref(),
                    Hop::real(message.message.return_path.as_ref(), [rcpt]),
                ) {
                    Ok(signature) => {
                        // Serialize signature to metadata
                        let mut header = Vec::with_capacity(64);
                        signature.write(&mut header);
                        params.metadata.push(Metadata::Headers {
                            value: header.into_boxed_slice(),
                            id: pos as u64,
                        });
                    }
                    Err(err) => {
                        trc::error!(
                            trc::Error::from(err)
                                .span_id(params.session_id)
                                .details("Failed to DKIM2 sign message")
                        );
                    }
                }
            }
        }

        (!headers.is_empty()).then_some(headers)
    }

    async fn eval_signers(
        &self,
        if_block: &IfBlock,
        resolver: &impl ResolveVariable,
        session_id: u64,
    ) -> Option<Arc<DkimSigners>> {
        let sign_with_domain = self
            .eval_if::<String, _>(if_block, resolver, session_id)
            .await?;
        match self.dkim_signers(&sign_with_domain).await {
            Ok(signers) => signers,
            Err(err) => {
                trc::error!(
                    err.span_id(session_id)
                        .details("Failed to retrieve DKIM signers")
                );
                None
            }
        }
    }
}

struct Dkim2Envelopes<'x> {
    undisclosed_recipients: Vec<(usize, &'x str)>,
    disclosed_recipients: Vec<&'x str>,
}

impl MessageWrapper {
    fn undisclosed_recipients<'x>(
        &'x self,
        message: &AuthenticatedMessage<'_>,
    ) -> Dkim2Envelopes<'x> {
        if self.message.recipients.len() == 1 {
            return Dkim2Envelopes {
                undisclosed_recipients: Vec::new(),
                disclosed_recipients: vec![self.message.recipients[0].address.as_ref()],
            };
        }

        let mut recipients = HashSet::with_capacity(self.message.recipients.len());

        for addr in message.headers.iter().filter_map(|(name, value)| {
            let name = name.trim_ascii();
            if name.len() == 2
                && (name.eq_ignore_ascii_case(b"to") || name.eq_ignore_ascii_case(b"cc"))
            {
                MessageStream::new(value).parse_address().into_address()
            } else {
                None
            }
        }) {
            match addr {
                Address::List(addrs) => {
                    recipients.extend(
                        addrs
                            .iter()
                            .filter_map(|a| a.address())
                            .map(sanitize_or_lower),
                    );
                }
                Address::Group(groups) => {
                    for group in groups {
                        recipients.extend(
                            group
                                .addresses
                                .iter()
                                .filter_map(|a| a.address())
                                .map(sanitize_or_lower),
                        );
                    }
                }
            }
        }

        let mut undisclosed_recipients = Vec::new();
        let mut disclosed_recipients = Vec::new();
        for (i, rcpt) in self.message.recipients.iter().enumerate() {
            if !recipients.contains(rcpt.address.as_ref())
                && !recipients.contains(&sanitize_or_lower(&rcpt.address))
            {
                undisclosed_recipients.push((i, rcpt.address.as_ref()));
            } else {
                disclosed_recipients.push(rcpt.address.as_ref());
            }
        }

        Dkim2Envelopes {
            undisclosed_recipients,
            disclosed_recipients,
        }
    }
}

fn sanitize_or_lower(rcpt: &str) -> String {
    sanitize_email(rcpt).unwrap_or_else(|| rcpt.to_lowercase())
}
