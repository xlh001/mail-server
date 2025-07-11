/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use common::{
    Server,
    ipc::{DmarcEvent, QueueEvent, QueueEventStatus, ReportingEvent, TlsEvent},
};
use store::{
    Deserialize, IterateParams, U64_LEN, ValueKey,
    write::{
        AlignedBytes, Archive, QueueClass, ReportEvent, ValueClass, key::DeserializeBigEndian,
    },
};
use tokio::sync::mpsc::error::TryRecvError;

use smtp::queue::{Message, MessageWrapper, QueueId, QueuedMessage};

use super::{QueueReceiver, ReportReceiver};

pub mod antispam;
pub mod asn;
pub mod auth;
pub mod basic;
pub mod data;
pub mod dmarc;
pub mod ehlo;
pub mod limits;
pub mod mail;
pub mod milter;
pub mod rcpt;
pub mod rewrite;
pub mod scripts;
pub mod sign;
pub mod throttle;
pub mod vrfy;

impl QueueReceiver {
    pub async fn read_event(&mut self) -> QueueEvent {
        match tokio::time::timeout(Duration::from_millis(100), self.queue_rx.recv()).await {
            Ok(Some(event)) => event,
            Ok(None) => panic!("Channel closed."),
            Err(_) => panic!("No queue event received."),
        }
    }

    pub async fn try_read_event(&mut self) -> Option<QueueEvent> {
        match tokio::time::timeout(Duration::from_millis(100), self.queue_rx.recv()).await {
            Ok(Some(event)) => Some(event),
            Ok(None) => panic!("Channel closed."),
            Err(_) => None,
        }
    }

    pub fn assert_no_events(&mut self) {
        match self.queue_rx.try_recv() {
            Err(TryRecvError::Empty) => (),
            Ok(event) => panic!("Expected empty queue but got {event:?}"),
            Err(err) => panic!("Queue error: {err:?}"),
        }
    }

    pub async fn assert_queue_is_empty(&self) {
        assert_eq!(self.read_queued_messages().await, vec![]);
        assert_eq!(self.read_queued_events().await, vec![]);
    }

    pub async fn assert_report_is_empty(&self) {
        assert_eq!(self.read_report_events().await, vec![]);

        for (from_key, to_key) in [
            (
                ValueKey::from(ValueClass::Queue(QueueClass::TlsReportEvent(ReportEvent {
                    due: 0,
                    policy_hash: 0,
                    seq_id: 0,
                    domain: String::new(),
                }))),
                ValueKey::from(ValueClass::Queue(QueueClass::TlsReportEvent(ReportEvent {
                    due: u64::MAX,
                    policy_hash: 0,
                    seq_id: 0,
                    domain: String::new(),
                }))),
            ),
            (
                ValueKey::from(ValueClass::Queue(QueueClass::DmarcReportEvent(
                    ReportEvent {
                        due: 0,
                        policy_hash: 0,
                        seq_id: 0,
                        domain: String::new(),
                    },
                ))),
                ValueKey::from(ValueClass::Queue(QueueClass::DmarcReportEvent(
                    ReportEvent {
                        due: u64::MAX,
                        policy_hash: 0,
                        seq_id: 0,
                        domain: String::new(),
                    },
                ))),
            ),
        ] {
            self.store
                .iterate(
                    IterateParams::new(from_key, to_key).ascending().no_values(),
                    |key, _| {
                        panic!("Unexpected report event: {key:?}");
                    },
                )
                .await
                .unwrap();
        }
    }

    pub async fn expect_message(&mut self) -> MessageWrapper {
        self.read_event().await.assert_refresh();
        self.last_queued_message().await
    }

    pub async fn consume_message(&mut self, server: &Server) -> MessageWrapper {
        self.read_event().await.assert_refresh();
        let message = self.last_queued_message().await;
        message
            .clone()
            .remove(server, self.last_queued_due().await.into())
            .await;
        message
    }

    pub async fn expect_message_then_deliver(&mut self) -> QueuedMessage {
        let message = self.expect_message().await;

        self.delivery_attempt(message.queue_id).await
    }

    pub async fn delivery_attempt(&mut self, queue_id: u64) -> QueuedMessage {
        QueuedMessage {
            due: self.message_due(queue_id).await,
            queue_id,
            queue_name: Default::default(),
        }
    }

    pub async fn read_queued_events(&self) -> Vec<store::write::QueueEvent> {
        let mut events = Vec::new();

        let from_key = ValueKey::from(ValueClass::Queue(QueueClass::MessageEvent(
            store::write::QueueEvent {
                due: 0,
                queue_id: 0,
                queue_name: [0; 8],
            },
        )));
        let to_key = ValueKey::from(ValueClass::Queue(QueueClass::MessageEvent(
            store::write::QueueEvent {
                due: u64::MAX,
                queue_id: u64::MAX,
                queue_name: [u8::MAX; 8],
            },
        )));

        self.store
            .iterate(
                IterateParams::new(from_key, to_key).ascending().no_values(),
                |key, _| {
                    events.push(store::write::QueueEvent {
                        due: key.deserialize_be_u64(0)?,
                        queue_id: key.deserialize_be_u64(U64_LEN)?,
                        queue_name: key[U64_LEN + 1..U64_LEN + 9]
                            .try_into()
                            .expect("Queue name must be 8 bytes"),
                    });
                    Ok(true)
                },
            )
            .await
            .unwrap();

        events
    }

    pub async fn read_queued_messages(&self) -> Vec<MessageWrapper> {
        let from_key = ValueKey::from(ValueClass::Queue(QueueClass::Message(0)));
        let to_key = ValueKey::from(ValueClass::Queue(QueueClass::Message(u64::MAX)));
        let mut messages = Vec::new();

        self.store
            .iterate(
                IterateParams::new(from_key, to_key).descending(),
                |key, value| {
                    messages.push(MessageWrapper {
                        queue_id: key.deserialize_be_u64(0)?,
                        queue_name: Default::default(),
                        is_multi_queue: false,
                        span_id: 0,
                        message: <Archive<AlignedBytes> as Deserialize>::deserialize(value)?
                            .deserialize::<Message>()?,
                    });
                    Ok(true)
                },
            )
            .await
            .unwrap();

        messages
    }

    pub async fn read_report_events(&self) -> Vec<QueueClass> {
        let from_key = ValueKey::from(ValueClass::Queue(QueueClass::DmarcReportHeader(
            ReportEvent {
                due: 0,
                policy_hash: 0,
                seq_id: 0,
                domain: String::new(),
            },
        )));
        let to_key = ValueKey::from(ValueClass::Queue(QueueClass::TlsReportHeader(
            ReportEvent {
                due: u64::MAX,
                policy_hash: 0,
                seq_id: 0,
                domain: String::new(),
            },
        )));

        let mut events = Vec::new();
        self.store
            .iterate(
                IterateParams::new(from_key, to_key).ascending().no_values(),
                |key, _| {
                    let event = ReportEvent::deserialize(key)?;
                    // Skip lock
                    if event.seq_id != 0 {
                        events.push(if *key.last().unwrap() == 0 {
                            QueueClass::DmarcReportHeader(event)
                        } else {
                            QueueClass::TlsReportHeader(event)
                        });
                    }
                    Ok(true)
                },
            )
            .await
            .unwrap();
        events
    }

    pub async fn last_queued_message(&self) -> MessageWrapper {
        self.read_queued_messages()
            .await
            .into_iter()
            .next()
            .expect("No messages found in queue")
    }

    pub async fn last_queued_due(&self) -> u64 {
        self.message_due(self.last_queued_message().await.queue_id)
            .await
    }

    pub async fn message_due(&self, queue_id: QueueId) -> u64 {
        self.read_queued_events()
            .await
            .iter()
            .find_map(|event| {
                if event.queue_id == queue_id {
                    Some(event.due)
                } else {
                    None
                }
            })
            .expect("No event found in queue for message")
    }

    pub async fn clear_queue(&self, server: &Server) {
        for message in self.read_queued_messages().await {
            let due = self.message_due(message.queue_id).await;
            message.remove(server, due.into()).await;
        }
    }
}

impl ReportReceiver {
    pub async fn read_report(&mut self) -> ReportingEvent {
        match tokio::time::timeout(Duration::from_millis(100), self.report_rx.recv()).await {
            Ok(Some(event)) => event,
            Ok(None) => panic!("Channel closed."),
            Err(_) => panic!("No report event received."),
        }
    }

    pub async fn try_read_report(&mut self) -> Option<ReportingEvent> {
        match tokio::time::timeout(Duration::from_millis(100), self.report_rx.recv()).await {
            Ok(Some(event)) => Some(event),
            Ok(None) => panic!("Channel closed."),
            Err(_) => None,
        }
    }
    pub fn assert_no_reports(&mut self) {
        match self.report_rx.try_recv() {
            Err(TryRecvError::Empty) => (),
            Ok(event) => panic!("Expected no reports but got {event:?}"),
            Err(err) => panic!("Report error: {err:?}"),
        }
    }
}

pub trait TestQueueEvent {
    fn assert_refresh(self);
    fn assert_done(self);
    fn assert_refresh_or_done(self);
}

impl TestQueueEvent for QueueEvent {
    fn assert_refresh(self) {
        match self {
            QueueEvent::Refresh
            | QueueEvent::WorkerDone {
                status: QueueEventStatus::Deferred,
                ..
            } => (),
            e => panic!("Unexpected event: {e:?}"),
        }
    }

    fn assert_done(self) {
        match self {
            QueueEvent::WorkerDone {
                status: QueueEventStatus::Completed,
                ..
            } => (),
            e => panic!("Unexpected event: {e:?}"),
        }
    }

    fn assert_refresh_or_done(self) {
        match self {
            QueueEvent::WorkerDone {
                status: QueueEventStatus::Completed | QueueEventStatus::Deferred,
                ..
            } => (),
            e => panic!("Unexpected event: {e:?}"),
        }
    }
}

pub trait TestReportingEvent {
    fn unwrap_dmarc(self) -> Box<DmarcEvent>;
    fn unwrap_tls(self) -> Box<TlsEvent>;
}

impl TestReportingEvent for ReportingEvent {
    fn unwrap_dmarc(self) -> Box<DmarcEvent> {
        match self {
            ReportingEvent::Dmarc(event) => event,
            e => panic!("Unexpected event: {e:?}"),
        }
    }

    fn unwrap_tls(self) -> Box<TlsEvent> {
        match self {
            ReportingEvent::Tls(event) => event,
            e => panic!("Unexpected event: {e:?}"),
        }
    }
}

#[allow(async_fn_in_trait)]
pub trait TestMessage {
    async fn read_message(&self, core: &QueueReceiver) -> String;
    async fn read_lines(&self, core: &QueueReceiver) -> Vec<String>;
}

impl TestMessage for MessageWrapper {
    async fn read_message(&self, core: &QueueReceiver) -> String {
        String::from_utf8(
            core.blob_store
                .get_blob(self.message.blob_hash.as_slice(), 0..usize::MAX)
                .await
                .unwrap()
                .expect("Message blob not found"),
        )
        .unwrap()
    }

    async fn read_lines(&self, core: &QueueReceiver) -> Vec<String> {
        self.read_message(core)
            .await
            .split('\n')
            .map(|l| l.to_string())
            .collect()
    }
}
