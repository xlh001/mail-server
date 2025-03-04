/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::{Engine, engine::general_purpose};
use common::{Server, auth::AccessToken};
use jmap_proto::{
    error::set::SetError,
    method::set::{RequestArguments, SetRequest, SetResponse},
    object::Object,
    response::references::EvalObjectReferences,
    types::{
        collection::Collection,
        date::UTCDate,
        property::Property,
        type_state::DataType,
        value::{MaybePatchValue, Value},
    },
};
use rand::distr::Alphanumeric;
use std::future::Future;
use store::{
    rand::{Rng, rng},
    write::{BatchBuilder, F_CLEAR, F_VALUE, now},
};
use trc::AddContext;

use crate::services::state::StateManager;

const EXPIRES_MAX: i64 = 7 * 24 * 3600; // 7 days
const VERIFICATION_CODE_LEN: usize = 32;

pub trait PushSubscriptionSet: Sync + Send {
    fn push_subscription_set(
        &self,
        request: SetRequest<RequestArguments>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<SetResponse>> + Send;
}

impl PushSubscriptionSet for Server {
    async fn push_subscription_set(
        &self,
        mut request: SetRequest<RequestArguments>,
        access_token: &AccessToken,
    ) -> trc::Result<SetResponse> {
        let account_id = access_token.primary_id();
        let mut push_ids = self
            .get_document_ids(account_id, Collection::PushSubscription)
            .await?
            .unwrap_or_default();
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?;
        let will_destroy = request.unwrap_destroy();

        // Process creates
        'create: for (id, object) in request.unwrap_create() {
            let mut push = Object::with_capacity(object.properties.len());

            if push_ids.len() as usize >= self.core.jmap.push_max_total {
                response.not_created.append(id, SetError::forbidden().with_description(
                    "There are too many subscriptions, please delete some before adding a new one.",
                ));
                continue 'create;
            }

            for (property, value) in object.properties {
                match response
                    .eval_object_references(value)
                    .and_then(|value| validate_push_value(&property, value, None))
                {
                    Ok(Value::Null) => (),
                    Ok(value) => {
                        push.set(property, value);
                    }
                    Err(err) => {
                        response.not_created.append(id, err);
                        continue 'create;
                    }
                }
            }

            if !push.properties.contains_key(&Property::DeviceClientId)
                || !push.properties.contains_key(&Property::Url)
            {
                response.not_created.append(
                    id,
                    SetError::invalid_properties()
                        .with_properties([Property::DeviceClientId, Property::Url])
                        .with_description("Missing required properties"),
                );
                continue 'create;
            }

            // Add expiry time if missing
            let expires = if let Some(expires) = push.properties.get(&Property::Expires) {
                expires.clone()
            } else {
                let expires = Value::Date(UTCDate::from_timestamp(now() as i64 + EXPIRES_MAX));
                push.append(Property::Expires, expires.clone());
                expires
            };

            // Generate random verification code
            push.append(
                Property::Value,
                Value::Text(
                    rng()
                        .sample_iter(Alphanumeric)
                        .take(VERIFICATION_CODE_LEN)
                        .map(char::from)
                        .collect::<String>(),
                ),
            );

            // Insert record
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::PushSubscription)
                .create_document()
                .value(Property::Value, push, F_VALUE);
            let document_id = self
                .store()
                .write_expect_id(batch)
                .await
                .caused_by(trc::location!())?;
            push_ids.insert(document_id);
            response.created.insert(
                id,
                Object::with_capacity(1)
                    .with_property(Property::Id, Value::Id(document_id.into()))
                    .with_property(Property::Keys, Value::Null)
                    .with_property(Property::Expires, expires),
            );
        }

        // Process updates
        'update: for (id, object) in request.unwrap_update() {
            // Make sure id won't be destroyed
            if will_destroy.contains(&id) {
                response.not_updated.append(id, SetError::will_destroy());
                continue 'update;
            }

            // Obtain push subscription
            let document_id = id.document_id();
            let mut push = if let Some(push) = self
                .get_property::<Object<Value>>(
                    account_id,
                    Collection::PushSubscription,
                    document_id,
                    Property::Value,
                )
                .await?
            {
                push
            } else {
                response.not_updated.append(id, SetError::not_found());
                continue 'update;
            };

            for (property, value) in object.properties {
                match response
                    .eval_object_references(value)
                    .and_then(|value| validate_push_value(&property, value, Some(&push)))
                {
                    Ok(Value::Null) => {
                        push.remove(&property);
                    }
                    Ok(value) => {
                        push.set(property, value);
                    }
                    Err(err) => {
                        response.not_updated.append(id, err);
                        continue 'update;
                    }
                };
            }

            // Update record
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::PushSubscription)
                .update_document(document_id)
                .value(Property::Value, push, F_VALUE);
            self.store()
                .write(batch)
                .await
                .caused_by(trc::location!())?;
            response.updated.append(id, None);
        }

        // Process deletions
        for id in will_destroy {
            let document_id = id.document_id();
            if push_ids.contains(document_id) {
                // Update record
                let mut batch = BatchBuilder::new();
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::PushSubscription)
                    .delete_document(document_id)
                    .value(Property::Value, (), F_VALUE | F_CLEAR);
                self.store()
                    .write(batch)
                    .await
                    .caused_by(trc::location!())?;
                response.destroyed.push(id);
            } else {
                response.not_destroyed.append(id, SetError::not_found());
            }
        }

        // Update push subscriptions
        if response.has_changes() {
            self.update_push_subscriptions(account_id).await;
        }

        Ok(response)
    }
}

fn validate_push_value(
    property: &Property,
    value: MaybePatchValue,
    current: Option<&Object<Value>>,
) -> Result<Value, SetError> {
    Ok(match (property, value) {
        (Property::DeviceClientId, MaybePatchValue::Value(Value::Text(value)))
            if current.is_none() && value.len() < 255 =>
        {
            Value::Text(value)
        }
        (Property::Url, MaybePatchValue::Value(Value::Text(value)))
            if current.is_none() && value.len() < 512 && value.starts_with("https://") =>
        {
            Value::Text(value)
        }
        (Property::Keys, MaybePatchValue::Value(Value::Object(value)))
            if current.is_none()
                && value.properties.len() == 2
                && matches!(value.get(&Property::Auth), Value::Text(auth) if auth.len() < 1024 &&
                general_purpose::URL_SAFE.decode(auth).is_ok())
                && matches!(value.get(&Property::P256dh), Value::Text(p256dh) if p256dh.len() < 1024 &&
                general_purpose::URL_SAFE.decode(p256dh).is_ok()) =>
        {
            Value::Object(value)
        }
        (Property::Expires, MaybePatchValue::Value(Value::Date(value))) => {
            let current_time = now() as i64;
            let expires = value.timestamp();
            Value::Date(UTCDate::from_timestamp(
                if expires > current_time && (expires - current_time) > EXPIRES_MAX {
                    current_time + EXPIRES_MAX
                } else {
                    expires
                },
            ))
        }
        (Property::Expires, MaybePatchValue::Value(Value::Null)) => {
            Value::Date(UTCDate::from_timestamp(now() as i64 + EXPIRES_MAX))
        }
        (Property::Types, MaybePatchValue::Value(Value::List(value)))
            if value.iter().all(|value| {
                value
                    .as_string()
                    .and_then(|value| DataType::try_from(value).ok())
                    .is_some()
            }) =>
        {
            Value::List(value)
        }
        (Property::VerificationCode, MaybePatchValue::Value(Value::Text(value)))
            if current.is_some() =>
        {
            if current
                .as_ref()
                .unwrap()
                .properties
                .get(&Property::Value)
                .is_some_and(|v| matches!(v, Value::Text(v) if v == &value))
            {
                Value::Text(value)
            } else {
                return Err(SetError::invalid_properties()
                    .with_property(property.clone())
                    .with_description("Verification code does not match.".to_string()));
            }
        }
        (
            Property::Keys | Property::Types | Property::VerificationCode,
            MaybePatchValue::Value(Value::Null),
        ) => Value::Null,
        (property, _) => {
            return Err(SetError::invalid_properties()
                .with_property(property.clone())
                .with_description("Field could not be set."));
        }
    })
}
