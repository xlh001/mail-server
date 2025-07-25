/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use directory::QueryParams;
use jmap_proto::{
    method::get::{GetRequest, GetResponse, RequestArguments},
    types::{
        collection::Collection,
        property::Property,
        state::State,
        value::{Object, Value},
    },
};
use std::future::Future;

pub trait PrincipalGet: Sync + Send {
    fn principal_get(
        &self,
        request: GetRequest<RequestArguments>,
    ) -> impl Future<Output = trc::Result<GetResponse>> + Send;
}

impl PrincipalGet for Server {
    async fn principal_get(
        &self,
        mut request: GetRequest<RequestArguments>,
    ) -> trc::Result<GetResponse> {
        let ids = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            Property::Id,
            Property::Type,
            Property::Name,
            Property::Description,
            Property::Email,
            //Property::Timezone,
            //Property::Capabilities,
        ]);
        let principal_ids = self
            .get_document_ids(u32::MAX, Collection::Principal)
            .await?
            .unwrap_or_default();
        let ids = if let Some(ids) = ids {
            ids
        } else {
            principal_ids
                .iter()
                .take(self.core.jmap.get_max_objects)
                .map(Into::into)
                .collect::<Vec<_>>()
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: State::Initial.into(),
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };

        for id in ids {
            // Obtain the principal
            let principal = if let Some(principal) = self
                .core
                .storage
                .directory
                .query(QueryParams::id(id.document_id()).with_return_member_of(false))
                .await?
            {
                principal
            } else {
                response.not_found.push(id.into());
                continue;
            };

            let mut result = Object::with_capacity(properties.len());
            for property in &properties {
                let value = match property {
                    Property::Id => Value::Id(id),
                    Property::Type => Value::Text(principal.typ().to_jmap().to_string()),
                    Property::Name => Value::Text(principal.name().to_string()),
                    Property::Description => principal
                        .description()
                        .map(|v| Value::Text(v.to_string()))
                        .unwrap_or(Value::Null),
                    Property::Email => principal
                        .emails
                        .first()
                        .map(|email| Value::Text(email.to_string()))
                        .unwrap_or(Value::Null),
                    _ => Value::Null,
                };

                result.append(property.clone(), value);
            }
            response.list.push(result);
        }

        Ok(response)
    }
}
