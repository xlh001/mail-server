/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::cmp::Ordering;

use crate::scripts::{into_sieve_value, to_store_value};
use sieve::{FunctionMap, runtime::Variable};
use store::{Rows, Value};

use super::PluginContext;

pub fn register(plugin_id: u32, fnc_map: &mut FunctionMap) {
    fnc_map.set_external_function("query", plugin_id, 3);
}

pub async fn exec(ctx: PluginContext<'_>) -> trc::Result<Variable> {
    // Obtain store name
    let store = match &ctx.arguments[0] {
        Variable::String(v) if !v.is_empty() => ctx.server.core.storage.stores.get(v.as_ref()),
        _ => Some(&ctx.server.core.storage.data),
    }
    .ok_or_else(|| {
        trc::SieveEvent::RuntimeError
            .ctx(trc::Key::Id, ctx.arguments[0].to_string().into_owned())
            .details("Unknown store")
    })?;

    // Obtain query string
    let query = ctx.arguments[1].to_string();
    if query.is_empty() {
        trc::bail!(
            trc::SieveEvent::RuntimeError
                .ctx(trc::Key::Id, ctx.arguments[0].to_string().into_owned())
                .details("Empty query string")
        );
    }

    // Obtain arguments
    let arguments = match &ctx.arguments[2] {
        Variable::Array(l) => l.iter().map(to_store_value).collect(),
        v => vec![to_store_value(v)],
    };

    // Run query
    if query
        .as_bytes()
        .get(..6)
        .is_some_and(|q| q.eq_ignore_ascii_case(b"SELECT"))
    {
        let mut rows = store.sql_query::<Rows>(&query, arguments).await?;
        Ok(match rows.rows.len().cmp(&1) {
            Ordering::Equal => {
                let mut row = rows.rows.pop().unwrap().values;
                match row.len().cmp(&1) {
                    Ordering::Equal if !matches!(row.first(), Some(Value::Null)) => {
                        row.pop().map(into_sieve_value).unwrap()
                    }
                    Ordering::Less => Variable::default(),
                    _ => Variable::Array(
                        row.into_iter()
                            .map(into_sieve_value)
                            .collect::<Vec<_>>()
                            .into(),
                    ),
                }
            }
            Ordering::Less => Variable::default(),
            Ordering::Greater => rows
                .rows
                .into_iter()
                .map(|r| {
                    Variable::Array(
                        r.values
                            .into_iter()
                            .map(into_sieve_value)
                            .collect::<Vec<_>>()
                            .into(),
                    )
                })
                .collect::<Vec<_>>()
                .into(),
        })
    } else {
        Ok(store
            .sql_query::<usize>(&query, arguments)
            .await
            .is_ok()
            .into())
    }
}
