/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::Future;

use common::Server;

use crate::{modules::bayes::bayes_classify, SpamFilterContext};

pub trait SpamFilterAnalyzeBayes: Sync + Send {
    fn spam_filter_analyze_bayes_classify(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;

    fn spam_filter_analyze_spam_trap(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = bool> + Send;
}

impl SpamFilterAnalyzeBayes for Server {
    async fn spam_filter_analyze_bayes_classify(&self, ctx: &mut SpamFilterContext<'_>) {
        if let Some(config) = &self.core.spam.bayes {
            if !ctx.result.has_tag("SPAM_TRAP") && !ctx.result.has_tag("TRUSTED_REPLY") {
                match bayes_classify(self, ctx).await {
                    Ok(Some(score)) => {
                        if score > config.score_spam {
                            ctx.result.add_tag("BAYES_SPAM");
                        } else if score < config.score_ham {
                            ctx.result.add_tag("BAYES_HAM");
                        }
                    }
                    Ok(None) => (),
                    Err(err) => {
                        trc::error!(err.span_id(ctx.input.span_id).caused_by(trc::location!()));
                    }
                }
            }
        }
    }

    async fn spam_filter_analyze_spam_trap(&self, ctx: &mut SpamFilterContext<'_>) -> bool {
        if ctx
            .output
            .env_to_addr
            .iter()
            .any(|addr| self.core.spam.lists.spamtraps.contains(&addr.address))
        {
            ctx.result.add_tag("SPAM_TRAP");
            true
        } else {
            false
        }
    }
}
