/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

include!(concat!(env!("OUT_DIR"), "/locales.rs"));

pub fn locale_or_default(name: &str) -> &'static Locale {
    if let Some(locale) = locale(name) {
        return locale;
    }

    locale_by_language(name.split(['_', '-']).next().unwrap_or(name)).unwrap_or(&EN_US_LOCALES)
}

#[cfg(test)]
mod tests {
    use super::{locale, locale_or_default};

    const LOCALES: [&str; 12] = [
        "en-US", "es-ES", "fr-FR", "de-DE", "it-IT", "pt-PT", "nl-NL", "da-DK", "ca-ES", "el-GR",
        "sv-SE", "pl-PL",
    ];

    #[test]
    fn locales_are_named_after_themselves() {
        for lang in LOCALES {
            assert_eq!(locale(lang).expect("locale must exist").name, lang);
        }
    }

    #[test]
    fn bare_and_hyphenated_language_tags_resolve() {
        for (input, expected) in [
            ("es-ES", "es-ES"),
            ("es", "es-ES"),
            ("es-MX", "es-ES"),
            ("pt-BR", "pt-PT"),
            ("zh-Hans", "en-US"),
            ("zz", "en-US"),
            ("", "en-US"),
            // BCP 47 tags are case-insensitive
            ("ES", "es-ES"),
            ("es-es", "es-ES"),
            ("PT-br", "pt-PT"),
            ("EL-GR", "el-GR"),
        ] {
            assert_eq!(
                locale_or_default(input).name,
                expected,
                "failed for {input}"
            );
        }
    }
}
