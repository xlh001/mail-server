/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;
use std::iter::Peekable;
use std::vec::IntoIter;

use compact_str::{CompactString, ToCompactString, format_compact};

use crate::{
    Command,
    protocol::fetch::{self, Attribute, Section},
    receiver::{Request, Token, bad},
};

use super::{PushUnique, parse_number, parse_sequence_set};

impl Request<Command> {
    #[allow(clippy::while_let_on_iterator)]
    pub fn parse_fetch(self) -> trc::Result<fetch::Arguments> {
        if self.tokens.len() < 2 {
            return Err(self.into_error("Missing parameters."));
        }

        let mut tokens = self.tokens.into_iter().peekable();
        let mut attributes = Vec::new();
        let sequence_set = parse_sequence_set(
            &tokens
                .next()
                .ok_or_else(|| bad(self.tag.to_compact_string(), "Missing sequence set."))?
                .unwrap_bytes(),
        )
        .map_err(|v| bad(self.tag.to_compact_string(), v))?;

        let mut in_parentheses = false;

        while let Some(token) = tokens.next() {
            match token {
                Token::Argument(value) => {
                    hashify::fnc_map_ignore_case!(value.as_slice(),
                        "ALL" => {
                            attributes = vec![
                                Attribute::Flags,
                                Attribute::InternalDate,
                                Attribute::Rfc822Size,
                                Attribute::Envelope,
                            ];
                            break;
                        },
                        "FULL" => {
                            attributes = vec![
                                Attribute::Flags,
                                Attribute::InternalDate,
                                Attribute::Rfc822Size,
                                Attribute::Envelope,
                                Attribute::Body,
                            ];
                            break;
                        },
                        "FAST" => {
                            attributes = vec![
                                Attribute::Flags,
                                Attribute::InternalDate,
                                Attribute::Rfc822Size,
                            ];
                            break;
                        },
                        "ENVELOPE" => {
                            attributes.push_unique(Attribute::Envelope);
                        },
                        "FLAGS" => {
                            attributes.push_unique(Attribute::Flags);
                        },
                        "INTERNALDATE" => {
                            attributes.push_unique(Attribute::InternalDate);
                        },
                        "BODYSTRUCTURE" => {
                            attributes.push_unique(Attribute::BodyStructure);
                        },
                        "UID" => {
                            attributes.push_unique(Attribute::Uid);
                        },
                        "RFC822" => {
                            attributes.push_unique(
                                if tokens.peek().is_some_and(|token| token.is_dot()) {
                                    tokens.next();
                                    let rfc822 = tokens
                                        .next()
                                        .ok_or_else(|| {
                                            bad(self.tag.to_compact_string(), "Missing RFC822 parameter.")
                                        })?
                                        .unwrap_bytes();
                                    if rfc822.eq_ignore_ascii_case(b"HEADER") {
                                        Attribute::Rfc822Header
                                    } else if rfc822.eq_ignore_ascii_case(b"SIZE") {
                                        Attribute::Rfc822Size
                                    } else if rfc822.eq_ignore_ascii_case(b"TEXT") {
                                        Attribute::Rfc822Text
                                    } else {
                                        return Err(bad(
                                            CompactString::from_string_buffer(self.tag),
                                            format_compact!(
                                                "Invalid RFC822 parameter {:?}.",
                                                String::from_utf8_lossy(&rfc822)
                                            ),
                                        ));
                                    }
                                } else {
                                    Attribute::Rfc822
                                },
                            );
                        },
                        "BODY" => {
                            let is_peek = match tokens.peek() {
                                Some(Token::BracketOpen) => {
                                    tokens.next();
                                    false
                                }
                                Some(Token::Dot) => {
                                    tokens.next();
                                    if tokens
                                        .next()
                                        .is_none_or( |token| !token.eq_ignore_ascii_case(b"PEEK"))
                                    {
                                        return Err(bad(
                                            self.tag.to_compact_string(),
                                            "Expected 'PEEK' after '.'.",
                                        ));
                                    }
                                    if tokens.next().is_none_or( |token| !token.is_bracket_open()) {
                                        return Err(bad(
                                            self.tag.to_compact_string(),
                                            "Expected '[' after 'BODY.PEEK'",
                                        ));
                                    }
                                    true
                                }
                                _ => {
                                    attributes.push_unique(Attribute::Body);

                                    if !in_parentheses {
                                        break;
                                    } else {
                                        continue;
                                    }
                                }
                            };

                            // Parse section-spect
                            let mut sections = Vec::new();
                            while let Some(token) = tokens.next() {
                                match token {
                                    Token::BracketClose => break,
                                    Token::Argument(value) => {
                                        let section = if value.eq_ignore_ascii_case(b"HEADER") {
                                            if let Some(Token::Dot) = tokens.peek() {
                                                tokens.next();
                                                if tokens.next().is_none_or( |token| {
                                                    !token.eq_ignore_ascii_case(b"FIELDS")
                                                }) {
                                                    return Err(bad(
                                                        CompactString::from_string_buffer(self.tag),
                                                        "Expected 'FIELDS' after 'HEADER.'.",
                                                    ));
                                                }
                                                let is_not = if let Some(Token::Dot) = tokens.peek() {
                                                    tokens.next();
                                                    if tokens.next().is_none_or( |token| {
                                                        !token.eq_ignore_ascii_case(b"NOT")
                                                    }) {
                                                        return Err(bad(
                                                            CompactString::from_string_buffer(self.tag),
                                                            "Expected 'NOT' after 'HEADER.FIELDS.'.",
                                                        ));
                                                    }
                                                    true
                                                } else {
                                                    false
                                                };
                                                if tokens
                                                    .next()
                                                    .is_none_or( |token| !token.is_parenthesis_open())
                                                {
                                                    return Err(bad(
                                                        CompactString::from_string_buffer(self.tag),
                                                        "Expected '(' after 'HEADER.FIELDS'.",
                                                    ));
                                                }
                                                let mut fields = Vec::new();
                                                while let Some(token) = tokens.next() {
                                                    match token {
                                                        Token::ParenthesisClose => break,
                                                        Token::Argument(value) => {
                                                            fields.push(String::from_utf8(value).map_err(
                                                            |_| bad(self.tag.to_compact_string(),"Invalid UTF-8 in header field name."),
                                                        )?);
                                                        }
                                                        _ => {
                                                            return Err(bad(
                                                                CompactString::from_string_buffer(self.tag),
                                                                "Expected field name.",
                                                            ))
                                                        }
                                                    }
                                                }
                                                Section::HeaderFields {
                                                    not: is_not,
                                                    fields,
                                                }
                                            } else {
                                                Section::Header
                                            }
                                        } else if value.eq_ignore_ascii_case(b"TEXT") {
                                            Section::Text
                                        } else if value.eq_ignore_ascii_case(b"MIME") {
                                            Section::Mime
                                        } else {
                                            Section::Part {
                                                num: parse_number::<u32>(&value)
                                                    .map_err(|v| bad(self.tag.to_compact_string(), v))?,
                                            }
                                        };
                                        sections.push(section);
                                    }
                                    Token::Dot => (),
                                    _ => {
                                        return Err(bad(
                                            CompactString::from_string_buffer(self.tag),
                                            format_compact!(
                                                "Invalid token {:?} found in section-spect.",
                                                token
                                            ),
                                        ))
                                    }
                                }
                            }

                            attributes.push_unique(Attribute::BodySection {
                                peek: is_peek,
                                sections,
                                partial: parse_partial(&mut tokens)
                                    .map_err(|v| bad(self.tag.to_compact_string(), v))?,
                            });
                        },
                        "BINARY" => {
                            let (is_peek, is_size) = if let Some(Token::Dot) = tokens.peek() {
                                tokens.next();
                                let param = tokens
                                    .next()
                                    .ok_or({
                                        bad(self.tag.to_compact_string(),"Missing parameter after 'BINARY.'.")
                                    })?
                                    .unwrap_bytes();
                                if param.eq_ignore_ascii_case(b"PEEK") {
                                    (true, false)
                                } else if param.eq_ignore_ascii_case(b"SIZE") {
                                    (false, true)
                                } else {
                                    return Err(bad(
                                        CompactString::from_string_buffer(self.tag),
                                        "Expected 'PEEK' or 'SIZE' after 'BINARY.'.",
                                    ));
                                }
                            } else {
                                (false, false)
                            };

                            // Parse section-part
                            if tokens.next().is_none_or( |token| !token.is_bracket_open()) {
                                return Err(bad(self.tag.to_compact_string(), "Expected '[' after 'BINARY'."));
                            }
                            let mut sections = Vec::new();
                            while let Some(token) = tokens.next() {
                                match token {
                                    Token::Argument(value) => {
                                        sections.push(
                                            parse_number::<u32>(&value)
                                                .map_err(|v| bad(self.tag.to_compact_string(), v))?,
                                        );
                                    }
                                    Token::Dot => (),
                                    Token::BracketClose => break,
                                    _ => {
                                        return Err(bad(
                                            CompactString::from_string_buffer(self.tag),
                                            format_compact!(
                                                "Expected part section integer, got {:?}.",
                                                token.to_string()
                                            ),
                                        ))
                                    }
                                }
                            }
                            attributes.push_unique(if !is_size {
                                Attribute::Binary {
                                    peek: is_peek,
                                    sections,
                                    partial: parse_partial(&mut tokens)
                                        .map_err(|v| bad(self.tag.to_compact_string(), v))?,
                                }
                            } else {
                                Attribute::BinarySize { sections }
                            });
                        },
                        "PREVIEW" => {
                            attributes.push_unique(Attribute::Preview {
                                lazy: if let Some(Token::ParenthesisOpen) = tokens.peek() {
                                    tokens.next();
                                    let mut is_lazy = false;
                                    while let Some(token) = tokens.next() {
                                        match token {
                                            Token::ParenthesisClose => break,
                                            Token::Argument(value) => {
                                                if value.eq_ignore_ascii_case(b"LAZY") {
                                                    is_lazy = true;
                                                }
                                            }
                                            _ => (),
                                        }
                                    }
                                    is_lazy
                                } else {
                                    false
                                },
                            });
                        },
                        "MODSEQ" => {
                            attributes.push_unique(Attribute::ModSeq);
                        },
                        "EMAILID" => {
                            attributes.push_unique(Attribute::EmailId);
                        },
                        "THREADID" => {
                            attributes.push_unique(Attribute::ThreadId);
                        },
                        _ => {
                            return Err(bad(
                                CompactString::from_string_buffer(self.tag),
                                format_compact!("Invalid attribute {:?}", String::from_utf8_lossy(&value)),
                            ));
                        }
                    );

                    if !in_parentheses {
                        break;
                    }
                }
                Token::ParenthesisOpen => {
                    if !in_parentheses {
                        in_parentheses = true;
                    } else {
                        return Err(bad(
                            self.tag.to_compact_string(),
                            "Unexpected parenthesis open.",
                        ));
                    }
                }
                Token::ParenthesisClose => {
                    if in_parentheses {
                        break;
                    } else {
                        return Err(bad(
                            self.tag.to_compact_string(),
                            "Unexpected parenthesis close.",
                        ));
                    }
                }
                _ => {
                    return Err(bad(
                        CompactString::from_string_buffer(self.tag),
                        format_compact!("Invalid fetch argument {:?}.", token.to_string()),
                    ));
                }
            }
        }

        // CONDSTORE parameters
        let mut changed_since = None;
        let mut include_vanished = false;
        if let Some(Token::ParenthesisOpen) = tokens.peek() {
            tokens.next();
            while let Some(token) = tokens.next() {
                match token {
                    Token::Argument(param) if param.eq_ignore_ascii_case(b"CHANGEDSINCE") => {
                        changed_since = parse_number::<u64>(
                            &tokens
                                .next()
                                .ok_or_else(|| {
                                    bad(
                                        self.tag.to_compact_string(),
                                        "Missing CHANGEDSINCE parameter.",
                                    )
                                })?
                                .unwrap_bytes(),
                        )
                        .map_err(|v| bad(self.tag.to_compact_string(), v))?
                        .into();
                    }
                    Token::Argument(param) if param.eq_ignore_ascii_case(b"VANISHED") => {
                        include_vanished = true;
                    }
                    Token::ParenthesisClose => {
                        break;
                    }
                    _ => {
                        return Err(bad(
                            self.tag.to_compact_string(),
                            format_compact!("Unsupported parameter '{}'.", token),
                        ));
                    }
                }
            }
        }

        if !attributes.is_empty() {
            Ok(fetch::Arguments {
                tag: self.tag,
                sequence_set,
                attributes,
                changed_since,
                include_vanished,
            })
        } else {
            Err(bad(
                CompactString::from_string_buffer(self.tag),
                "No data items to fetch specified.",
            ))
        }
    }
}

pub fn parse_partial(tokens: &mut Peekable<IntoIter<Token>>) -> super::Result<Option<(u32, u32)>> {
    if tokens.peek().is_none_or(|token| !token.is_lt()) {
        return Ok(None);
    }
    tokens.next();

    let start = parse_number::<u32>(
        &tokens
            .next()
            .ok_or_else(|| Cow::from("Missing partial start."))?
            .unwrap_bytes(),
    )?;

    if tokens.next().is_none_or(|token| !token.is_dot()) {
        return Err("Expected '.' after partial start.".into());
    }

    let end = parse_number::<u32>(
        &tokens
            .next()
            .ok_or_else(|| Cow::from("Missing partial end."))?
            .unwrap_bytes(),
    )?;

    if end == 0 {
        return Err("Invalid partial range.".into());
    }

    if tokens.next().is_none_or(|token| !token.is_gt()) {
        return Err("Expected '>' after range.".into());
    }

    Ok(Some((start, end)))
}

/*

   fetch           = "FETCH" SP sequence-set SP (
                     "ALL" / "FULL" / "FAST" /
                     fetch-att / "(" fetch-att *(SP fetch-att) ")")

   fetch-att       = "ENVELOPE" / "FLAGS" / "INTERNALDATE" /
                     "RFC822" [".HEADER" / ".SIZE" / ".TEXT"] /
                     "BODY" ["STRUCTURE"] / "UID" /
                     "BODY" section [partial] /
                     "BODY.PEEK" section [partial] /
                     "BINARY" [".PEEK"] section-binary [partial] /
                     "BINARY.SIZE" section-binary

   partial         = "<" number64 "." nz-number64 ">"
                       ; Partial FETCH request. 0-based offset of
                       ; the first octet, followed by the number of
                       ; octets in the fragment.

   section         = "[" [section-spec] "]"

   section-binary  = "[" [section-part] "]"

   section-msgtext = "HEADER" /
                     "HEADER.FIELDS" [".NOT"] SP header-list /
                     "TEXT"
                       ; top-level or MESSAGE/RFC822 or
                       ; MESSAGE/GLOBAL part

   section-part    = nz-number *("." nz-number)
                       ; body part reference.
                       ; Allows for accessing nested body parts.

   section-spec    = section-msgtext / (section-part ["." section-text])

   section-text    = section-msgtext / "MIME"
                       ; text other than actual body part (headers,
                       ; etc.)


*/

#[cfg(test)]
mod tests {
    use crate::{
        protocol::{
            Sequence,
            fetch::{self, Attribute, Section},
        },
        receiver::Receiver,
    };

    #[test]
    fn parse_fetch() {
        let mut receiver = Receiver::new();

        for (command, arguments) in [
            (
                "A654 FETCH 2:4 (FLAGS BODY[HEADER.FIELDS (DATE FROM)])\r\n",
                fetch::Arguments {
                    tag: "A654".into(),
                    sequence_set: Sequence::range(2.into(), 4.into()),
                    attributes: vec![
                        Attribute::Flags,
                        Attribute::BodySection {
                            peek: false,
                            sections: vec![Section::HeaderFields {
                                not: false,
                                fields: vec!["DATE".into(), "FROM".into()],
                            }],
                            partial: None,
                        },
                    ],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
            (
                "A001 FETCH 1 BODY[]\r\n",
                fetch::Arguments {
                    tag: "A001".into(),
                    sequence_set: Sequence::number(1),
                    attributes: vec![Attribute::BodySection {
                        peek: false,
                        sections: vec![],
                        partial: None,
                    }],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
            (
                "A001 FETCH 1 (BODY[HEADER])\r\n",
                fetch::Arguments {
                    tag: "A001".into(),
                    sequence_set: Sequence::number(1),
                    attributes: vec![Attribute::BodySection {
                        peek: false,
                        sections: vec![Section::Header],
                        partial: None,
                    }],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
            (
                "A001 FETCH 1 (BODY.PEEK[HEADER.FIELDS (X-MAILER)] PREVIEW(LAZY))\r\n",
                fetch::Arguments {
                    tag: "A001".into(),
                    sequence_set: Sequence::number(1),
                    attributes: vec![
                        Attribute::BodySection {
                            peek: true,
                            sections: vec![Section::HeaderFields {
                                not: false,
                                fields: vec!["X-MAILER".into()],
                            }],
                            partial: None,
                        },
                        Attribute::Preview { lazy: true },
                    ],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
            (
                "A001 FETCH 1 (BODY[HEADER.FIELDS.NOT (FROM TO SUBJECT)])\r\n",
                fetch::Arguments {
                    tag: "A001".into(),
                    sequence_set: Sequence::number(1),
                    attributes: vec![Attribute::BodySection {
                        peek: false,
                        sections: vec![Section::HeaderFields {
                            not: true,
                            fields: vec!["FROM".into(), "TO".into(), "SUBJECT".into()],
                        }],
                        partial: None,
                    }],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
            (
                "A001 FETCH 1 (BODY[MIME] BODY[TEXT] PREVIEW)\r\n",
                fetch::Arguments {
                    tag: "A001".into(),
                    sequence_set: Sequence::number(1),
                    attributes: vec![
                        Attribute::BodySection {
                            peek: false,
                            sections: vec![Section::Mime],
                            partial: None,
                        },
                        Attribute::BodySection {
                            peek: false,
                            sections: vec![Section::Text],
                            partial: None,
                        },
                        Attribute::Preview { lazy: false },
                    ],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
            (
                "A001 FETCH 1 (BODYSTRUCTURE ENVELOPE FLAGS INTERNALDATE UID)\r\n",
                fetch::Arguments {
                    tag: "A001".into(),
                    sequence_set: Sequence::number(1),
                    attributes: vec![
                        Attribute::BodyStructure,
                        Attribute::Envelope,
                        Attribute::Flags,
                        Attribute::InternalDate,
                        Attribute::Uid,
                    ],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
            (
                "A001 FETCH 1 (RFC822 RFC822.HEADER RFC822.SIZE RFC822.TEXT)\r\n",
                fetch::Arguments {
                    tag: "A001".into(),
                    sequence_set: Sequence::number(1),
                    attributes: vec![
                        Attribute::Rfc822,
                        Attribute::Rfc822Header,
                        Attribute::Rfc822Size,
                        Attribute::Rfc822Text,
                    ],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
            (
                concat!(
                    "A001 FETCH 1 (",
                    "BODY[4.2.HEADER]<0.20> ",
                    "BODY.PEEK[3.2.2.2] ",
                    "BODY[4.2.TEXT]<4.100> ",
                    "BINARY[1.2.3] ",
                    "BINARY.PEEK[4] ",
                    "BINARY[6.5.4]<100.200> ",
                    "BINARY.PEEK[7]<9.88> ",
                    "BINARY.SIZE[9.1]",
                    ")\r\n"
                ),
                fetch::Arguments {
                    tag: "A001".into(),
                    sequence_set: Sequence::number(1),
                    attributes: vec![
                        Attribute::BodySection {
                            peek: false,
                            sections: vec![
                                Section::Part { num: 4 },
                                Section::Part { num: 2 },
                                Section::Header,
                            ],
                            partial: Some((0, 20)),
                        },
                        Attribute::BodySection {
                            peek: true,
                            sections: vec![
                                Section::Part { num: 3 },
                                Section::Part { num: 2 },
                                Section::Part { num: 2 },
                                Section::Part { num: 2 },
                            ],
                            partial: None,
                        },
                        Attribute::BodySection {
                            peek: false,
                            sections: vec![
                                Section::Part { num: 4 },
                                Section::Part { num: 2 },
                                Section::Text,
                            ],
                            partial: Some((4, 100)),
                        },
                        Attribute::Binary {
                            peek: false,
                            sections: vec![1, 2, 3],
                            partial: None,
                        },
                        Attribute::Binary {
                            peek: true,
                            sections: vec![4],
                            partial: None,
                        },
                        Attribute::Binary {
                            peek: false,
                            sections: vec![6, 5, 4],
                            partial: Some((100, 200)),
                        },
                        Attribute::Binary {
                            peek: true,
                            sections: vec![7],
                            partial: Some((9, 88)),
                        },
                        Attribute::BinarySize {
                            sections: vec![9, 1],
                        },
                    ],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
            (
                "A001 FETCH 1 ALL\r\n",
                fetch::Arguments {
                    tag: "A001".into(),
                    sequence_set: Sequence::number(1),
                    attributes: vec![
                        Attribute::Flags,
                        Attribute::InternalDate,
                        Attribute::Rfc822Size,
                        Attribute::Envelope,
                    ],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
            (
                "A001 FETCH 1 FULL\r\n",
                fetch::Arguments {
                    tag: "A001".into(),
                    sequence_set: Sequence::number(1),
                    attributes: vec![
                        Attribute::Flags,
                        Attribute::InternalDate,
                        Attribute::Rfc822Size,
                        Attribute::Envelope,
                        Attribute::Body,
                    ],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
            (
                "A001 FETCH 1 FAST\r\n",
                fetch::Arguments {
                    tag: "A001".into(),
                    sequence_set: Sequence::number(1),
                    attributes: vec![
                        Attribute::Flags,
                        Attribute::InternalDate,
                        Attribute::Rfc822Size,
                    ],
                    changed_since: None,
                    include_vanished: false,
                },
            ),
            (
                "s100 UID FETCH 1:* (FLAGS MODSEQ) (CHANGEDSINCE 12345 VANISHED)\r\n",
                fetch::Arguments {
                    tag: "s100".into(),
                    sequence_set: Sequence::range(1.into(), None),
                    attributes: vec![Attribute::Flags, Attribute::ModSeq],
                    changed_since: 12345.into(),
                    include_vanished: true,
                },
            ),
            (
                "9 UID FETCH 1:* UID (VANISHED CHANGEDSINCE 1)\r\n",
                fetch::Arguments {
                    tag: "9".into(),
                    sequence_set: Sequence::range(1.into(), None),
                    attributes: vec![Attribute::Uid],
                    changed_since: 1.into(),
                    include_vanished: true,
                },
            ),
        ] {
            assert_eq!(
                receiver
                    .parse(&mut command.as_bytes().iter())
                    .unwrap()
                    .parse_fetch()
                    .expect(command),
                arguments,
                "{}",
                command
            );
        }
    }
}
