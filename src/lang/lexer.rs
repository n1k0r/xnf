use super::tokens::*;

use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
pub struct LexicalError {
    pub token: String,
    pub line: usize,
    pub column: usize,
}

pub fn extract_tokens(src: &str) -> (Vec<Token>, Vec<LexicalError>) {
    let mut tokens: Vec<Token> = vec![];
    let mut errors = vec![];

    for (line, line_str) in src.lines().enumerate() {
        let mut current_token_start: Option<usize> = None;

        let chars_count = line_str.chars().collect::<Vec<char>>().len();
        for (column, char) in line_str.chars().enumerate() {
            let last_column = column == chars_count - 1;

            let mut finish_token = |from, to| {
                let token = &line_str[from..to];
                let kind = guess_token(token, true);
                if kind.is_none() {
                    errors.push(LexicalError {
                        token: token.to_string(),
                        line: line + 1,
                        column: from + 1,
                    });

                    return;
                }

                let kind = kind.unwrap();
                tokens.push(
                    Token::new(kind, line + 1, from + 1),
                );
            };

            if char.is_whitespace() || char == '#' {
                if let Some(start) = current_token_start {
                    finish_token(start, column);
                    current_token_start = None;
                }

                if char == '#' {
                    break;
                }
            } else {
                if current_token_start == None {
                    current_token_start = Some(column);
                } else {
                    let tried_token = line_str[current_token_start.unwrap()..column + 1].to_string();
                    let kind = guess_token(&tried_token, false);

                    if kind == None {
                        finish_token(current_token_start.unwrap(), column);
                        current_token_start = Some(column);
                    }
                }
            }

            if last_column && current_token_start.is_some() {
                finish_token(current_token_start.unwrap(), column + 1);
                current_token_start = None;
            }
        }

        tokens.push(Token::new(
            EOL,
            line + 1,
            chars_count + 1,
        ));
    }

    let last_token = tokens.last();
    if last_token == None || *last_token.unwrap().get_kind() != EOL {
        let (lines, last_line) = src.lines().enumerate().last().unwrap_or((0, ""));

        tokens.push(Token::new(
            EOL,
            lines + 1,
            last_line.to_string().chars().count() + 1,
        ));
    }

    (tokens, errors)
}

fn guess_token(token: &str, last: bool) -> Option<TokenKind> {
    use StructuralKeyword as SK;
    let struct_kw = |kw| Some(TokenKind::Keyword(Keyword::Structural(kw)));
    let action_kw = |action| Some(TokenKind::Keyword(Keyword::Action(action)));
    let type_kw = |kwtype| Some(TokenKind::Keyword(Keyword::Type(kwtype)));
    let cmp_op = |op| Some(TokenKind::Keyword(Keyword::CmpOp(op)));

    let is_id = |s: &str|
        s.len() > 0 &&
        s.chars().nth(0).unwrap().is_alphabetic() &&
        s.chars().all(|c| c.is_ascii_alphanumeric());

    match token {
        "proto" => struct_kw(SK::Proto),
        "->" => struct_kw(SK::Is),
        "{" => struct_kw(SK::ProtoBlockOpen),
        "}" => struct_kw(SK::ProtoBlockClose),
        ":" => struct_kw(SK::Delimiter),
        "!" => struct_kw(SK::ProtoField),
        "(" => struct_kw(SK::TypeBlockOpen),
        ")" => struct_kw(SK::TypeBlockClose),
        "*" => struct_kw(SK::Of),
        "[" => struct_kw(SK::RuleBlockOpen),
        "]" => struct_kw(SK::RuleBlockClose),

        "=" => cmp_op(CmpOp::Equal),
        "!=" => cmp_op(CmpOp::NotEqual),
        ">" => cmp_op(CmpOp::Greater),
        ">=" => cmp_op(CmpOp::GreaterOrEqual),
        "<" => cmp_op(CmpOp::Lesser),
        "<=" => cmp_op(CmpOp::LesserOrEqual),

        "pass" => action_kw(Action::Pass),
        "drop" => action_kw(Action::Drop),

        "uint" => type_kw(Type::UInt),
        "addr4" => type_kw(Type::Addr4),
        "addr6" => type_kw(Type::Addr6),

        "b" => Some(
            TKind::Keyword(
                Kw::SizeUnit(SizeUnit::Bit)
            )
        ),
        "B" => Some(
            TKind::Keyword(
                Kw::SizeUnit(SizeUnit::Byte)
            )
        ),

        s if Const::parse_number(s).is_some() => Some(
            TKind::Constant(Const::parse_number(s).unwrap())
        ),
        s if Const::parse_ip4(s).is_some() => Some(
            TKind::Constant(Const::parse_ip4(s).unwrap())
        ),
        s if Const::parse_ip6(s).0.is_some() && (
            !last || Const::parse_ip6(s).1
        ) => Some(
            TKind::Constant(Const::parse_ip6(s).0.unwrap())
        ),

        s if is_id(s) => Some(
            TokenKind::Identifier(
                s.to_string().to_lowercase()
            )
        ),

        _ => None,
    }
}

impl Constant {
    fn parse_number(mut s: &str) -> Option<Constant> {
        let hex = s.starts_with("0x");
        let num = if hex {
            s = &s[2..];

            if s.len() == 0 {
                0
            } else {
                match u64::from_str_radix(s, 16) {
                    Ok(num) => num,
                    Err(_) => return None,
                }
            }
        } else {
            match u64::from_str_radix(s, 10) {
                Ok(num) => num,
                Err(_) => return None,
            }
        };

        Some(Constant::Number(num))
    }

    fn parse_ip4(s: &str) -> Option<Constant> {
        let mut octets: Vec<String> = vec![];
        let mut current_octet = String::new();
        let mut addr_done = false;
        let mut subnet = String::new();

        for c in s.chars() {
            match c {
                '.' if !addr_done && octets.len() < 3 && !current_octet.is_empty() => {
                    octets.push(current_octet);
                    current_octet = String::new();
                },
                '/' if !addr_done && octets.len() == 3 && !current_octet.is_empty() => {
                    octets.push(current_octet);
                    current_octet = String::new();

                    addr_done = true;
                },
                c if c.is_ascii_digit() && !addr_done && octets.len() < 4 => {
                    current_octet.push(c);

                    if let Err(_) = current_octet.parse::<u8>() {
                        return None;
                    }
                },
                c if c.is_ascii_digit() && addr_done => {
                    subnet.push(c);

                    match subnet.parse::<u8>() {
                        Ok(num) if num <= 32 => (),
                        _ => return None,
                    }
                },
                _ => return None,
            }
        }

        if !current_octet.is_empty() {
            octets.push(current_octet);
        }

        let mut num_octets = [0 as u8; 4];
        for i in 0..num_octets.len() {
            num_octets[i] = match octets.get(i) {
                Some(octet) => match octet.parse() {
                    Ok(num) => num,
                    Err(_) => return None,
                },
                None => 0,
            }
        }

        let num_subnet = match subnet.parse() {
            Ok(num) => num,
            _ if subnet.is_empty() => 32,
            _ => return None,
        };

        Some(Const::Addr4(Ipv4Addr::from(num_octets), num_subnet))
    }

    fn parse_ip6(mut s: &str) -> (Option<Constant>, bool) {
        if s.starts_with("[") {
            s = &s[1..];
        } else {
            return (None, false);
        }

        if s.starts_with("::") {
            s = &s[1..];
        }

        const WILDCARD: &str = "::";
        let mut wildcard_used = false;

        let mut octets: Vec<String> = vec![];
        let mut current_octet = String::new();
        let mut terminated = false;
        let mut addr_done = false;
        let mut subnet = String::new();

        for c in s.chars() {
            match c {
                ':' if !terminated && !addr_done && octets.len() < 7 && !current_octet.is_empty() => {
                    octets.push(current_octet);
                    current_octet = String::new();
                },
                ':' if !terminated && !addr_done && octets.len() < 7 && current_octet.is_empty() && !wildcard_used => {
                    octets.push(WILDCARD.to_string());
                    wildcard_used = true;
                },
                ']' if !terminated && !addr_done && (octets.len() == 7 || wildcard_used) && (!current_octet.is_empty() || octets.last() == Some(&WILDCARD.to_string())) => {
                    if !current_octet.is_empty() {
                        octets.push(current_octet);
                        current_octet = String::new();
                    }

                    terminated = true;
                },
                '/' if terminated && !addr_done => {
                    addr_done = true;
                },
                c if c.is_ascii_hexdigit() && !terminated && !addr_done && octets.len() < 8 => {
                    current_octet.push(c);

                    if let Err(_) = u16::from_str_radix(&current_octet, 16) {
                        return (None, false);
                    }
                },
                c if c.is_ascii_digit() && addr_done => {
                    subnet.push(c);

                    match subnet.parse::<u8>() {
                        Ok(num) if num <= 128 => (),
                        _ => return (None, false),
                    }
                },
                _ => return (None, false),
            }
        }

        if !current_octet.is_empty() {
            octets.push(current_octet);
        }

        if wildcard_used {
            let pos = octets.iter().position(
                |octet| *octet == WILDCARD
            ).unwrap();

            octets.remove(pos);

            while octets.len() < 8 {
                octets.insert(pos, "0".to_string());
            }
        }

        let mut num_octets = [0 as u16; 8];
        for i in 0..num_octets.len() {
            num_octets[i] = match octets.get(i) {
                Some(octet) => match u16::from_str_radix(&octet, 16) {
                    Ok(num) => num,
                    Err(_) => return (None, false),
                },
                None => 0,
            }
        }

        let num_subnet = match subnet.parse() {
            Ok(num) => num,
            _ if subnet.is_empty() => 128,
            _ => return (None, false),
        };

        let valid = terminated && (!addr_done || !subnet.is_empty());

        (Some(
            Const::Addr6(
                Ipv6Addr::from(num_octets),
                num_subnet
            )
        ), valid)
    }
}
