use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub struct Token {
    kind: TokenKind,
    line: usize,
    column: usize,
}

impl Token {
    const EMPTY: Token = Token {
        kind: TokenKind::RulePart { id: String::new() },
        line: 0,
        column: 0,
    };

    #[allow(dead_code)]
    pub(super) fn new(kind: TokenKind, line: usize, column: usize) -> Token {
        Token { kind, line, column }
    }

    pub fn empty() -> Token {
        Token::EMPTY
    }

    pub fn is_empty(token: &Token) -> bool {
        *token == Token::EMPTY
    }

    pub fn get_kind(&self) -> &TokenKind {
        &self.kind
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum TokenKind {
    RulePart { id: String },
    EOL,
    BlockOpen,
    BlockClose,
}

pub fn extract_tokens(src: &str) -> Vec<Token> {
    let mut tokens: Vec<Token> = vec![];

    for (line, line_str) in src.lines().enumerate() {
        let mut current_token_start: Option<usize> = None;

        let chars_count = line_str.chars().collect::<Vec<char>>().len();
        for (column, char) in line_str.chars().enumerate() {
            let last_column = column == chars_count - 1;

            if !char.is_whitespace() {
                if current_token_start == None {
                    current_token_start = Some(column);
                }
            }

            if current_token_start.is_some() && (char.is_whitespace() || last_column) {
                let token_start = current_token_start.unwrap();
                let word = &line_str[token_start..if last_column { column + 1 } else { column }];

                let kind = match word {
                    "[" => TokenKind::BlockOpen,
                    "]" => TokenKind::BlockClose,
                    _ => TokenKind::RulePart { id: word.to_string() },
                };

                tokens.push(Token {
                    kind: kind,
                    line: line + 1,
                    column: token_start + 1,
                });

                current_token_start = None;
            }
        }

        tokens.push(Token {
            kind: TokenKind::EOL,
            line: line + 1,
            column: chars_count + 1,
        });
    }

    let last_token = tokens.last();
    if last_token == None || last_token.unwrap().kind != TokenKind::EOL {
        let (lines, last_line) = src.lines().enumerate().last().unwrap_or((0, ""));

        tokens.push(
            Token {
                kind: TokenKind::EOL,
                line: lines + 1,
                column: last_line.to_string().chars().count() + 1,
            }
        );
    }

    tokens
}

#[cfg(test)]
mod tests;
