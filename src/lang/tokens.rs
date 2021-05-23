use serde::{Deserialize, Serialize};

use std::net::{Ipv4Addr, Ipv6Addr};

pub use Constant as Const;
pub use Keyword as Kw;
pub use StructuralKeyword as SKw;
pub use TokenKind as TKind;

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Token {
    kind: TokenKind,
    line: usize,
    column: usize,
}

impl Token {
    pub(super) fn new(kind: TokenKind, line: usize, column: usize) -> Token {
        Token { kind, line, column }
    }

    pub fn root() -> Token {
        Token {
            kind: TokenKind::Keyword(
                Keyword::Structural(
                    StructuralKeyword::EOL
                )
            ),
            line: 0,
            column: 0,
        }
    }

    pub fn get_kind(&self) -> &TokenKind {
        &self.kind
    }

    pub fn get_pos(&self) -> (usize, usize) {
        (self.line, self.column)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum TokenKind {
    Keyword(Keyword),
    Constant(Constant),
    Identifier(String),
}

impl TokenKind {
    pub fn any_id() -> TokenKind {
        TokenKind::Identifier("".to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum Keyword {
    Structural(StructuralKeyword),
    Type(Type),
    Action(Action),
    CmpOp(CmpOp),
    SizeUnit(SizeUnit),
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum StructuralKeyword {
    Proto,
    Is,
    ProtoBlockOpen,
    ProtoBlockClose,
    Delimiter,
    ProtoField,
    TypeBlockOpen,
    TypeBlockClose,
    Of,
    RuleBlockOpen,
    RuleBlockClose,
    EOL,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum Type {
    Any,
    UInt,
    Addr4,
    Addr6,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum Action {
    Any,
    Pass,
    Drop,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum CmpOp {
    Any,
    Equal,
    NotEqual,
    Greater,
    GreaterOrEqual,
    Lesser,
    LesserOrEqual,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum Constant {
    Any,
    Number(u64),
    Addr4(Ipv4Addr, usize),
    Addr6(Ipv6Addr, usize),
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum SizeUnit {
    Any,
    Bit,
    Byte,
}

impl SizeUnit {
    pub fn to_bits(&self) -> usize {
        match self {
            SizeUnit::Bit => 1,
            SizeUnit::Byte => 8,
            SizeUnit::Any => panic!("SizeUnit::Any can't be used"),
        }
    }
}

pub const EOL: TokenKind = TokenKind::Keyword(
    Keyword::Structural(
        StructuralKeyword::EOL
    )
);
