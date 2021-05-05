use super::*;

fn check_src(src: &str, expected: Vec<Token>) {
    let tokens = extract_tokens(src);
    assert_eq!(expected, tokens);
}

#[test]
fn empty() {
    let src = "";
    let expected: Vec<Token> = vec![
        Token {
            kind: TokenKind::EOL,
            line: 1,
            column: 1,
        },
    ];
    check_src(src, expected);
}

#[test]
fn single_line() {
    let src = "first and  second";
    let expected: Vec<Token> = vec![
        Token {
            kind: TokenKind::RulePart { id: "first".to_string() },
            line: 1,
            column: 1,
        },
        Token {
            kind: TokenKind::RulePart { id: "and".to_string() },
            line: 1,
            column: 7,
        },
        Token {
            kind: TokenKind::RulePart { id: "second".to_string() },
            line: 1,
            column: 12,
        },
        Token {
            kind: TokenKind::EOL,
            line: 1,
            column: 18,
        },
    ];
    check_src(src, expected);
}

#[test]
fn multiple_lines() {
    let src = "\
eth0 [
    pass icmp
]";
    let expected: Vec<Token> = vec![
        Token {
            kind: TokenKind::RulePart { id: "eth0".to_string() },
            line: 1,
            column: 1,
        },
        Token {
            kind: TokenKind::BlockOpen,
            line: 1,
            column: 6,
        },
        Token {
            kind: TokenKind::EOL,
            line: 1,
            column: 7,
        },
        Token {
            kind: TokenKind::RulePart { id: "pass".to_string() },
            line: 2,
            column: 5,
        },
        Token {
            kind: TokenKind::RulePart { id: "icmp".to_string() },
            line: 2,
            column: 10,
        },
        Token {
            kind: TokenKind::EOL,
            line: 2,
            column: 14,
        },
        Token {
            kind: TokenKind::BlockClose,
            line: 3,
            column: 1,
        },
        Token {
            kind: TokenKind::EOL,
            line: 3,
            column: 2,
        },
    ];
    check_src(src, expected);
}
