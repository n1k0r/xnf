use std::collections::VecDeque;
use std::fmt;

use super::lexer::{Token, TokenKind};

#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    token: Token,
    childs: Vec<Node>,
}

impl Node {
    fn new(token: Token) -> Node {
        Node {
            token,
            childs: vec![],
        }
    }

    fn root() -> Node {
        Node::new(Token::empty())
    }

    fn append(&mut self, node: Node) -> &mut Node {
        self.childs.push(node);
        self.childs.last_mut().unwrap()
    }
}

#[derive(Debug, PartialEq)]
pub enum ParseError {
    UnexpectedBlockOpen(Token),
    UnexpectedBlockClose(Token),
    UnexpectedEnd,
}

fn get_right_subchild(root: &mut Node, level: u32) -> Option<&mut Node> {
    match level {
        0 => Some(root),
        _ => match root.childs.last_mut() {
            Some(child ) => get_right_subchild(child, level - 1),
            None => None,
        },
    }
}

pub fn build_tree(tokens: Vec<Token>) -> Result<Node, Vec<ParseError>> {
    let mut root = Node::root();

    let mut hanging = false;
    let mut stack = vec![0 as u32];

    let mut errors: Vec<ParseError> = vec![];

    let mut deq = VecDeque::from(tokens);
    while let Some(token) = deq.pop_front() {
        match token.get_kind() {
            TokenKind::RulePart { id: _ } => {
                let node = Node::new(token);

                let last = *stack.last().unwrap();
                let parent = get_right_subchild(&mut root, last).unwrap();
                parent.append(node);

                if hanging {
                    stack.pop();
                }
                stack.push(last + 1);

                hanging = true;
            },

            TokenKind::BlockOpen => {
               match hanging {
                   true => hanging = false,
                   false => errors.push(
                        ParseError::UnexpectedBlockOpen(token.clone()),
                   ),
               }
            },

            TokenKind::BlockClose => {
                let mut add_error = || errors.push(
                    ParseError::UnexpectedBlockClose(token.clone()),
                );

                match hanging {
                    false => if let Some(0) = stack.pop() { add_error() },
                    true => add_error(),
                }
            },

            TokenKind::EOL if hanging => {
                hanging = false;
                stack.pop();
            },

            _ => (),
        }
    }

    if hanging {
        stack.pop();
    }

    if stack.len() != 1 {
        errors.push(ParseError::UnexpectedEnd);
    }

    if errors.len() > 0 {
        return Err(errors);
    }

    Ok(root)
}
