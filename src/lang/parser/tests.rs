use super::*;

fn simple_tree<'a>() -> (Vec<Token>, Node) {
    /*
    drop

    lo [
        tcp
        10.0.0.0/8
    ]
    */

    let mut root = Node::root();

    let tokens = vec![
        Token::new(
            TokenKind::RulePart {
                id: "drop".to_string(),
            },
            1, 1,
        ),
        Token::new(
            TokenKind::EOL,
            1, 5,
        ),
        Token::new(
            TokenKind::EOL,
            2, 1,
        ),
        Token::new(
            TokenKind::RulePart {
                id: "lo".to_string(),
            },
            3, 1,
        ),
        Token::new(
            TokenKind::BlockOpen,
            3, 4,
        ),
        Token::new(
            TokenKind::EOL,
            3, 5,
        ),
        Token::new(
            TokenKind::RulePart {
                id: "tcp".to_string(),
            },
            4, 5,
        ),
        Token::new(
            TokenKind::EOL,
            4, 8,
        ),
        Token::new(
            TokenKind::RulePart {
                id: "10.0.0.0/8".to_string(),
            },
            5, 5,
        ),
        Token::new(
            TokenKind::EOL,
            5, 15,
        ),
        Token::new(
            TokenKind::BlockClose,
            6, 1,
        ),
        Token::new(
            TokenKind::EOL,
            6, 2,
        ),
    ];

    let rule_tokens: Vec<_> = tokens
        .iter()
        .filter(
            |token| matches!(token.get_kind(), TokenKind::RulePart { id: _ })
        )
        .collect();

    let child1 = Node::new(rule_tokens[0].clone());
    let mut child2 = Node::new(rule_tokens[1].clone());
    let subchild1 = Node::new(rule_tokens[2].clone());
    let subchild2 = Node::new(rule_tokens[3].clone());

    child2.append(subchild1);
    child2.append(subchild2);
    root.append(child1);
    root.append(child2);

    (tokens, root)
}

mod subchild_search_tests {
    use super::*;

    #[test]
    fn only_root() {
        let mut root = Node::root();

        let subchild = get_right_subchild(&mut root, 0).unwrap().clone();
        assert_eq!(subchild, root);
    }

    #[test]
    fn get_root() {
        let (_, mut root) = simple_tree();

        let subchild = get_right_subchild(&mut root, 0).unwrap().clone();
        assert_eq!(subchild, root);
    }

    #[test]
    fn get_child() {
        let (_, mut root) = simple_tree();
        let leaf = root.childs.last().unwrap().clone();

        let subchild = get_right_subchild(&mut root, 1).unwrap().clone();
        assert_eq!(subchild, leaf);
    }

    #[test]
    fn get_leaf() {
        let (_, mut root) = simple_tree();
        let leaf = root.childs.last().unwrap().childs.last().unwrap().clone();

        let subchild = get_right_subchild(&mut root, 2).unwrap().clone();
        assert_eq!(subchild, leaf);
    }

    #[test]
    fn get_wrong() {
        let (_, mut root) = simple_tree();

        let result = get_right_subchild(&mut root, 3);
        assert_eq!(result, None);
    }
}

mod build_tree_tests {
    use super::*;

    fn tokens_to_branch(tokens: Vec<Token>) -> Option<Node> {
        let mut top = None;

        let mut expected_nodes: Vec<_> = tokens.iter().map(|token| Node::new(token.clone())).collect();
        while let Some(node) = expected_nodes.pop() {
            match expected_nodes.len() {
                0 => top = Some(node),
                _ => { expected_nodes.last_mut().unwrap().append(node); },
            }
        }

        top
    }

    #[test]
    fn empty() {
        let tokens = vec![];
        let root = build_tree(tokens).unwrap();
        assert_eq!(root, Node::root());
    }

    #[test]
    fn single_token() {
        let token = Token::new(
            TokenKind::RulePart {
                id: "drop".to_string(),
            },
            1, 1,
        );

        let tokens = vec![token.clone()];

        let mut expected = Node::root();
        expected.append(
            Node::new(token.clone())
        );

        let root = build_tree(tokens).unwrap();
        assert_eq!(root, expected);
        }

    #[test]
    fn single_rule() {
        let tokens = vec![
            Token::new(
                TokenKind::RulePart {
                    id: "pass".to_string(),
                },
                1, 1,
            ),
            Token::new(
                TokenKind::RulePart {
                    id: "tcp".to_string(),
                },
                1, 6,
            ),
            Token::new(
                TokenKind::RulePart {
                    id: "10.0.0.0/8".to_string(),
                },
                1, 10,
            ),
        ];

        let mut expected = Node::root();
        expected.append(
            tokens_to_branch(tokens.clone()).unwrap()
        );

        let root = build_tree(tokens).unwrap();
        assert_eq!(root, expected);
    }

    #[test]
    fn simple_rules() {
        let rules_tokens = vec![
            vec![
                Token::new(
                    TokenKind::RulePart {
                        id: "pass".to_string(),
                    },
                    1, 1,
                ),
                Token::new(
                    TokenKind::RulePart {
                        id: "icmp".to_string(),
                    },
                    1, 6,
                ),
            ],
            vec![
                Token::new(
                    TokenKind::RulePart {
                        id: "pass".to_string(),
                    },
                    1, 1,
                ),
                Token::new(
                    TokenKind::RulePart {
                        id: "tcp".to_string(),
                    },
                    1, 6,
                ),
                Token::new(
                    TokenKind::RulePart {
                        id: "10.0.0.0/8".to_string(),
                    },
                    1, 10,
                ),
            ],
            vec![
                Token::new(
                    TokenKind::RulePart {
                        id: "drop".to_string(),
                    },
                    1, 1,
                ),
            ],
        ];

        let mut expected = Node::root();
        for branch in rules_tokens.iter() {
            expected.append(
                tokens_to_branch(branch.clone()).unwrap()
            );
        }

        let flatten_rules_tokens = rules_tokens.into_iter().map(|mut branch| {
            branch.push(
                Token::new(
                    TokenKind::EOL,
                    0, 0,
                )
            );
            branch
        }).collect::<Vec<Vec<Token>>>().concat();

        let root = build_tree(flatten_rules_tokens).unwrap();
        assert_eq!(root, expected);
    }

    #[test]
    fn rules_block() {
        let (tokens, expected) = simple_tree();

        let root = build_tree(tokens).unwrap();
        assert_eq!(root, expected);
    }

    #[test]
    fn many_newlines() {
        let (tokens, expected) = simple_tree();

        let tokens = tokens.into_iter().map(|token| {
            let mut part = vec![token.clone()];
            if let TokenKind::EOL = token.get_kind() {
                for _ in 1..3 {
                    part.push(token.clone());
                }
            }
            part
        }).collect::<Vec<Vec<Token>>>().concat();

        let root = build_tree(tokens).unwrap();
        assert_eq!(root, expected);
    }

    #[test]
    fn root_block() {
        let tokens = vec![
            Token::new(
                TokenKind::BlockOpen,
                1, 1,
            ),
            Token::new(
                TokenKind::BlockClose,
                1, 3,
            ),
        ];

        let expected_err = ParseError::UnexpectedBlockOpen(
            tokens[0].clone(),
        );

        let errors = build_tree(tokens).unwrap_err();
        assert_eq!(errors[0], expected_err);
    }

    #[test]
    fn double_block() {
        let tokens = vec![
            Token::new(
                TokenKind::RulePart { id: "eth0".to_string() },
                1, 1,
            ),
            Token::new(
                TokenKind::BlockOpen,
                1, 6,
            ),
            Token::new(
                TokenKind::BlockOpen,
                1, 8,
            ),
            Token::new(
                TokenKind::BlockClose,
                2, 1,
            ),
            Token::new(
                TokenKind::BlockClose,
                2, 3,
            ),
        ];

        let expected_err = ParseError::UnexpectedBlockOpen(
            tokens[2].clone(),
        );

        let errors = build_tree(tokens).unwrap_err();
        assert_eq!(errors[0], expected_err);
    }

    #[test]
    fn missed_block_close() {
        let tokens = vec![
            Token::new(
                TokenKind::RulePart { id: "eth0".to_string() },
                1, 1,
            ),
            Token::new(
                TokenKind::BlockOpen,
                1, 6,
            ),
            Token::new(
                TokenKind::BlockClose,
                2, 1,
            ),
            Token::new(
                TokenKind::BlockClose,
                2, 3,
            ),
        ];

        let expected_err = ParseError::UnexpectedBlockClose(
            tokens[3].clone(),
        );

        let errors = build_tree(tokens).unwrap_err();
        assert_eq!(errors[0], expected_err);
    }

    #[test]
    fn unfinished_block() {
        let tokens = vec![
            Token::new(
                TokenKind::RulePart { id: "eth0".to_string() },
                1, 1,
            ),
            Token::new(
                TokenKind::BlockOpen,
                1, 6,
            ),
        ];

        let expected_err = ParseError::UnexpectedEnd;

        let errors = build_tree(tokens).unwrap_err();
        assert_eq!(errors[0], expected_err);
    }
}
