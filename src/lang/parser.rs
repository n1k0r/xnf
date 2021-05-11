use super::lexer::{Action, Const, Kw, SKw, SizeUnit, TKind, Token, Type, EOL};

#[derive(Debug)]
pub struct Filter {
    protocols: Vec<Protocol>,
    connections: Vec<Connection>,
    rules: Node,
}

impl Filter {
    fn new() -> Filter {
        Filter {
            protocols: vec![],
            connections: vec![],
            rules: Node::root(),
        }
    }
}

#[derive(Debug)]
struct Protocol {
    name: String,
    fields: Vec<Field>,
    size: usize, // excluding var_gap
    var_gap: Option<FinalVarGap>,
}

#[derive(Debug)]
struct FinalVarGap {
    field: String,
    multiplier: usize,
}

impl Protocol {
    fn new(name: String) -> Protocol {
        Protocol {
            name,
            fields: vec![],
            size: 0,
            var_gap: None,
        }
    }
}

#[derive(Debug)]
struct Field {
    name: String,
    kind: Type,
    offset_bits: usize,
    size_bits: usize,
    is_protocol: bool,
}

#[derive(Debug)]
struct Connection {
    container: String,
    encapsulated: String,
    ids: Vec<Const>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    part: RulePart,
    childs: Vec<Node>,
}

impl Node {
    fn new(part: RulePart) -> Node {
        Node {
            part,
            childs: vec![],
        }
    }

    fn root() -> Node {
        Node::new(RulePart::Identifier(Token::root()))
    }

    fn append(&mut self, node: Node) -> &mut Node {
        self.childs.push(node);
        self.childs.last_mut().unwrap()
    }

    pub fn get_part(&self) -> &RulePart {
        &self.part
    }

    pub fn get_childs(&self) -> &Vec<Node> {
        &self.childs
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum RulePart {
    Action(Token),
    Identifier(Token),
    Const(Token),
    Cmp { field: Token, op: Token, constant: Token },
}

#[derive(Debug, PartialEq)]
pub enum ParseError {
    UnexpectedToken { found: Token, expected: Vec<TKind> },
    UnexpectedEnd,
    ProtoSize { end: Token, size: usize },
}

fn unexp_token(found: &Token, expected: TKind) -> ParseError {
    ParseError::UnexpectedToken {
        found: found.clone(),
        expected: vec![expected],
    }
}

fn unexp_token_plural(found: &Token, expected: Vec<TKind>) -> ParseError {
    ParseError::UnexpectedToken {
        found: found.clone(),
        expected: expected,
    }
}

pub fn parse<'a>(mut tokens: impl Iterator<Item = &'a Token> + Clone) -> Result<Filter, Vec<ParseError>> {
    let mut filter = Filter::new();
    let mut errors = vec![];

    while let Some(token) = tokens.next() {
        match token.get_kind() {
            &EOL => (),

            TKind::Keyword(
                Kw::Structural(SKw::Proto)
            ) => match parse_proto(&mut tokens) {
                Ok(proto) => filter.protocols.push(proto),
                Err(mut proto_errors) => errors.append(&mut proto_errors),
            },

            TKind::Identifier(id)
                if tokens.clone().next().and_then(
                    |t| Some(t.get_kind().clone())
                ) == Some(TKind::Keyword(
                    Kw::Structural(SKw::TypeBlockOpen))
                )
            => match parse_connection(id.clone(), &mut tokens) {
                Ok(connection) => { filter.connections.push(connection); },
                Err(connection_error) => errors.push(connection_error),
            },

            TKind::Keyword(Kw::Action(_))
            | TKind::Constant(_)
            | TKind::Identifier(_) => match parse_rules_block(token, &mut tokens) {
                Ok(branch) => { filter.rules.append(branch); },
                Err(mut rules_errors) => errors.append(&mut rules_errors),
            },

            _ => errors.push(
                unexp_token_plural(&token, vec![
                    TKind::Keyword(Kw::Structural(SKw::Proto)),
                    TKind::any_id(),
                    TKind::Keyword(Kw::Action(Action::Any)),
                    TKind::Constant(Const::Any),
                    TKind::Keyword(Kw::Structural(SKw::Delimiter)),
                    EOL,
                ])
            ),
        }
    }

    if errors.len() > 0 {
        return Err(errors);
    }

    Ok(filter)
}

struct ParseProtoContext {
    offset_bits: usize,
}

fn advance_until_tokens<'a>(tokens: &mut impl Iterator<Item=&'a Token>, expected_tokens: Vec<TKind>) {
    while let Some(token) = tokens.next() {
        if expected_tokens.iter().any(
            |expected| token.get_kind() == expected
        ) {
            break;
        }
    }
}

fn advance_until_token<'a>(tokens: &mut impl Iterator<Item=&'a Token>, token: TKind) {
    advance_until_tokens(tokens, vec![token])
}

fn advance_until_eol<'a>(tokens: &mut impl Iterator<Item=&'a Token>) {
    advance_until_token(tokens, EOL)
}

fn parse_proto<'a>(tokens: &mut impl Iterator<Item=&'a Token>) -> Result<Protocol, Vec<ParseError>> {
    let mut errors = vec![];

    let error_advance = |tokens|
        advance_until_token(tokens, TKind::Keyword(
            Kw::Structural(SKw::ProtoBlockClose))
        );

    let name;
    if let Some(token) = tokens.next() {
        if let TKind::Identifier(id) = token.get_kind() {
            name = id.to_string();
        } else {
            errors.push(
                unexp_token(token, TKind::any_id())
            );

            error_advance(tokens);
            return Err(errors);
        }
    } else {
        errors.push(ParseError::UnexpectedEnd);
        return Err(errors);
    }

    let mut proto = Protocol::new(name);

    if let Some(token) = tokens.next() {
        if *token.get_kind() != TKind::Keyword(
            Kw::Structural(SKw::ProtoBlockOpen)
        ) {
            errors.push(
                unexp_token(token, TKind::Keyword(
                    Kw::Structural(SKw::ProtoBlockOpen)
                ))
            );

            error_advance(tokens);
            return Err(errors);
        }
    } else {
        errors.push(ParseError::UnexpectedEnd);
        return Err(errors);
    }

    let mut ctx = ParseProtoContext {
        offset_bits: 0,
    };

    let mut last = None;

    loop {
        let token = tokens.next();
        if token.is_some() {
            last = token;
        }

        let kind = token.and_then(|t| Some(t.get_kind()));
        match kind {
            Some(&EOL) => (),

            Some(
                TKind::Identifier(id)
            ) if proto.var_gap.is_none() => match parse_proto_field(id.to_string(), &mut ctx, tokens) {
                Ok(field) => proto.fields.push(field),
                Err(field_error) => errors.push(field_error),
            },

            Some(TKind::Keyword(
                Kw::Structural(SKw::Delimiter)
            )) if proto.var_gap.is_none() => match parse_proto_gap(&mut ctx, tokens) {
                Ok(None) => (),
                Ok(Some(var_gap)) => proto.var_gap = Some(var_gap),
                Err(field_error) => errors.push(field_error),
            },

            Some(TKind::Keyword(
                Kw::Structural(SKw::ProtoBlockClose)
            )) => {
                break;
            }

            Some(_) => {
                errors.push(
                    unexp_token_plural(token.unwrap(), vec![
                        TKind::any_id(),
                        TKind::Keyword(Kw::Structural(SKw::Delimiter)),
                        TKind::Keyword(Kw::Structural(SKw::ProtoBlockClose)),
                    ])
                );

                error_advance(tokens);
                return Err(errors);
            }

            None => {
                errors.push(ParseError::UnexpectedEnd);
                break;
            },
        }
    }

    if ctx.offset_bits % 8 != 0 && last.is_some() {
        errors.push(ParseError::ProtoSize { end: last.unwrap().clone(), size: ctx.offset_bits });
    }

    proto.size = ctx.offset_bits;

    if errors.len() > 0 {
        error_advance(tokens);
        return Err(errors);
    }

    Ok(proto)
}

fn parse_proto_gap<'a>(
    ctx: &mut ParseProtoContext,
    tokens: &mut impl Iterator<Item=&'a Token>
) -> Result<Option<FinalVarGap>, ParseError> {
    let size: usize;

    match parse_size(tokens) {
        Ok(parsed_size) => size = parsed_size,
        Err(size_error) => {
            advance_until_eol(tokens);
            return Err(size_error);
        },
    }

    let mut fvg = None;
    let mut expect_fvg = false;

    if let Some(token) = tokens.next() {
        match *token.get_kind() {
            EOL => (),
            TKind::Keyword(Kw::Structural(SKw::Of)) => expect_fvg = true,
            _ => {
                advance_until_eol(tokens);
                return Err(
                    unexp_token(token, EOL)
                );
            }
        }
    } else {
        return Err(ParseError::UnexpectedEnd);
    }

    if !expect_fvg {
        ctx.offset_bits += size;
    } else {
        let field;
        if let Some(token) = tokens.next() {
            if let TKind::Identifier(id) = token.get_kind() {
                field = id.to_string();
            } else {
                advance_until_eol(tokens);
                return Err(
                    unexp_token(token, TKind::any_id())
                );
            }
        } else {
            return Err(ParseError::UnexpectedEnd);
        }

        fvg = Some(
            FinalVarGap {
                field,
                multiplier: size,
            }
        );
    }

    Ok(fvg)
}

fn parse_proto_field<'a>(
    name: String,
    ctx: &mut ParseProtoContext,
    tokens: &mut impl Iterator<Item=&'a Token>
) -> Result<Field, ParseError> {
    if let Some(token) = tokens.next() {
        if *token.get_kind() != TKind::Keyword(
            Kw::Structural(SKw::Delimiter)
        ) {
            advance_until_eol(tokens);
            return Err(
                unexp_token(token, TKind::Keyword(
                    Kw::Structural(SKw::Delimiter)
                ))
            );
        }
    } else {
        return Err(ParseError::UnexpectedEnd);
    }

    let ftype: Option<Type>;

    if let Some(token) = tokens.next() {
        if let TKind::Keyword(
            Kw::Type(field_type)
        ) = token.get_kind() {
            ftype = Some(field_type.clone());
        } else {
            advance_until_eol(tokens);
            return Err(
                unexp_token(token, TKind::Keyword(
                    Kw::Type(Type::Any)
                ))
            );
        }
    } else {
        return Err(ParseError::UnexpectedEnd);
    }

    if let Some(token) = tokens.next() {
        if *token.get_kind() != TKind::Keyword(
            Kw::Structural(SKw::TypeBlockOpen)
        ) {
            advance_until_eol(tokens);
            return Err(
                unexp_token(token, TKind::Keyword(
                    Kw::Structural(SKw::TypeBlockOpen)
                ))
            );
        }
    } else {
        return Err(ParseError::UnexpectedEnd);
    }

    let size;

    match parse_size(tokens) {
        Ok(parsed_size) => size = parsed_size,
        Err(size_error) => {
            advance_until_eol(tokens);
            return Err(size_error);
        },
    }

    if let Some(token) = tokens.next() {
        if *token.get_kind() != TKind::Keyword(
            Kw::Structural(SKw::TypeBlockClose)
        ) {
            advance_until_eol(tokens);
            return Err(
                unexp_token(token, TKind::Keyword(
                    Kw::Structural(SKw::TypeBlockClose)
                ))
            );
        }
    } else {
        return Err(ParseError::UnexpectedEnd);
    }

    let mut protofield = false;

    if let Some(token) = tokens.next() {
        match token.get_kind() {
            &EOL => (),

            TKind::Keyword(
                Kw::Structural(SKw::ProtoField)
            ) => protofield = true,

            _ => {
                advance_until_eol(tokens);
                return Err(
                    unexp_token_plural(token, vec![
                        TKind::Keyword(Kw::Structural(SKw::TypeBlockClose)),
                        EOL,
                    ])
                );
            },
        }
    }

    let field = Field {
        name: name.clone(),
        kind: ftype.unwrap(),
        offset_bits: ctx.offset_bits,
        size_bits: size,
        is_protocol: protofield,
    };

    ctx.offset_bits += size;

    Ok(field)
}

fn parse_size<'a>(tokens: &mut impl Iterator<Item=&'a Token>) -> Result<usize, ParseError> {
    let mut size: usize;

    if let Some(token) = tokens.next() {
        if let TKind::Constant(
            Const::Number(num)
        ) = token.get_kind() {
            size = *num as usize;
        } else {
            return Err(
                unexp_token(token, TKind::Constant(
                    Const::Number(0)
                ))
            );
        }
    } else {
        return Err(ParseError::UnexpectedEnd);
    }

    if let Some(token) = tokens.next() {
        if let TKind::Keyword(
            Kw::SizeUnit(unit)
        ) = token.get_kind() {
            size *= unit.to_bits();
        } else {
            return Err(
                unexp_token(token, TKind::Keyword(
                    Kw::SizeUnit(SizeUnit::Any),
                ))
            );
        }
    } else {
        return Err(ParseError::UnexpectedEnd);
    }

    Ok(size)
}

fn parse_connection<'a>(container: String, tokens: &mut impl Iterator<Item=&'a Token>) -> Result<Connection, ParseError> {
    let mut connection = Connection {
        container,
        encapsulated: String::new(),
        ids: vec![],
    };

    if let Some(token) = tokens.next() {
        if *token.get_kind() != TKind::Keyword(
            Kw::Structural(SKw::TypeBlockOpen)
        ) {
            advance_until_eol(tokens);
            return Err(
                unexp_token(token, TKind::Keyword(
                    Kw::Structural(SKw::TypeBlockOpen)
                ))
            );
        }
    } else {
        return Err(ParseError::UnexpectedEnd);
    }

    loop {
        let token = tokens.next();
        let kind = token.and_then(|t| Some(t.get_kind()));
        match kind {
            Some(TKind::Keyword(
                Kw::Structural(SKw::TypeBlockClose)
            )) => {
                break;
            }

            Some(TKind::Constant(constant)) => {
                connection.ids.push(constant.clone());
            },

            Some(_) => {
                advance_until_eol(tokens);
                return Err(
                    unexp_token_plural(token.unwrap(), vec![
                        TKind::Keyword(Kw::Structural(SKw::TypeBlockClose)),
                        TKind::Constant(Const::Any),
                    ])
                );
            }

            None => {
                return Err(ParseError::UnexpectedEnd);
            },
        }
    }

    if let Some(token) = tokens.next() {
        if *token.get_kind() != TKind::Keyword(
            Kw::Structural(SKw::Is)
        ) {
            advance_until_eol(tokens);
            return Err(
                unexp_token(token, TKind::Keyword(
                    Kw::Structural(SKw::Is)
                ))
            );
        }
    } else {
        return Err(ParseError::UnexpectedEnd);
    }

    if let Some(token) = tokens.next() {
        if let TKind::Identifier(id) = token.get_kind() {
            connection.encapsulated = id.to_string();
        } else {
            advance_until_eol(tokens);
            return Err(
                unexp_token(token, TKind::any_id())
            );
        }
    } else {
        return Err(ParseError::UnexpectedEnd);
    }

    Ok(connection)
}

fn parse_rules_block<'a>(first: &Token, tokens: &mut (impl Iterator<Item=&'a Token> + Clone)) -> Result<Node, Vec<ParseError>> {
    let mut errors: Vec<ParseError> = vec![];

    let mut root = None;

    let mut hanging = true;
    let mut stack = vec![0 as u32];

    let expected = vec![
        TKind::any_id(),
        TKind::Keyword(Kw::Action(Action::Any)),
        TKind::Constant(Const::Any),
        TKind::Keyword(Kw::Structural(SKw::RuleBlockOpen)),
        TKind::Keyword(Kw::Structural(SKw::RuleBlockClose)),
        EOL,
    ];

    let mut first_processed = false;
    loop {
        let mut add_part = None;

        let token = if !first_processed { first_processed = true; Some(first) } else { tokens.next() };
        let kind = token.and_then(|t| Some(t.get_kind()));
        match kind {
            Some(&EOL) if hanging && root != None => {
                hanging = false;
                stack.pop();

                if stack.len() < 1 {
                    break;
                }
            },

            Some(&EOL) if !hanging => (),

            Some(TKind::Keyword(
                Kw::Structural(SKw::RuleBlockOpen)
            )) if root != None => {
                match hanging {
                    true => hanging = false,
                    false => errors.push(
                        unexp_token_plural(
                            token.unwrap(),
                            expected.iter()
                                .cloned()
                                .filter(|kind| *kind != TKind::Keyword(Kw::Structural(SKw::RuleBlockOpen)))
                                .collect()
                        )
                    ),
                };
            },

            Some(TKind::Keyword(
                Kw::Structural(SKw::RuleBlockClose)
            )) if root != None => {
                match hanging {
                    false => {
                        stack.pop();
                        if stack.len() < 1 {
                            break;
                        }
                    },
                    true => errors.push(
                        unexp_token_plural(
                            token.unwrap(),
                            expected.iter()
                                .cloned()
                                .filter(|kind| *kind != TKind::Keyword(Kw::Structural(SKw::RuleBlockClose)))
                                .collect()
                        )
                    ),
                };
            },

            Some(TKind::Constant(_)) => {
                add_part = Some(
                    RulePart::Const(token.unwrap().clone())
                );
            },

            Some(TKind::Keyword(Kw::Action(_))) => {
                add_part = Some(
                    RulePart::Action(token.unwrap().clone())
                );
            },

            Some(TKind::Identifier(_)) => {
                let try_cmp = parse_cmp_rule(token.unwrap(), &mut tokens.clone());
                if let Ok(None) = try_cmp {
                    add_part = Some(
                        RulePart::Identifier(token.unwrap().clone())
                    );
                } else {
                    let cmp = parse_cmp_rule(token.unwrap(), tokens);
                    match cmp {
                        Ok(Some(part)) => add_part = Some(part),
                        Ok(None) => (),
                        Err(cmp_error) => errors.push(cmp_error),
                    }
                }
            },

            Some(_) => {
                errors.push(
                    unexp_token_plural(token.unwrap(), expected)
                );

                return Err(errors);
            }

            None => {
                errors.push(ParseError::UnexpectedEnd);
                return Err(errors);
            },
        }

        if add_part.is_none() {
            continue;
        }

        let node = Node::new(add_part.unwrap());

        if root.is_none() {
            root = Some(node);
            continue;
        }

        let last = *stack.last().unwrap();
        let root_node = &mut root.as_mut().unwrap();
        let parent = get_right_subchild(root_node, last).unwrap();
        parent.append(node);

        if hanging {
            stack.pop();
        }
        stack.push(last + 1);

        hanging = true;
    }

    if errors.len() > 0 {
        return Err(errors);
    }

    Ok(root.unwrap())
}

fn parse_cmp_rule<'a>(first: &Token, tokens: &mut impl Iterator<Item=&'a Token>) -> Result<Option<RulePart>, ParseError> {
    let part_field;
    let part_op;
    let part_const;

    if let TKind::Identifier(_) = first.get_kind() {
        part_field = first.clone();
    } else {
        return Ok(None);
    }

    if let Some(token) = tokens.next() {
        if let TKind::Keyword(Kw::CmpOp(_)) = token.get_kind() {
            part_op = token.clone();
        } else {
            return Ok(None);
        }
    } else {
        return Ok(None);
    }

    if let Some(token) = tokens.next() {
        if let TKind::Constant(_) = token.get_kind() {
            part_const = token.clone();
        } else {
            return Err(
                unexp_token(token, TKind::Constant(Const::Any))
            );
        }
    } else {
        return Err(ParseError::UnexpectedEnd);
    }

    let part = RulePart::Cmp {
        field: part_field,
        op: part_op,
        constant: part_const,
    };

    Ok(Some(part))
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

#[cfg(test)]
mod tests;
