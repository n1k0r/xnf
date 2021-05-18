use super::lexer::{Action, CmpOp, Const, Kw, SKw, SizeUnit, TKind, Token, Type, EOL};

use std::collections::HashMap;

const ROOT_PROTO: &str = "ethertype";

#[derive(Debug)]
pub struct Filter {
    protocols: Vec<Protocol>,
    connections: Vec<Connection>,
    rules: Vec<Rule>,
}

impl Filter {
    pub fn protocols(&self) -> &[Protocol] {
        &self.protocols
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

#[derive(Debug)]
pub struct Rule {
    pub action: Action,
    pub iface: Option<String>,
    pub ethertype: Option<Const>,
    pub tests: Vec<ProtoTest>,
}

#[derive(Debug)]
pub struct ProtoTest {
    pub protocol: String,
    pub tests: Vec<FieldTest>,
}

#[derive(Debug)]
pub struct FieldTest {
    pub field: String,
    pub op: CmpOp,
    pub constant: Const,
}

#[derive(Debug)]
pub struct Protocol {
    pub name: String,
    token: Token,
    pub fields: Vec<Field>,
    pub size: usize, // excluding var_gap
    var_gap: Option<FinalVarGap>,
}

#[derive(Debug)]
struct FinalVarGap {
    pub field: String,
    pub multiplier: usize,
}

impl Protocol {
    fn new(name: String, token: Token) -> Protocol {
        Protocol {
            name,
            token,
            fields: vec![],
            size: 0,
            var_gap: None,
        }
    }
}

#[derive(Debug)]
pub struct Field {
    pub name: String,
    pub kind: Type,
    pub offset_bits: usize,
    pub size_bits: usize,
    is_protocol: bool,

    token_name: Token,
}

#[derive(Debug)]
struct Connection {
    container: String,
    encapsulated: String,
    ids: Vec<Const>,

    token_container: Token,
    token_encapsulated: Token,
    tokens_ids: Vec<Token>,
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
    Cmp { field: Token, op: Token, constant: Token },
}

#[derive(Debug, PartialEq)]
pub enum ParseError {
    UnexpectedToken { found: Token, expected: Vec<TKind> },
    UnexpectedEnd,
    ProtoSize { end: Token, size: usize },
    ReservedName { token: Token, name: String },
    ProtoNameDuplicate { token: Token, name: String },
    FieldNameDuplicate { token: Token, name: String, proto: String, used_in: String },
    UnknownRulePartId { token: Token, id: String },
    FieldUsedTwice { token: Token, name: String },
    UnknownProtocol { token: Token, name: String },
    ConnectionSameProtocol { token: Token, name: String },
    ConnectionWrongIdCount { token: Token, required: usize, given: usize },
    UnusedProtocol { token: Token, name: String },
    ConnectionsCycle { container: String, encapsulated: String },
    NoRootProto { token: Token },
    NoProtoPath { token: Token },
    UnknownField { token: Token, name: String },
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

pub fn build_filter<'a>(tokens: impl Iterator<Item = &'a Token> + Clone) -> Result<Filter, Vec<ParseError>> {
    let (protocols, connections, rules_root, mut errors) = parse_structs(tokens);

    let mut filter = Filter {
        protocols,
        connections,
        rules: vec![],
    };

    let mut proto_errors = check_proto(&filter.protocols, &filter.connections);
    errors.append(&mut proto_errors);

    if errors.len() > 0 {
        return Err(errors);
    }

    let flat_rules = flatten_node(vec![&rules_root]);
    let (rules, mut rules_errors) = process_rules(&flat_rules, &filter.protocols, &filter.connections);
    errors.append(&mut rules_errors);
    filter.rules = rules;

    // TODO: check cmp type

    if errors.len() > 0 {
        return Err(errors);
    }

    Ok(filter)
}

fn process_rules(parts: &Vec<Vec<RulePart>>, protocols: &Vec<Protocol>, connections: &Vec<Connection>) -> (Vec<Rule>, Vec<ParseError>) {
    let mut rules = vec![];
    let mut errors = vec![];

    'rules: for rule_parts in parts.iter() {
        if rule_parts.len() == 0 {
            continue;
        }

        let mut action = None;
        let mut iface = None;

        let mut protos = vec![];

        for part in rule_parts.iter() {
            match part {
                RulePart::Action(token) => {
                    if action.is_none() {
                        if let TKind::Keyword(Kw::Action(new_action)) = token.get_kind() {
                            action = Some(new_action);
                        }
                    }
                },
                RulePart::Identifier(token) => {
                    if let TKind::Identifier(id) = token.get_kind() {
                        let proto = protocols.iter().find(|p| p.name == *id);
                        match proto {
                            Some(proto) => protos.push(proto.name.clone()),
                            None => {
                                if iface.is_none() {
                                    iface = Some(id.clone());
                                    continue;
                                }

                                errors.push(
                                    ParseError::UnknownRulePartId {
                                        token: token.clone(),
                                        id: id.clone(),
                                    }
                                );
                            },
                        }
                    }
                },
                RulePart::Cmp {..} => {},
            }
        }

        let root_proto = protos.iter().find(|p| {
            connections.iter().find(|c| c.encapsulated == **p && c.container == ROOT_PROTO).is_some()
        });

        let last_token = match rule_parts.last().unwrap() {
            RulePart::Action(token) => token,
            RulePart::Identifier(token) => token,
            RulePart::Cmp { constant, .. } => constant,
        };

        if root_proto.is_none() {
            if action.is_some() && rule_parts.len() == 1 {
                rules.push(
                    Rule {
                        action: action.unwrap().clone(),
                        iface,
                        ethertype: None,
                        tests: vec![],
                    }
                );

                continue;
            }

            errors.push(
                ParseError::NoRootProto {
                    token: last_token.clone(),
                },
            );
            continue;
        }

        let root_proto = root_proto.unwrap().clone();

        protos.retain(|p| *p != root_proto);

        let root_con = connections.iter().find(|c| c.encapsulated == root_proto && c.container == ROOT_PROTO).unwrap();
        let mut cons_order = vec![root_con];

        let mut proto_order = vec![root_proto];
        while !protos.is_empty() {
            let last = proto_order.last().unwrap();
            let con = connections.iter().find(
                |c| c.container == **last && protos.contains(&c.encapsulated)
            );

            match con {
                Some(con) => {
                    proto_order.push(con.encapsulated.clone());
                    cons_order.push(con);
                    protos.retain(|p| *p != con.encapsulated);
                },
                None => {
                    errors.push(
                        ParseError::NoProtoPath {
                            token: last_token.clone(),
                        },
                    );

                    continue 'rules;
                },
            }
        }

        drop(protos);

        let mut tests: Vec<_> = proto_order.iter().map(|p| ProtoTest {
            protocol: p.clone(),
            tests: vec![],
        }).collect();

        let mut ethertype = None;
        for (num, con) in cons_order.iter().enumerate() {
            if num == 0 {
                ethertype = Some(con.ids[num].clone());
                continue;
            }

            let prototest = &mut tests[num - 1];
            let proto = protocols.iter().find(
                |p| p.name == prototest.protocol
            ).unwrap();

            let mut pos = 0;
            for field in proto.fields.iter() {
                if !field.is_protocol {
                    continue;
                }

                prototest.tests.push(
                    FieldTest {
                        field: field.name.clone(),
                        op: CmpOp::Equal,
                        constant: con.ids[pos].clone(),
                    }
                );

                pos += 1;
            }
        }

        for part in rule_parts.iter() {
            if let RulePart::Cmp { field, op, constant } = part {
                let field = if let TKind::Identifier(id) = field.get_kind() { id } else { unreachable!() };
                let op = if let TKind::Keyword(Kw::CmpOp(op)) = op.get_kind() { op } else { unreachable!() };
                let constant = if let TKind::Constant(constant) = constant.get_kind() { constant } else { unreachable!() };

                let proto = proto_order.iter().map(
                    |p| protocols.iter().find(|pp| pp.name == *p).unwrap()
                ).find(|p| p.fields.iter().find(|f| f.name == *field).is_some());

                if proto.is_none() {
                    errors.push(
                        ParseError::UnknownField {
                            token: last_token.clone(),
                            name: field.clone(),
                        },
                    );

                    continue 'rules;
                }

                let proto = proto.unwrap();
                let ptests = tests.iter_mut().find(|p| p.protocol == proto.name).unwrap();
                ptests.tests.push(
                    FieldTest {
                        field: field.clone(),
                        op: op.clone(),
                        constant: constant.clone(),
                    }
                );
            }
        }

        rules.push(
            Rule {
                action: action.unwrap().clone(),
                iface,
                ethertype,
                tests,
            }
        );
    }

    (rules, errors)
}

fn check_proto(protocols: &Vec<Protocol>, connections: &Vec<Connection>) -> Vec<ParseError> {
    let mut errors = vec![];

    errors.extend(
        check_proto_names(protocols)
    );

    errors.extend(
        check_proto_connections(protocols, connections)
    );

    errors.extend(
        check_proto_connected(protocols, connections)
    );

    errors.extend(
        check_proto_acyclic(protocols, connections)
    );

    if errors.len() > 0 {
        return errors;
    }

    errors.extend(
        check_proto_traverse(protocols, connections)
    );

    errors
}

fn check_proto_names(protocols: &Vec<Protocol>) -> Vec<ParseError> {
    let mut errors = vec![];

    for proto in protocols.iter() {
        let count = protocols.iter().filter(|p| p.name == proto.name).count();

        if count > 1 {
            let error = ParseError::ProtoNameDuplicate {
                name: proto.name.clone(),
                token: proto.token.clone(),
            };

            if !errors.contains(&error) {
                errors.push(error);
            }
        }

        if proto.name == ROOT_PROTO {
            errors.push(
                ParseError::ReservedName {
                    name: proto.name.clone(),
                    token: proto.token.clone(),
                }
            );
        }
    }

    errors
}

fn check_proto_connections(protocols: &Vec<Protocol>, connections: &Vec<Connection>) -> Vec<ParseError> {
    let mut errors = vec![];

    for connection in connections.iter() {
        let encapsulated = protocols.iter().find(|p| p.name == connection.encapsulated);
        if encapsulated.is_none() || connection.encapsulated == ROOT_PROTO {
            errors.push(
                ParseError::UnknownProtocol {
                    name: connection.encapsulated.clone(),
                    token: connection.token_encapsulated.clone(),
                }
            );

            continue;
        }

        let container = protocols.iter().find(|p| p.name == connection.container);
        if container.is_none() && connection.container != ROOT_PROTO {
            errors.push(
                ParseError::UnknownProtocol {
                    name: connection.container.clone(),
                    token: connection.token_container.clone(),
                }
            );

            continue;
        }

        if connection.encapsulated == connection.container {
            errors.push(
                ParseError::ConnectionSameProtocol {
                    name: connection.encapsulated.clone(),
                    token: connection.token_encapsulated.clone(),
                }
            );

            continue;
        }

        if connection.container != ROOT_PROTO {
            let container = container.unwrap();
            let container_id_count = container.fields.iter().filter(|f| f.is_protocol).count();
            let id_count = connection.ids.len();
            if id_count != container_id_count {
                errors.push(
                    ParseError::ConnectionWrongIdCount {
                        token: connection.token_container.clone(),
                        required: container_id_count,
                        given: id_count,
                    }
                )
            }
        }

        // TODO: check id type
    }

    errors
}

fn get_encapsulated<'a>(proto: &str, connections: &'a Vec<Connection>) -> Vec<&'a str> {
    connections.iter().filter_map(
        |c| if c.container == proto { Some(&c.encapsulated[..]) } else { None }
    ).collect::<Vec<_>>()
}

fn check_proto_connected(protocols: &Vec<Protocol>, connections: &Vec<Connection>) -> Vec<ParseError> {
    let mut errors = vec![];

    fn visit<'a>(proto: &'a str, connections: &'a Vec<Connection>, visited: &mut Vec<&'a str>) {
        if visited.contains(&proto) {
            return;
        }

        visited.push(proto);

        let childs = get_encapsulated(proto, connections);
        for child in childs {
            visit(child, connections, visited);
        }
    }

    let mut visited: Vec<&str> = vec![];
    visit(ROOT_PROTO, connections, &mut visited);

    for proto in protocols.iter() {
        if !visited.contains(&&proto.name[..]) {
            errors.push(
                ParseError::UnusedProtocol {
                    name: proto.name.clone(),
                    token: proto.token.clone(),
                }
            );
        }
    }

    errors
}

fn check_proto_acyclic(protocols: &Vec<Protocol>, connections: &Vec<Connection>) -> Vec<ParseError> {
    let mut errors = vec![];

    enum Mark {
        Current,
        Visited,
    }

    fn visit<'a>(proto: &'a str, connections: &'a Vec<Connection>, marks: &mut HashMap<&'a str, Mark>) -> Option<ParseError> {
        marks.insert(proto, Mark::Current);

        let childs = get_encapsulated(proto, connections);
        for child in childs {
            match marks.get(child) {
                None => {
                    match visit(child, connections, marks) {
                        error @ Some(_) => return error,
                        None => (),
                    }
                },
                Some(Mark::Current) => return Some(
                    ParseError::ConnectionsCycle {
                        container: child.to_string(),
                        encapsulated: proto.to_string(),
                    }
                ),
                _ => (),
            }
        }

        marks.insert(proto, Mark::Visited);
        None
    }

    let mut marks = HashMap::new();
    let mut error = visit(ROOT_PROTO, connections, &mut marks);
    for proto in protocols.iter() {
        if error.is_some() {
            break;
        }

        error = visit(&proto.name, connections, &mut marks);
    }

    if error.is_some() {
        errors.push(error.unwrap());
    }

    errors
}

fn check_proto_traverse(protocols: &Vec<Protocol>, connections: &Vec<Connection>) -> Vec<ParseError> {
    let mut errors = vec![];

    fn visit<'a>(proto: &'a str, protocols: &'a Vec<Protocol>, connections: &'a Vec<Connection>, names: &HashMap<&'a str, &'a str>, errors: &mut Vec<ParseError>) {
        let childs = get_encapsulated(proto, connections);
        for child in childs {
            let mut names = names.clone();

            let protocol = protocols.iter().find(|p| p.name == child);
            if let Some(protocol) = protocol {
                names.insert(child, child);

                for field in protocol.fields.iter() {
                    let name = &field.name[..];
                    if names.contains_key(name) {
                        errors.push(
                            ParseError::FieldNameDuplicate {
                                token: field.token_name.clone(),
                                name: field.name.to_string(),
                                proto: child.to_string(),
                                used_in: names[name].to_string(),
                            }
                        );

                        continue;
                    }

                    names.insert(name, child);
                }
            }

            visit(child, protocols, connections, &names, errors);
        }
    }

    let names = HashMap::new();
    visit(ROOT_PROTO, protocols, connections, &names, &mut errors);

    errors
}

fn flatten_node(stack: Vec<&Node>) -> Vec<Vec<RulePart>> {
    let last = stack.last().unwrap();
    let childs = last.get_childs();
    let leaf = childs.len() == 0;

    if leaf {
        let rule = stack.iter().skip(1)
            .map(
                |node| node.get_part().clone()
            )
            .collect();

        return vec![rule];
    }

    let mut rules = vec![];

    for child in childs {
        let mut child_stack = stack.clone();
        child_stack.push(child);

        let mut new_rules = flatten_node(child_stack);

        rules.append(&mut new_rules);
    }

    rules
}

fn parse_structs<'a>(mut tokens: impl Iterator<Item = &'a Token> + Clone) -> (Vec<Protocol>, Vec<Connection>, Node, Vec<ParseError>) {
    let mut protocols = vec![];
    let mut connections = vec![];
    let mut root = Node::root();
    let mut errors = vec![];

    while let Some(token) = tokens.next() {
        match token.get_kind() {
            &EOL => (),

            TKind::Keyword(
                Kw::Structural(SKw::Proto)
            ) => match parse_proto(&mut tokens) {
                Ok(proto) => protocols.push(proto),
                Err(mut proto_errors) => errors.append(&mut proto_errors),
            },

            TKind::Identifier(id)
                if tokens.clone().next().and_then(
                    |t| Some(t.get_kind().clone())
                ) == Some(TKind::Keyword(
                    Kw::Structural(SKw::TypeBlockOpen))
                )
            => match parse_connection(id.clone(), &token, &mut tokens) {
                Ok(connection) => { connections.push(connection); },
                Err(connection_error) => errors.push(connection_error),
            },

            TKind::Keyword(Kw::Action(_))
            | TKind::Constant(_)
            | TKind::Identifier(_) => match parse_rules_block(token, &mut tokens) {
                Ok(branch) => { root.append(branch); },
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

    (protocols, connections, root, errors)
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
    let name_token;
    if let Some(token) = tokens.next() {
        if let TKind::Identifier(id) = token.get_kind() {
            name = id.to_string();
            name_token = token.clone();
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

    let mut proto = Protocol::new(name, name_token);

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
            ) if proto.var_gap.is_none() => match parse_proto_field(id.to_string(), token.unwrap(), &mut ctx, tokens) {
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
    token_name: &Token,
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

        token_name: token_name.clone(),
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

fn parse_connection<'a>(container: String, token_container: &Token, tokens: &mut impl Iterator<Item=&'a Token>) -> Result<Connection, ParseError> {
    let token_encapsulated;
    if let Some(token) = tokens.next() {
        token_encapsulated = token;

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

    let mut connection = Connection {
        container,
        encapsulated: String::new(),
        ids: vec![],

        token_container: token_container.clone(),
        token_encapsulated: token_encapsulated.clone(),
        tokens_ids: vec![],
    };

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
                connection.tokens_ids.push(token.unwrap().clone());
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

fn const_to_cmp(token: &Token, constant: &Const) -> RulePart {
    let const_token = token.clone();
    let (line, col) = const_token.get_pos();

    let field_id = match constant {
        Const::Number(..) => "to",
        Const::Addr4(..) | Const::Addr6(..) => "src",
        Const::Any => panic!("Const::Any can't be converted to RulePart::Cmp"),
    }.to_string();

    let field = Token::new(TKind::Identifier(field_id), line, col);
    let op = Token::new(TKind::Keyword(Kw::CmpOp(CmpOp::Equal)), line, col);

    RulePart::Cmp { field, op, constant: const_token }
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

            Some(TKind::Constant(constant)) => {
                add_part = Some(
                    const_to_cmp(token.unwrap(), constant)
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
