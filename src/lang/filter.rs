use super::tokens::*;

#[derive(Debug)]
pub struct Filter {
    protocols: Vec<Protocol>,
    connections: Vec<Connection>,
    rules: Vec<Rule>,
}

impl Filter {
    pub fn new(protocols: Vec<Protocol>, connections: Vec<Connection>, rules: Vec<Rule>) -> Filter {
        Filter {
            protocols,
            connections,
            rules,
        }
    }

    pub fn protocols(&self) -> &[Protocol] {
        &self.protocols
    }

    pub fn connections(&self) -> &[Connection] {
        &self.connections
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
    pub token: Token,
    pub fields: Vec<Field>,
    pub size: usize, // excluding var_gap
    pub var_gap: Option<FinalVarGap>,
}

impl Protocol {
    pub fn new(name: String, token: Token) -> Protocol {
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
pub struct FinalVarGap {
    pub field: String,
    pub multiplier: usize,
}

#[derive(Debug)]
pub struct Field {
    pub name: String,
    pub kind: Type,
    pub offset_bits: usize,
    pub size_bits: usize,
    pub is_protocol: bool,

    pub token_name: Token,
}

#[derive(Debug)]
pub struct Connection {
    pub container: String,
    pub encapsulated: String,
    pub ids: Vec<Const>,

    pub token_container: Token,
    pub token_encapsulated: Token,
    pub tokens_ids: Vec<Token>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    pub part: RulePart,
    pub childs: Vec<Node>,
}

impl Node {
    pub fn new(part: RulePart) -> Node {
        Node {
            part,
            childs: vec![],
        }
    }

    pub fn root() -> Node {
        Node::new(RulePart::Identifier(Token::root()))
    }

    pub fn append(&mut self, node: Node) -> &mut Node {
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
