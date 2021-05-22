use super::filter::*;
use super::parser::{ROOT_PROTO, ParseError};

use std::collections::HashMap;

pub fn check_proto(protocols: &Vec<Protocol>, connections: &Vec<Connection>) -> Vec<ParseError> {
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
