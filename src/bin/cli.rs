use xnf::{
    client::{Client, ClientError},
    compiler::CompileError,
    filter::{storage::filter_name, LoadError},
    lang::{tokens::*, Filter, LexicalError, ParseError, RuleTest},
    verifier,
};

use clap::{AppSettings, Clap};
use colored::*;
use human_panic::setup_panic;

#[derive(Clap, Debug)]
#[clap(
    about,
    version,
    setting=AppSettings::ColoredHelp,
    setting=AppSettings::GlobalVersion,
    setting=AppSettings::VersionlessSubcommands,
)]
struct Arguments {
    #[clap(subcommand)]
    command: Command,

    /// Print intermediate data structures
    #[clap[short, long]]
    debug: bool,
}

#[derive(Clap, Debug)]
enum Command {
    Load(Load),
    Check(Check),
    Verify(Verify),
}

/// Loads specified filter
#[derive(Clap, Debug)]
struct Load {
    /// Path to filter description file
    filter: String,
}

/// Checks syntax of specified filter without loading
#[derive(Clap, Debug)]
struct Check {
    /// Path to filter description file
    filter: String,
}

/// Checks if packets of specified type would be rejected
#[derive(Clap, Debug)]
struct Verify {
    /// Path to filter description file
    #[clap[short, long]]
    filter: String,

    /// Type of packets for test
    rule: Vec<String>,
}

fn main() {
    setup_panic!();

    let mut eprint = ErrorPrinter::new();

    let args = Arguments::parse();
    match args.command {
        Command::Load(load) => {
            let filter = match parse_filter_file(&mut eprint, &load.filter, args.debug) {
                Ok(filter) => filter,
                Err(()) => std::process::exit(1),
            };

            let mut client = match Client::new() {
                Ok(client) => client,
                Err(_) => {
                    eprintln!("{}", "Unable to connect to daemon".bold().red());
                    std::process::exit(1);
                },
            };

            let filter_id = match client.compile_filter(filter) {
                Ok(id) => id,
                Err(err) => {
                    eprint.client_error(&err);
                    std::process::exit(1);
                },
            };

            if let Err(err) = client.load_filter(filter_id) {
                eprint.client_error(&err);
                std::process::exit(1);
            }

            println!("{}", "Filter applied to network interfaces".bold().green());
        },
        Command::Check(check) => {
            let result = parse_filter_file(&mut eprint, &check.filter, args.debug);
            if let Ok(_) = result {
                println!("{}", "Filter is valid".bold().green());
            }
        },
        Command::Verify(verify) => {
            let filter = match parse_filter_file(&mut eprint, &verify.filter, args.debug) {
                Ok(filter) => filter,
                Err(()) => std::process::exit(1),
            };

            let test_raw = verify.rule.join(" ");
            let test = match parse_test(&mut eprint, &test_raw, &filter, args.debug) {
                Ok(filter) => filter,
                Err(()) => std::process::exit(1),
            };

            let matched_rules = verifier::verify(&filter, &test);
            for rule in matched_rules.iter() {
                print_rule(rule);
            }

            if matched_rules.len() == 0 {
                println!("{}", "No rule matched this test so packet would be passed".bold().blue());
            }
        },
    }
}

fn parse_filter_file(eprint: &mut ErrorPrinter, path: &str, debug: bool) -> Result<Filter, ()> {
    let src = match std::fs::read_to_string(path) {
        Ok(str) => str,
        Err(err) => {
            eprint.error(&err.to_string());
            std::process::exit(1);
        },
    };

    parse_filter(eprint, &src, debug)
}

fn parse_filter(eprint: &mut ErrorPrinter, src: &str, debug: bool) -> Result<Filter, ()> {
    eprint.set_src(src);

    let (tokens, errors) = xnf::lang::lexer::extract_tokens(&src);
    if debug {
        println!("{}", "Tokens:".bold());
        tokens.iter().for_each(|t| println!("{:?}", t));
        println!();
    }

    for error in errors.iter() {
        eprint.lexical_error(error);
    }

    let filter = xnf::lang::parser::build_filter(tokens.iter());
    if let Err(errors) = filter {
        for error in errors {
            eprint.parser_error(&error);
        }

        std::process::exit(1);
    }

    if errors.len() > 0 {
        std::process::exit(1);
    }

    if debug {
        println!("{}", "Filter:".bold());
        println!("{:#?}\n", filter);
    }

    Ok(filter.unwrap())
}

fn parse_test(eprint: &mut ErrorPrinter, src: &str, filter: &Filter, debug: bool) -> Result<RuleTest, ()> {
    eprint.set_src(src);

    let (tokens, errors) = xnf::lang::lexer::extract_tokens(&src);
    if debug {
        println!("{}", "Tokens:".bold());
        tokens.iter().for_each(|t| println!("{:?}", t));
        println!();
    }

    if errors.len() > 0 {
        for error in errors.iter() {
            eprint.lexical_error(error);
        }

        std::process::exit(1);
    }

    let test = match xnf::lang::parser::parse_test(tokens.iter(), filter) {
        Ok(test) => test,
        Err(errors) => {
            for error in errors {
                eprint.parser_error(&error);
            }

            std::process::exit(1);
        },
    };

    if debug {
        println!("{}", "Test:".bold());
        println!("{:#?}\n", test);
    }

    Ok(test)
}

fn print_rule(vrule: &verifier::VerifiedRule) {
    let rule = vrule.rule;
    let mut line = vec![];

    if let Some(iface) = &rule.iface {
        line.push(iface.blue());
        line.push(" ".to_string().normal());
    }

    line.push(match rule.action {
        Action::Pass => "pass".green(),
        Action::Drop => "drop".red(),
        Action::Any => unreachable!(),
    });

    if let Some(test) = &rule.test {
        for proto in test.tests.iter() {
            line.push(" ".to_string().normal());
            line.push(proto.protocol.underline());

            for field in proto.tests.iter() {
                let op = match field.op {
                    CmpOp::Equal => "=",
                    CmpOp::NotEqual => "!=",
                    CmpOp::Greater => ">",
                    CmpOp::GreaterOrEqual => ">=",
                    CmpOp::Lesser => "<",
                    CmpOp::LesserOrEqual => "<=",
                    CmpOp::Any => unreachable!(),
                };

                let constant = match field.constant {
                    Const::Number(num) => format!("{}", num),
                    Const::Addr4(addr, prefix) => format!("{}/{}", addr, prefix),
                    Const::Addr6(addr, prefix) => format!("{}/{}", addr, prefix),
                    Const::Any => unreachable!(),
                };

                line.push(" ".to_string().normal());
                line.push(field.field.normal());
                line.push(op.normal());
                line.push(constant.normal());
            }
        }
    }

    line.iter().for_each(
        |part| print!("{}", if vrule.last {
            part.clone().bold()
        } else {
            part.clone()
        })
    );
    println!();
}

struct ErrorPrinter {
    first_error: bool,
    src: Option<String>,
}

impl ErrorPrinter {
    fn new() -> ErrorPrinter {
        ErrorPrinter {
            first_error: true,
            src: None,
        }
    }

    fn set_src(&mut self, src: &str) {
        self.src = Some(src.to_string());
    }

    fn check_line(&mut self) {
        if self.first_error {
            self.first_error = false;
        } else {
            eprintln!();
        }
    }

    fn error(&mut self, msg: &str) {
        self.first_error = false;

        eprintln!(
            "{}{}",
            "error: ".bold().red(),
            msg.bold(),
        );
    }

    fn error_pos(&mut self, msg: &str, line: usize, column: usize) {
        self.check_line();

        if let Some(src) = &self.src {
            let src_line = src.lines().nth(line - 1);
            if let Some(src_line) = src_line {
                let line_str = line.to_string();
                let line_prefix = format!(
                    "{}{}{}",
                    "line ".bold().dimmed(),
                    line_str.bold().dimmed(),
                    ":  ".bold().dimmed(),
                );

                eprintln!(
                    "{}{}",
                    &line_prefix,
                    src_line.trim(),
                );

                let diff = src_line.chars().count() - src_line.trim_start().chars().count();
                let pos_offset = column - 1 + line_str.len() - diff + 5 + 3;
                eprintln!("{}{}", " ".repeat(pos_offset), "^".yellow());
            }
        }

        self.error(msg);
    }

    fn lexical_error(&mut self, error: &LexicalError) {
        let msg = format!("unrecognized token `{}`", error.token);
        self.error_pos(&msg, error.line, error.column);
    }

    fn tkind_name(kind: &TKind) -> &str {
        match kind {
            TKind::Identifier(_) => "Identifier",
            TKind::Constant(constant) => match constant {
                Const::Any => "Constant",
                Const::Number(_) => "Number",
                Const::Addr4(..) => "IPv4 address",
                Const::Addr6(..) => "IPv6 address",
            },
            TKind::Keyword(kw) => match kw {
                Kw::Structural(skw) => match skw {
                    SKw::Proto => "proto",
                    SKw::Is => "->",
                    SKw::ProtoBlockOpen => "{",
                    SKw::ProtoBlockClose => "}",
                    SKw::Delimiter => ":",
                    SKw::ProtoField => "!",
                    SKw::TypeBlockOpen => "(",
                    SKw::TypeBlockClose => ")",
                    SKw::Of => "*",
                    SKw::RuleBlockOpen => "[",
                    SKw::RuleBlockClose => "]",
                    SKw::EOL => "new line",
                },
                Kw::Action(_) => "Action",
                Kw::CmpOp(_) => "Compare operation",
                Kw::SizeUnit(_) => "Size unit",
                Kw::Type(_) => "Field type",
            },
        }
    }

    fn parser_error(&mut self, error: &ParseError) {
        match error {
            ParseError::UnexpectedToken { found, expected } => {
                let (line, column) = found.get_pos();

                let found_str = ErrorPrinter::tkind_name(found.get_kind());
                let expected_str = expected.iter()
                    .map(|tk| ErrorPrinter::tkind_name(tk))
                    .collect::<Vec<_>>()
                    .join(", ");

                let mut msg = format!("encountered an unexpected token {} while expecting ", found_str);
                if expected.len() > 1 {
                    let end = format!("one of: {}", expected_str);
                    msg += &end;
                } else {
                    let end = format!("{}", expected_str);
                    msg += &end;
                };

                self.error_pos(&msg, line, column);
            },
            ParseError::UnexpectedEnd => {
                let mut line = 0;
                let mut column = 0;

                if let Some(src) = &self.src {
                    line = src.lines().count();
                    if let Some(last) = src.lines().last() {
                        column = last.chars().count();
                    }
                }

                self.error_pos("unexpected end of file", line, column);
            },
            ParseError::ProtoSize { end, size } => {
                let (line, column) = end.get_pos();
                let msg = format!("total size of header have to be byte padded but got {} bits", size);
                self.error_pos(&msg, line, column);
            },
            ParseError::ReservedName { name, token } => {
                let (line, column) = token.get_pos();
                let msg = format!("used reserved identifier `{}`", name);
                self.error_pos(&msg, line, column);
            },
            ParseError::ProtoNameDuplicate { token, name } => {
                let (line, column) = token.get_pos();
                let msg = format!("protocol named `{}` is not unique", name);
                self.error_pos(&msg, line, column);
            },
            ParseError::FieldNameDuplicate { token, name, proto, used_in } => {
                let (line, column) = token.get_pos();
                let msg = format!("field named `{}` of protocol `{}` is already used in protocol `{}`", proto, name, used_in);
                self.error_pos(&msg, line, column);
            },
            ParseError::UnknownRulePartId { token, id } => {
                let (line, column) = token.get_pos();
                let msg = format!("identificator `{}` unknown", id);
                self.error_pos(&msg, line, column);
            },
            ParseError::FieldUsedTwice { name, token } => {
                let (line, column) = token.get_pos();
                let msg = format!("field `{}` is already used in this rule", name);
                self.error_pos(&msg, line, column);
            },
            ParseError::UnknownProtocol { name, token } => {
                let (line, column) = token.get_pos();
                let msg = format!("unknown protocol `{}` used", name);
                self.error_pos(&msg, line, column);},
            ParseError::ConnectionSameProtocol { name, token } => {
                let (line, column) = token.get_pos();
                let msg = format!("connection use same protocol `{}` twice", name);
                self.error_pos(&msg, line, column);
            },
            ParseError::ConnectionWrongIdCount { token, required, given } => {
                let (line, column) = token.get_pos();
                let msg = format!("protocol requires {} ID fields but {} is specified", required, given);
                self.error_pos(&msg, line, column);
            },
            ParseError::UnusedProtocol { name, token } => {
                let (line, column) = token.get_pos();
                let msg = format!("protocol `{}` can not be used because it is not connected to any other protocol or `ethertype`", name);
                self.error_pos(&msg, line, column);
            },
            ParseError::ConnectionsCycle { container, encapsulated } => {
                let msg = format!("connection cycle found (detected between protocols `{}` -> `{}`)", container, encapsulated);
                self.error(&msg);
            },
            ParseError::NoRootProto { token } => {
                let (line, column) = token.get_pos();
                let msg = "no used protocols connected with `ethertype`";
                self.error_pos(&msg, line, column);
            },
            ParseError::NoProtoPath { token } => {
                let (line, column) = token.get_pos();
                let msg = "this rule does not contain sequential set of protocols";
                self.error_pos(&msg, line, column);
            },
            ParseError::UnknownField { token, name } => {
                let (line, column) = token.get_pos();
                let msg = format!("field `{}` is not part of any used protocols", name);
                self.error_pos(&msg, line, column);
            },
            ParseError::TooManyTokensForTest => {
                self.error("test must be single rule without specified action or interface");
            }
        }
    }

    fn compile_error(&mut self, error: &CompileError) {
        match error {
            CompileError::CmpOpNotImplemented(op) => println!("operator {:?} is not implemented", op),
            CompileError::CreateStorage(err) => println!("unable to create storage: {}", err),
            CompileError::ObjSaveError(err) => println!("unable to save object: {}", err),
            CompileError::TypeNotImplemented(t) => println!("type {:?} is not implemented", t),
            CompileError::TargetUnavailable => println!("unable to create LLVM target"),
            CompileError::FieldOffset { field, proto } => {
                let msg = format!("wrong offset of field `{}` in protocol `{}`", field, proto);
                self.error(&msg);
            },
            CompileError::FieldSize { field, proto } => {
                let msg = format!("wrong size of field `{}` in protocol `{}`", field, proto);
                self.error(&msg);
            },
            CompileError::FieldType { field, proto } => {
                let msg = format!("wrong type of field `{}` in protocol `{}`", field, proto);
                self.error(&msg);
            },
        }
    }

    fn load_error(&mut self, error: &LoadError) {
        match error {
            LoadError::StorageNotExist(id) => println!("filter {} does not exist", filter_name(id)),
            LoadError::InvalidStorage(id) => println!("filter storage {} is invalid", filter_name(id)),
            LoadError::MarkStorage(id, err) => println!("unable to mark filter {}: {}", filter_name(id), err),
            LoadError::Open(err) => println!("unable to open object: {}", err),
            LoadError::Load(err) => println!("unable to load object: {}", err),
            LoadError::Attach(err) => println!("unable to attach filter to network interface: {}", err),
            LoadError::IfacesList => println!("unable to get list of network interfaces"),
            LoadError::IfaceNotExist(iface) => println!("unable to attach filter to nonexistent network interface `{}`", iface),
            LoadError::InternalError => println!("internal communication error"),
        }
    }

    fn client_error(&mut self, error: &ClientError) {
        match error {
            ClientError::CompilerError(err) => self.compile_error(err),
            ClientError::LoadError(err) => self.load_error(err),
            ClientError::OpenListener(path, err) => {
                let msg = format!(
                    "unable to connect to {}: {}",
                    path.to_str().unwrap(),
                    err.to_string()
                );
                self.error(&msg);
            },
            ClientError::ConnectionClosed => self.error("connection to daemon closed"),
            ClientError::UnexpectedResponse => self.error("received unexpected response from daemon"),
        }
    }
}
