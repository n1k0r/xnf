use xnf::lang::{lexer::{Const, Kw, LexicalError, SKw, TKind}, parser::ParseError};

use clap::{AppSettings, Clap};
use colored::*;

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
    Show(Show),
    Load(Load),
    Check(Check),
    Verify(Verify),
    Stats(Stats),
}

/// Lists network interfaces and status of attached filters
#[derive(Clap, Debug)]
struct Show {}

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

/// Retrieves statistics for loaded filters
#[derive(Clap, Debug)]
struct Stats {}

fn main() {
    let mut eprint = ErrorPrinter::new();

    let args = Arguments::parse();
    match args.command {
        Command::Check(check) => {
            let src = match std::fs::read_to_string(check.filter) {
                Ok(str) => str,
                Err(err) => {
                    eprint.error(&err.to_string());
                    std::process::exit(1);
                },
            };

            eprint.set_src(&src);

            let (tokens, errors) = xnf::lang::lexer::extract_tokens(&src);
            if args.debug {
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

            if args.debug {
                println!("{}", "Filter:".bold());
                println!("{:#?}\n", filter);
            }

            println!("{}", "Filter is valid".bold().green());
        },
        _ => println!("{:#?}", args), // TODO: implement other commands
    }
}

struct ErrorPrinter<'a> {
    first_error: bool,
    src: Option<&'a str>,
}

impl<'a> ErrorPrinter<'a> {
    fn new() -> ErrorPrinter<'a> {
        ErrorPrinter {
            first_error: true,
            src: None,
        }
    }

    fn set_src(&mut self, src: &'a str) {
        self.src = Some(src);
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

        if let Some(src) = self.src {
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

                if let Some(src) = self.src {
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
        }
    }
}
