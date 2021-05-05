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
    let args = Arguments::parse();

    match args.command {
        Command::Check(check) => {
            let src = match std::fs::read_to_string(check.filter) {
                Ok(str) => str,
                Err(err) => {
                    eprintln!("{} {}", "Error:".red().bold(), err);
                    return;
                },
            };

            let tokens = xnf::lang::lexer::extract_tokens(&src);
            println!("{}", "Tokens:".bold().underline());
            tokens.iter().for_each(|token| println!("{}", token));

            println!("");

            let root = xnf::lang::parser::build_tree(tokens).unwrap();
            print!("{}\n{}", "Tree:".bold().underline(), root);
        },
        _ => println!("{:#?}", args), // TODO: implement other commands
    }
}
