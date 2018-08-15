#[macro_use]
extern crate clap;
extern crate sonm;

use clap::{App, Arg, SubCommand};

fn main() {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .arg(Arg::with_name("config")
            .global(true)
            .short("c")
            .long("config")
            .value_name("FILE")
            .help("Path to the configuration file")
            .takes_value(true))
        .subcommand(SubCommand::with_name("login")
            .arg(Arg::with_name("account")
                .value_name("ACCOUNT")
                .index(1)
                .help("Account ETH address")))
        .get_matches();

    match matches.subcommand() {
        ("login", Some(matches)) => {
            println!("{:?}", matches);
        }
        (cmd, ..) => {
            println!("Unknown command: {}", cmd);
        }
    }
}

// key -> sha256
