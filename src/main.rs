extern crate request_smuggler;
use crate::request_smuggler::{
    detections::{differential_responses, timing},
    raw_requests::make_connection,
    args::get_config,
};

#[cfg(windows)]
fn main() {
    colored::control::set_virtual_terminal(true).unwrap();
    run();
}

#[cfg(not(windows))]
fn main() {
    run();
}

fn run() {
    let config = get_config();

    timing(&config, make_connection(&config).unwrap());
    if config.full {
        differential_responses(&config, make_connection(&config).unwrap());
    }
    println!("Nothing found")
}
