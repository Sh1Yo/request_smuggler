extern crate request_smuggler;
use request_smuggler::structs::{AttackType, AttackKind};

use crate::request_smuggler::{
    detections::{differential_responses, timing, send_request},
    args::get_config,
};
use std::fs::read_to_string;

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

    if config.file.is_empty() {
        let mut time_tech: Vec<AttackType> = Vec::new();
        let mut diff_tech: Vec<AttackType> = Vec::new();

        for attack_type in config.attack_types.iter() {
            if attack_type.kind() == AttackKind::Time {
                time_tech.push(*attack_type)
            } else {
                diff_tech.push(*attack_type)
            }
        }

        //if a website is vulnerable to Cl.Te req. smuggling vulnerability - Te.Cl time detection can disrupt other users
        //that's why it's important to check for Cl.Te one firstly
        if time_tech.len() == 2 && time_tech[0] != AttackType::ClTeTime {
            time_tech.swap(0, 1);
        }

        timing(&config, &time_tech);
        if !diff_tech.is_empty() {
            differential_responses(&config, &diff_tech);
        }
    } else {
        send_request(&config, &read_to_string(&config.file).unwrap())
    }
}
