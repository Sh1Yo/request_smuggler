use crate::{structs::{Config, AttackType}};
use clap::{crate_version, App, AppSettings, Arg};
use std::{collections::HashMap, str::FromStr};
use url::Url;

pub fn get_config() -> Config {
    let app = App::new("request_smuggler")
        .setting(AppSettings::ArgRequiredElseHelp)
        .version(crate_version!())
        .author("sh1yo <sh1yo@tuta.io>")
        .about("Http request smuggling vulnerability scanner")
        .arg(Arg::with_name("url")
            .short("u")
            .long("url")
            .takes_value(true)
            .required(true)
        )
        .arg(
            Arg::with_name("method")
                .short("X")
                .long("method")
                .value_name("method")
                .default_value("POST")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("headers")
                .short("H")
                .long("header")
                .help("Example: -H 'one:one' 'two:two'")
                .takes_value(true)
                .min_values(1)
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .help("0 - print detected cases and errors only,
1 - print first line of server responses
2 - print requests")
                .default_value("0")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("amount-of-payloads")
                .long("amount-of-payloads")
                .help("low/medium/all")
                .default_value("low")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("attack-types")
                .long("attack-types")
                .short("t")
                .help("[ClTeMethod, ClTePath, ClTeTime, TeClMethod, TeClPath, TeClTime] [default: \"ClTeTime\" \"TeClTime\"]")
                .min_values(1)
        )
        .arg(
            Arg::with_name("verify")
                .long("verify")
                .help("how many times verify the vulnerability")
                .default_value("2")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("file")
                .long("file")
                .help("send request from a file\nyou need to explicitly pass \\r\\n at the end of the lines")
                .takes_value(true)
        );

    let args = app.clone().get_matches();

    let verbose: usize = args.value_of("verbose").unwrap().parse().expect("incorrect verbose");
    let verify: usize = args.value_of("verify").unwrap().parse().expect("incorrect verify");

    let mut headers: HashMap<String, String> = HashMap::new();
    if let Some(val) = args.values_of("headers") {
        for header in val {
            let mut k_v = header.split(':');
            let key = k_v.next().expect("Unable to parse headers");
            let value: String = [
                k_v.next().expect("Unable to parse headers").to_string(),
                k_v.map(|x| ":".to_owned() + x).collect(),
            ].concat();

            headers.insert(key.to_string(), value);
        }
    };

    let mut attack_types: Vec<AttackType> = Vec::new();
    if let Some(val) = args.values_of("attack-types") {
        for attack_type in val {
            attack_types.push(AttackType::from_str(attack_type).expect("Unable to parse attack-type"));
        }
    };

    if attack_types.is_empty() {
        attack_types = vec![AttackType::ClTeTime, AttackType::TeClTime]
    }

    let url = Url::parse(args.value_of("url").expect("No URL is provided")).expect("Unable to parse URL");

    let host = url.host_str().unwrap();
    let path = url[url::Position::BeforePath..].to_string();
    let mut port = match url.port() {
        Some(val) => val as usize,
        None => 0
    };

    if !headers.keys().any(|i| i.contains("User-Agent")) {
        headers.insert(String::from("User-Agent"), String::from("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36"));
    }
    if !headers.keys().any(|i| i.contains("Host")) {
        headers.insert(String::from("Host"), host.to_string());
    }
    if !headers.keys().any(|i| i.contains("Accept")) {
        headers.insert(String::from("Accept"), String::from("*/*"));
    }
    headers.insert(String::from("Accept-Encoding"), String::from("gzip"));

    let url = args
        .value_of("url")
        .unwrap()
        .to_string();

    let https = url.contains("https://");
    if port == 0 {
        port = match https {
            true => 443,
            false => 80
        }
    };

    println!("Loaded attack types: {:?}", attack_types);

    Config{
        url,
        host: host.to_string(),
        path,
        method: args.value_of("method").unwrap().to_string(),
        https,
        port,
        headers,
        attack_types,
        verify,
        amount_of_payloads: args.value_of("amount-of-payloads").unwrap().to_string(),
        verbose,
        file: args.value_of("file").unwrap_or("").to_string(),
    }
}