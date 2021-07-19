use crate::{structs::Config};
use clap::{crate_version, App, AppSettings, Arg};
use std::{collections::HashMap, io::{self, Write}};
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
        /*.arg(
            Arg::with_name("proxy")
                .short("x")
                .long("proxy")
                .value_name("proxy")
        )*/
        .arg(
            Arg::with_name("method")
                .short("X")
                .long("method")
                .value_name("method")
                .help("(default is \"POST\")")
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
                .help("0 - print detected cases and errors only, 1 - print first line of server responses (default is 0)")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("full")
                .long("full")
                .help("Tries to detect the vulnerability using differential responses as well.\nCan disrupt other users!!!")
        )
        .arg(
            Arg::with_name("amount-of-payloads")
                .long("amount-of-payloads")
                .help("low/medium/all (default is \"low\")")
                .takes_value(true)
        );

    let args = app.clone().get_matches();

    let verbose: usize = match args.value_of("verbose") {
        Some(val) => val.parse().expect("incorrect verbose"),
        None => 0,
    };

    let mut headers: HashMap<String, String> = HashMap::new();
    if let Some(val) = args.values_of("headers") {
        for header in val {
            let mut k_v = header.split(':');
            let key = match k_v.next() {
                Some(val) => val,
                None => {
                    writeln!(io::stderr(), "Unable to parse headers").ok();
                    std::process::exit(1);
                }
            };
            let value: String = [
                match k_v.next() {
                    Some(val) => val.trim().to_owned(),
                    None => {
                        writeln!(io::stderr(), "Unable to parse headers").ok();
                        std::process::exit(1);
                    }
                },
                k_v.map(|x| ":".to_owned() + x).collect(),
            ].concat();

            headers.insert(key.to_string(), value);
        }
    };

    let url = match Url::parse(args.value_of("url").unwrap_or("https://example.com")) {
        Ok(val) => val,
        Err(err) => {
            writeln!(io::stderr(), "Unable to parse target url: {}", err).ok();
            std::process::exit(1);
        },
    };

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
        .unwrap_or("https://something.something")
        .to_string();

    let https = url.contains("https://");
    if port == 0 {
        port = match https {
            true => 443,
            false => 80
        }
    };

    Config{
        url,
        host: host.to_string(),
        path,
        method: args.value_of("method").unwrap_or("POST").to_string(),
        https,
        port,
        proxy: args.value_of("proxy").unwrap_or("").to_string(),
        headers,
        full: args.is_present("full"),
        amount_of_payloads: args.value_of("amount-of-payloads").unwrap_or("low").to_string(),
        verbose
    }
}