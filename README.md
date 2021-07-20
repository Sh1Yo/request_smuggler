[![Twitter](https://img.shields.io/twitter/follow/sh1yo_.svg?logo=twitter)](https://twitter.com/sh1yo_)

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/B0B858X5E)

![crates.io](https://img.shields.io/crates/v/request_smuggler.svg)
![stars](https://img.shields.io/github/stars/Sh1Yo/request_smuggler)
![crates_downloads](https://img.shields.io/crates/d/request_smuggler?logo=rust)
![github_downloads](https://img.shields.io/github/downloads/sh1yo/request_smuggler/total?label=downloads&logo=github)

<h1 align="center">Request smuggler</h1>
<h3 align="center">Http request smuggling vulnerability scanner</h3>
<p align="center">
<img src=https://user-images.githubusercontent.com/54232788/126177471-151fade2-f7bb-4852-a106-59f35fe2b560.png>
</p>

Based on the amazing [research](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn) by [James Kettle](https://twitter.com/albinowax).
The tool can help to find servers that may be vulnerable to request smuggling vulnerability.

## Usage

```
USAGE:
    request_smuggler [FLAGS] [OPTIONS] --url <url>

FLAGS:
        --full       Tries to detect the vulnerability using differential responses as well.
                     Can disrupt other users!!!
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --amount-of-payloads <amount-of-payloads>    low/medium/all (default is "low")
    -H, --header <headers>                           Example: -H 'one:one' 'two:two'
    -X, --method <method>                            (default is "POST")
    -u, --url <url>
    -v, --verbose <verbose>
            0 - print detected cases and errors only, 1 - print first line of server responses (default is 0)
```

## Installation
- Linux
    - from releases
    - from source code (rust should be installed)
        ```bash
        git clone https://github.com/Sh1Yo/request_smuggler
        cd request_smuggler
        cargo build --release
        ```
    - using cargo install
        ```bash
        cargo install request_smuggler --version 0.1.0-alpha.1
        ```
- Mac
    - from source code (rust should be installed)
        ```bash
        git clone https://github.com/Sh1Yo/request_smuggler
        cd request_smuggler
        cargo build --release
        ```
    - using cargo install
        ```bash
        cargo install request_smuggler --version 0.1.0-alpha.1
        ```

- Windows
    - from releases