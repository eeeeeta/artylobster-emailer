extern crate imap;
extern crate mailparse;
extern crate serde;
extern crate serde_json;
#[macro_use] extern crate failure;
extern crate toml;
#[macro_use] extern crate serde_derive;
extern crate native_tls;
extern crate regex;
extern crate reqwest;

#[derive(Deserialize, Debug)]
pub struct Config {
    imap_domain: String,
    imap_port: u16,
    imap_username: String,
    imap_password: String,
    form_email: String,
    backoffice_url: String,
    backoffice_username: String,
    backoffice_password: String
}
#[derive(Deserialize, Debug)]
pub struct EmailData {
    name: String,
    email: String,
    phonetext: String,
    petname: String,
    petbreed: Option<String>,
    comments: Option<String>
}
#[derive(Default, Clone, Debug, Serialize)]
#[allow(non_snake_case)]
pub struct BackofficeData {
    billingAddress1: Option<String>,
    billingAddress2: Option<String>,
    billingAddress3: Option<String>,
    billingAddress4: Option<String>,
    billingAddress5: Option<String>,
    comments: Option<String>,
    email: Option<String>,
    facebook: Option<String>,
    id: Option<String>,
    instagram: Option<String>,
    mobile: Option<String>,
    name: Option<String>,
    phone: Option<String>,
    shippingAddress1: Option<String>,
    shippingAddress2: Option<String>,
    shippingAddress3: Option<String>,
    shippingAddress4: Option<String>,
    shippingAddress5: Option<String>,
    twitter: Option<String>,
}
use std::fs::File;
use std::io::prelude::*;
use std::collections::HashMap;
use regex::Regex;
use reqwest::header::{Cookie, CookieJar, SetCookie, Headers, ContentType};
use reqwest::Response;
fn run() -> Result<(), failure::Error> {
    println!("[+] Arty Lobster Automatic Customer Maker v0.0.1");
    println!("[+] Reading configuration file from 'config.toml'...");
    let mut file = File::open("config.toml")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let cfg: Config = toml::from_str(&contents)?;
    let socket_addr = (&cfg.imap_domain as &str, cfg.imap_port);
    println!("[+] Initialising SSL");
    let ssl_connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    println!("[+] Connecting to IMAP server '{}' on port {}...", cfg.imap_domain, cfg.imap_port);
    let mut imap_socket = imap::client::Client::secure_connect(socket_addr, &cfg.imap_domain, &ssl_connector)?;
    println!("[+] Authenticating as user '{}'...", cfg.imap_username);
    imap_socket.login(&cfg.imap_username, &cfg.imap_password)?;
    println!("[+] Opening INBOX...");
    imap_socket.select("INBOX")?;
    println!("[+] Finding unread emails from '{}'...", cfg.form_email);
    let mut unseen = imap_socket
        .run_command_and_read_response(&format!("UID SEARCH FROM {} UNSEEN 1:*", cfg.form_email))?;
    // remove last line of response (OK Completed)
    unseen.pop();
    let mut num_unseen = 0;
    let mut uids = Vec::new();
    let unseen = ::std::str::from_utf8(&unseen[..]).unwrap();
    let unseen = unseen.split_whitespace().skip(2);
    for uid in unseen.take_while(|&e| e != "" && e != "Completed") {
        if let Ok(uid) = usize::from_str_radix(uid, 10) {
            uids.push(format!("{}", uid));
            num_unseen += 1;
        }
    }
    println!("[+] {} unread emails to process", num_unseen);
    let mut datas = Vec::new();
    if !uids.is_empty() {
        for msg in imap_socket
            .uid_fetch(&uids.join(","), "body[text]")?
            .iter() {
                if let Some(body) = msg.body() {
                    println!("[+] Processing new message");
                    let text = ::std::str::from_utf8(&body).unwrap();
                    let mut attrs = HashMap::new();
                    for attr in &["name", "email", "phonetext", "petname", "petbreed", "comments"] {
                        let re = Regex::new(&format!("##{0} (.*) ##end_{0}", attr)).unwrap();
                        if let Some(caps) = re.captures(&text) {
                            if let Some(cap) = caps.get(1) {
                                println!("[+] Extracted attribute: '{}' -> '{}'", attr, cap.as_str());
                                attrs.insert(attr.to_string(), cap.as_str().to_string());
                            }
                        }
                    }
                    println!("[+] Parsing message data");
                    let val = match serde_json::to_value(attrs) {
                        Ok(v) => v,
                        Err(e) => {
                            println!("[!] error converting message data to value: {}", e);
                            println!("[!] skipping message");
                            continue;
                        }
                    };
                    let data: EmailData = match serde_json::from_value(val) {
                        Ok(v) => v,
                        Err(e) => {
                            println!("[!] error parsing message data: {}", e);
                            println!("[!] skipping message");
                            continue;
                        }
                    };
                    println!("[+] Got data: {:?}", data);
                    datas.push(data);
                }
        }
    }
    println!("[+] Got {} customers to create", datas.len());
    println!("[+] Attempting to login to backoffice...");
    let mut jar = CookieJar::new(b"definitely secret");
    println!("[+] Initializing reqwest");
    let client = reqwest::Client::new()?;
    println!("[+] Requesting main page");
    let mut resp = client.get(&cfg.backoffice_url).send()?;
    on_response(&mut jar, &mut resp)?;
    println!("[+] Logging in as '{}'...", cfg.backoffice_username);
    let mut params = HashMap::new();
    params.insert("j_username", &cfg.backoffice_username as &str);
    params.insert("j_password", &cfg.backoffice_password);
    params.insert("remember-me", "false");
    params.insert("submit", "Login");
    let mut resp = client.post(&format!("{}/api/authentication", cfg.backoffice_url))
        .headers(get_headers(&jar)?)
        .form(&params)
        .send()?;
    on_response(&mut jar, &mut resp)?;
    println!("[+] checking backoffice connectivity...");
    let mut resp = client.get(&format!("{}/api/account", cfg.backoffice_url))
        .headers(get_headers(&jar)?)
        .send()?;
    on_response(&mut jar, &mut resp)?;
    println!("[+] processing customers");
    for data in datas {
        println!("[+] uploading customer '{}'...", data.name);
        let n = data.name.clone();
        let mut comments = format!("Pet name: {}\n", data.petname);
        if let Some(pb) = data.petbreed {
            if pb.trim() != "" {
                comments.push_str(&format!("Pet breed: {}\n", pb));
            }
        }
        if let Some(c) = data.comments {
            if c.trim() != "" {
                comments.push_str(&format!("Customer comments: {}\n", c));
            }
        }
        let bod = BackofficeData {
            name: Some(data.name),
            email: Some(data.email),
            phone: Some(data.phonetext),
            comments: Some(comments),
            ..Default::default()
        };
        println!("[+] serializing backoffice data");
        let json = serde_json::to_string(&bod)?;
        println!("[+] uploading to backoffice...");
        let mut resp = client.post(&format!("{}/api/customers", cfg.backoffice_url))
            .headers(get_headers(&jar)?)
            .header(ContentType::json())
            .body(json)
            .send()?;
        if let Err(e) = on_response(&mut jar, &mut resp) {
            println!("[!] *** Uploading customer '{}' failed ***", n);
            println!("[!] *** Error message: {} ***", e);
            println!("[!] You probably need to do this customer manually.");
        }
    }
    Ok(())
}
fn check_success(resp: &mut Response) -> Result<(), failure::Error> {
    if !resp.status().is_success() {
        let mut text = String::new();
        resp.read_to_string(&mut text)?;
        println!("[!] request failed, body: {}", text);
        Err(format_err!("request failed with {}", resp.status()))
    }
    else {
        Ok(())
    }
}
fn get_headers(jar: &CookieJar) -> Result<Headers, failure::Error> {
    let mut hdrs = Headers::new();
    hdrs.set(Cookie::from_cookie_jar(&jar));
    if let Some(ck) = jar.find("CSRF-TOKEN") {
        hdrs.set_raw("X-CSRF-TOKEN", vec![ck.value.as_bytes().to_owned()]);
    }
    else {
        return Err(format_err!("no CSRF token"));
    }
    Ok(hdrs)
}
fn on_response(jar: &mut CookieJar, resp: &mut Response) -> Result<(), failure::Error> {
    println!("[+] Got response");
    for hdr in resp.headers().iter() {
        if let Some(sch) = hdr.value::<SetCookie>() {
            println!("[*] Applying cookies: {:?}", sch);
            sch.apply_to_cookie_jar(jar);
        }
    }
    check_success(resp)?;
    Ok(())
}
fn main() {
    run().unwrap();
}
