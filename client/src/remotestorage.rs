use crate::error::Error;
use crate::error::Error::ServerError;
use hex::encode;
use openssl::sha::sha256;
use simpletcp::simpletcp::{Message, TcpStream};
use std::convert::TryInto;
use std::io;
use std::io::{stdout, Write};
use std::net::ToSocketAddrs;

pub struct RemoteStorage {
    conn: TcpStream,
}

impl RemoteStorage {
    pub fn new<A: ToSocketAddrs>(addr: A) -> Result<Self, Error> {
        let mut conn = TcpStream::connect(addr)?;
        conn.wait_until_ready()?;
        Ok(Self { conn })
    }

    pub fn set_key(&mut self, key: &[u8], username: &str) -> Result<(), Error> {
        print!("[Remote] set_key u={} k={}: ", username, encode(&key[..8]));
        let mut m = Message::new();
        m.write_u8(0);
        m.write_buffer(key);
        m.write_buffer(username.as_bytes());
        self.conn.write_blocking(&m)?;
        let mut resp = self.conn.read_blocking()?;
        if resp.read_i8()? != 0 {
            println!("Error");
            return Err(ServerError);
        }
        println!("Ok");
        Ok(())
    }

    pub fn get_key(&mut self, user_hash: [u8; 32]) -> Result<Option<(String, Vec<u8>)>, Error> {
        print!("[Remote] get_key u={}: ", encode(&user_hash[..8]));
        let mut m = Message::new();
        m.write_u8(1);
        m.write_buffer(&user_hash);
        self.conn.write_blocking(&m)?;
        let mut resp = self.conn.read_blocking()?;
        return match resp.read_i8()? {
            0 => {
                println!("None");
                Ok(None)
            }
            1 => {
                let username = String::from_utf8(resp.read_buffer()?.to_vec())?;
                let key = resp.read_buffer()?.to_vec();
                println!("u={} k={}", username, encode(&key[..8]));
                Ok(Some((username, key)))
            }
            _ => {
                println!("Error");
                Err(ServerError)
            }
        };
    }
    pub fn get_key_by_username(
        &mut self,
        username: &str,
    ) -> Result<Option<(String, Vec<u8>)>, Error> {
        let hash = sha256(username.as_bytes());
        self.get_key(hash)
    }

    pub fn set_file(
        &mut self,
        hash: [u8; 32],
        user_hash: [u8; 32],
        signature: &[u8],
    ) -> Result<(), Error> {
        print!(
            "[Remote] set_file h={} u={} sig={}: ",
            encode(&hash[..8]),
            encode(&user_hash[..8]),
            encode(&signature[..8])
        );
        let mut m = Message::new();
        m.write_buffer(&hash);
        m.write_buffer(&user_hash);
        m.write_buffer(signature);
        self.conn.write_blocking(&m)?;
        let mut resp = self.conn.read_blocking()?;
        if resp.read_i8()? != 0 {
            println!("Error");
            return Err(ServerError);
        }
        println!("Ok");
        Ok(())
    }

    pub fn get_file(&mut self, hash: [u8; 32]) -> Result<Option<SignedFile>, Error> {
        print!("[Remote] get_file h={}: ", encode(&hash[..8]));
        let mut m = Message::new();
        m.write_u8(2);
        m.write_buffer(&hash);
        self.conn.write_blocking(&m)?;
        self.receive_file()
    }

    fn receive_file(&mut self) -> Result<Option<SignedFile>, Error> {
        print!("recv_file: ");
        let mut resp = self.conn.read_blocking()?;
        return match resp.read_i8()? {
            0 => {
                println!("None");
                Ok(None)
            }
            1 => {
                let hash: [u8; 32] = resp.read_buffer()?.to_vec()[..32].try_into()?;
                let user_hash: [u8; 32] = resp.read_buffer()?.to_vec()[..32].try_into()?;
                let prev_hash: [u8; 32] = resp.read_buffer()?.to_vec()[..32].try_into()?;
                let signature = resp.read_buffer()?.to_vec();
                println!(
                    "hash={} u={} prev_hash = {} sig={}",
                    encode(&hash[..8]),
                    encode(&user_hash[..8]),
                    encode(&prev_hash[..8]),
                    encode(&signature[..8])
                );
                Ok(Some(SignedFile {
                    hash,
                    user_hash,
                    prev_hash,
                    signature,
                }))
            }
            _ => {
                println!("Error");
                Err(ServerError)
            }
        };
    }

    pub fn get_prev(&mut self) -> Result<Option<SignedFile>, Error> {
        print!("[Remote] get_prev: ");
        stdout().lock().flush().unwrap();
        let mut m = Message::new();
        m.write_u8(4);
        self.conn.write_blocking(&m).unwrap();
        self.receive_file()
    }
}

pub struct SignedFile {
    pub hash: [u8; 32],
    pub user_hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub signature: Vec<u8>,
}

impl SignedFile {
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), io::Error> {
        writer.write_all(&self.hash)?;
        writer.write_all(&self.user_hash)?;
        writer.write_all(&self.prev_hash)?;
        writer.write_all(&self.signature)?;
        Ok(())
    }
}
