use crate::error::Error;
use crate::error::Error::ServerError;
use openssl::sha::sha256;
use simpletcp::simpletcp::{Message, TcpStream};
use std::convert::TryInto;
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

    pub fn get_user_by_username(&mut self, username: &str) -> Result<Option<User>, Error> {
        let hash = sha256(username.as_bytes());
        self.get_user(hash)
    }

    pub fn get_prev(&mut self) -> Result<[u8; 32], Error> {
        stdout().lock().flush().unwrap();
        let mut m = Message::new();
        m.write_u8(4);
        self.conn.write_blocking(&m).unwrap();

        let resp = self.conn.read_timeout(5000)?;
        match resp {
            None => Err(ServerError),
            Some(mut resp) => match resp.read_i8()? {
                -1 => Err(ServerError),
                0 => Ok([0; 32]),
                1 => {
                    let hash = resp.read_buffer()?.try_into()?;
                    Ok(hash)
                }
                _ => Err(ServerError),
            },
        }
    }

    pub fn set_user(&mut self, u: User) -> Result<(), Error> {
        let mut m = Message::new();
        m.write_u8(0);
        m.write_buffer(&u.key);
        m.write_buffer(&u.username);
        self.conn.write_blocking(&m)?;

        match self.conn.read_timeout(5000)? {
            None => Err(ServerError),
            Some(mut resp) => match resp.read_i8()? {
                0 => Ok(()),
                -1 => Err(ServerError),
                _ => Err(ServerError),
            },
        }
    }

    pub fn get_user(&mut self, hash: [u8; 32]) -> Result<Option<User>, Error> {
        let mut m = Message::new();
        m.write_u8(1);
        m.write_buffer(&hash);
        self.conn.write_blocking(&m)?;

        match self.conn.read_timeout(5000)? {
            None => Err(ServerError),
            Some(mut resp) => match resp.read_i8()? {
                0 => Ok(None),
                1 => {
                    let username = resp.read_buffer()?.to_vec();
                    let key = resp.read_buffer()?.to_vec();
                    Ok(Some(User { username, key }))
                }
                -1 => Err(ServerError),
                _ => Err(ServerError),
            },
        }
    }

    pub fn add_sig(&mut self, s: Signature) -> Result<(), Error> {
        let mut m = Message::new();
        m.write_buffer(&s.obj);
        m.write_buffer(&s.user);
        m.write_buffer(&s.prev_sig);
        m.write_buffer(&s.signature);
        self.conn.write_blocking(&m)?;

        match self.conn.read_timeout(5000)? {
            None => Err(ServerError),
            Some(mut resp) => match resp.read_i8()? {
                0 => Ok(()),
                _ => Err(ServerError),
            },
        }
    }

    pub fn get_obj(&mut self, hash: [u8; 32]) -> Result<Vec<[u8; 32]>, Error> {
        let mut m = Message::new();
        m.write_i8(2);
        m.write_buffer(&hash);
        self.conn.write_blocking(&m)?;

        match self.conn.read_timeout(5000)? {
            None => Err(ServerError),
            Some(mut resp) => match resp.read_i8()? {
                0 => Ok(Vec::new()),
                1 => {
                    let mut r = Vec::new();
                    loop {
                        let h = resp.read_buffer();
                        match h {
                            Ok(h) => {
                                r.push(h.try_into()?);
                            }
                            Err(_) => {
                                break;
                            }
                        }
                    }
                    Ok(r)
                }
                _ => Err(ServerError),
            },
        }
    }

    pub fn get_sig(&mut self, hash: [u8; 32]) -> Result<Option<Signature>, Error> {
        let mut m = Message::new();
        m.write_i8(3);
        m.write_buffer(&hash);

        self.conn.write_blocking(&m)?;

        let resp = self.conn.read_timeout(5000)?;
        match resp {
            None => Err(ServerError),
            Some(mut resp) => match resp.read_i8()? {
                0 => Ok(None),
                1 => {
                    let obj = resp.read_buffer()?.try_into()?;
                    let user = resp.read_buffer()?.try_into()?;
                    let prev_sig = resp.read_buffer()?.try_into()?;
                    let signature = resp.read_buffer()?.try_into()?;
                    let s = Signature {
                        obj,
                        user,
                        prev_sig,
                        signature,
                    };
                    Ok(Some(s))
                }
                _ => Err(ServerError),
            },
        }
    }
}

pub struct User {
    pub(crate) username: Vec<u8>,
    pub(crate) key: Vec<u8>,
}

pub struct Signature {
    pub(crate) obj: [u8; 32],
    pub(crate) user: [u8; 32],
    pub(crate) prev_sig: [u8; 32],
    pub(crate) signature: Vec<u8>,
}
