use simpletcp::simpletcp::TcpServer;

use crate::threadpool::Server;

mod error;
mod localstorage;
mod threadpool;

fn main() {
    let mut pool = Server::new(8, "storage");
    let server = TcpServer::new("0.0.0.0:37687").unwrap();
    loop {
        match server.accept_blocking() {
            Ok(client) => {
                pool.accept(client);
            }
            _ => {}
        }
    }
}
