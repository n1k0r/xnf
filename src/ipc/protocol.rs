use super::unix;
use crate::{compiler::CompileError, lang::Filter};

use serde::{Deserialize, Serialize};

use std::path::PathBuf;

pub const SOCKET_PATH: &str = "/run/xnf.sock";

pub type Listener = unix::Listener<Response, Request>;
pub type ServerConnection = unix::Connection<Response, Request>;
pub type Connection = unix::Connection<Request, Response>;

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Compile(Filter),
    Apply(u64),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    CompileResult(Result<u64, CompileError>),
    ApplyResult(Result<(), ApplyError>),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ApplyError {
    ObjectNotFound,
    VerifierRejected,
}

pub fn create_listener() -> Option<Listener> {
    let path = PathBuf::from(SOCKET_PATH);
    let listener = Listener::new(&path);
    listener
}

pub fn create_connection() -> Option<Connection> {
    let path = PathBuf::from(SOCKET_PATH);
    let connection = Connection::new(&path);
    connection
}
