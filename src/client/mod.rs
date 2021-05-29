use crate::{
    compiler::CompileError,
    filter::LoadError,
    ipc::{self, Connection, Request, Response},
    lang::{Filter, RuleTest},
    verifier::VerifiedRule,
};

use std::io::Error as IOError;
use std::path::PathBuf;

pub struct Client {
    connection: Connection,
}

impl Client {
    pub fn new() -> Result<Self, ClientError> {
        let path = PathBuf::from(ipc::SOCKET_PATH);
        let connection = match Connection::new(&path) {
            Ok(c) => c,
            Err(err) => return Err(ClientError::OpenListener(path, err)),
        };

        Ok(Self { connection })
    }

    pub fn compile_filter(&mut self, filter: Filter) -> Result<u64, ClientError> {
        let req = Request::Compile(filter);
        self.send(&req)?;

        match self.recv()? {
            Response::CompileResult(result) => match result {
                Ok(id) => Ok(id),
                Err(err) => Err(ClientError::CompilerError(err)),
            },
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    pub fn load_filter(&mut self, id: u64) -> Result<(), ClientError> {
        let req = Request::Load(id);
        self.send(&req)?;

        match self.recv()? {
            Response::LoadResult(Ok(())) => Ok(()),
            Response::LoadResult(Err(err)) => Err(ClientError::LoadError(err)),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    pub fn verify_filter(&mut self, filter: Filter, test: RuleTest) -> Result<Vec<VerifiedRule>, ClientError> {
        let req = Request::Verify(filter, test);
        self.send(&req)?;

        match self.recv()? {
            Response::VerifyResult(rules) => Ok(rules),
            _ => Err(ClientError::UnexpectedResponse),
        }
    }

    fn send(&mut self, req: &Request) -> Result<(), ClientError> {
        if let Err(_) = self.connection.send(&req) {
            return Err(ClientError::ConnectionClosed);
        }

        Ok(())
    }

    fn recv(&mut self) -> Result<Response, ClientError> {
        match self.connection.next() {
            Some(resp) => Ok(resp),
            None => Err(ClientError::ConnectionClosed),
        }
    }
}

#[derive(Debug)]
pub enum ClientError {
    OpenListener(PathBuf, IOError),
    ConnectionClosed,
    UnexpectedResponse,
    LoadError(LoadError),
    CompilerError(CompileError),
}
