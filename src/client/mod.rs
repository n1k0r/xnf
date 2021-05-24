use crate::lang::Filter;
use crate::{
    compiler::CompileError,
    ipc::{create_connection, ApplyError, Connection, Request, Response},
};

pub struct Client {
    connection: Connection,
}

impl Client {
    pub fn new() -> Option<Self> {
        let connection = match create_connection() {
            Some(c) => c,
            None => return None,
        };

        Some(Self { connection })
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

    pub fn apply_filter(&mut self, id: u64) -> Result<(), ClientError> {
        let req = Request::Apply(id);
        self.send(&req)?;

        match self.recv()? {
            Response::ApplyResult(Ok(())) => Ok(()),
            Response::ApplyResult(Err(err)) => Err(ClientError::ApplyError(err)),
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
    ConnectionClosed,
    UnexpectedResponse,
    ApplyError(ApplyError),
    CompilerError(CompileError),
}
