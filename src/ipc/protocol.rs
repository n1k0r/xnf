use super::unix;
use crate::{
    compiler::CompileError,
    filter::{
        stats::{StatsError, StatsValues},
        storage::FilterID,
        IfaceInfo, LoadError,
    },
    lang::{Filter, RuleTest},
    verifier::VerifiedRule,
};

use serde::{Deserialize, Serialize};

pub const SOCKET_PATH: &str = "/run/xnf.sock";
pub const PID_PATH: &str = "/run/xnf.pid";

pub type Listener = unix::Listener<Response, Request>;
pub type ServerConnection = unix::Connection<Response, Request>;
pub type Connection = unix::Connection<Request, Response>;

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Compile(Filter),
    Load(FilterID),
    Unload,
    Verify(Filter, RuleTest),
    Info,
    GetStats,
    ResetStats,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    CompileResult(Result<FilterID, CompileError>),
    LoadResult(Result<(), LoadError>),
    UnloadResult(Result<(), LoadError>),
    VerifyResult(Vec<VerifiedRule>),
    InfoResult(Result<Vec<IfaceInfo>, LoadError>),
    StatsValuesResult(Result<StatsValues, StatsError>),
    ResetStatsResult(Result<(), StatsError>),
}
