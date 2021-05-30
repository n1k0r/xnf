use crate::compiler;

use serde::{Deserialize, Serialize};

use std::{collections::HashMap, sync::mpsc};

pub type StatsValues = HashMap<String, u64>;

pub struct Stats {
    sender: mpsc::Sender<StatsRequest>,
    receiver: mpsc::Receiver<StatsResponse>,
}

struct StatsThread {
    sender: mpsc::Sender<StatsResponse>,
    receiver: mpsc::Receiver<StatsRequest>,
    values: StatsValues,
    prev: StatsValues,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum StatsError {
    InternalError,
}

enum StatsRequest {
    GetValues,
    ResetValues,
    RegisterValue(String, u64, u32),
}

enum StatsResponse {
    Values(StatsValues),
    Reset,
    Register,
    WrongArgument,
}

impl Stats {
    pub fn new() -> Self {
        let (req_tx, req_rx) = mpsc::channel();
        let (resp_tx, resp_rx) = mpsc::channel();

        std::thread::spawn(|| {
            let mut stats = StatsThread::new(req_rx, resp_tx);
            stats.work();
        });

        Stats {
            sender: req_tx,
            receiver: resp_rx,
        }
    }

    pub fn values(&mut self) -> Result<StatsValues, StatsError> {
        if let Err(_) = self.sender.send(StatsRequest::GetValues) {
            return Err(StatsError::InternalError);
        }

        let resp = match self.receiver.recv() {
            Ok(StatsResponse::Values(values)) => values,
            _ => return Err(StatsError::InternalError),
        };

        Ok(resp)
    }

    pub fn reset(&mut self) -> Result<(), StatsError> {
        if let Err(_) = self.sender.send(StatsRequest::ResetValues) {
            return Err(StatsError::InternalError);
        }

        let resp = match self.receiver.recv() {
            Ok(StatsResponse::Reset) => (),
            _ => return Err(StatsError::InternalError),
        };

        Ok(resp)
    }

    pub fn register_value(&mut self, iface: &str, value: u64, action: u32) -> Result<(), StatsError> {
        if let Err(_) = self.sender.send(StatsRequest::RegisterValue(iface.to_string(), value, action)) {
            return Err(StatsError::InternalError);
        }

        let resp = match self.receiver.recv() {
            Ok(StatsResponse::Register) => (),
            _ => return Err(StatsError::InternalError),
        };

        Ok(resp)
    }
}

impl StatsThread {
    pub fn new(rx: mpsc::Receiver<StatsRequest>, tx: mpsc::Sender<StatsResponse>) -> Self {
        let mut stats = Self {
            receiver: rx,
            sender: tx,
            values: HashMap::new(),
            prev: HashMap::new(),
        };

        stats.values.insert("pass".to_string(), 0);
        stats.values.insert("drop".to_string(), 0);

        stats
    }

    pub fn work(&mut self) {
        while let Ok(req) = self.receiver.recv() {
            let result = match req {
                StatsRequest::GetValues => self.values(),
                StatsRequest::ResetValues => self.reset(),
                StatsRequest::RegisterValue(iface, value, action) => self.register(iface, value, action),
            };
            self.sender.send(result).unwrap();
        }
    }

    fn values(&mut self) -> StatsResponse {
        StatsResponse::Values(self.values.clone())
    }

    fn reset(&mut self) -> StatsResponse {
        for (_, value) in self.values.iter_mut() {
            *value = 0;
        }

        StatsResponse::Reset
    }

    fn register(&mut self, iface: String, new_value: u64, action: u32) -> StatsResponse {
        let action_name = match action {
            compiler::STATS_KEY_PASS => "pass",
            compiler::STATS_KEY_DROP => "drop",
            _ => return StatsResponse::WrongArgument,
        };

        let key = format!("{}_{}", action_name, iface);
        if !self.values.contains_key(&key) {
            self.values.insert(key.clone(), 0);
        }

        let increment = match self.value_diff(&key, new_value) {
            Some(inc) => inc,
            None => new_value,
        };

        let value = self.values.get_mut(&key).unwrap();
        *value += increment;

        let action_value = self.values.get_mut(action_name).unwrap();
        *action_value += increment;

        StatsResponse::Register
    }

    fn value_diff(&mut self, key: &str, new_value: u64) -> Option<u64> {
        if !self.prev.contains_key(key) {
            self.prev.insert(key.to_string(), 0);
        }

        let value = self.prev.get_mut(key).unwrap();
        if *value > new_value {
            return None;
        }

        let result = new_value - *value;

        *value = new_value;
        return Some(result);
    }
}
