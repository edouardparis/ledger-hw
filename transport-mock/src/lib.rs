use async_trait::async_trait;
use hex::FromHex;
use regex::Regex;

use ledger_hw_transport::Transport;

pub struct RecordStore {
    pub queue: Vec<(Vec<u8>, Vec<u8>)>,
}

impl RecordStore {
    pub fn new() -> RecordStore {
        RecordStore { queue: Vec::new() }
    }
    pub fn from_str(s: &str) -> Result<RecordStore, MockError> {
        let cmd_reg: Regex = Regex::new(r"^=>([0-9a-fA-F]+)$").unwrap();
        let out_reg: Regex = Regex::new(r"^<=([0-9a-fA-F]+)$").unwrap();
        let mut store = RecordStore::new();
        let mut c: Vec<u8> = Vec::new();
        for l in s.split('\n') {
            let line = l.replace(" ", "");
            if let Some(cmd) = cmd_reg.find(&line) {
                c = Vec::from_hex(cmd.as_str().replace("=>", ""))
                    .map_err(|_| MockError::ParseExchangeError)?;
            }
            if let Some(out) = out_reg.find(&line) {
                let o = Vec::from_hex(out.as_str().replace("<=", ""))
                    .map_err(|_| MockError::ParseExchangeError)?;
                store.queue.push((c.clone(), o));
            }
        }

        Ok(store)
    }
}

pub struct TransportReplayer {
    store: RecordStore,
}

impl TransportReplayer {
    pub fn new(store: RecordStore) -> TransportReplayer {
        TransportReplayer { store: store }
    }
}

#[async_trait]
impl Transport for TransportReplayer {
    type Err = MockError;
    async fn exchange(&self, command: &[u8]) -> Result<Vec<u8>, Self::Err> {
        for exchange in &self.store.queue {
            if command == exchange.0.as_slice() {
                return Ok(exchange.1.clone());
            }
        }
        Err(MockError::ExchangeNotFound)
    }
}

#[derive(Debug)]
pub enum MockError {
    ParseExchangeError,
    ExchangeNotFound,
}
