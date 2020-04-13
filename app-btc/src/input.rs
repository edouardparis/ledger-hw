use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::{OutPoint, TxIn};

#[derive(Debug)]
pub struct DeviceSig {
    pub magic: [u8; 4],
    pub sig: [u8; 8],
}

#[derive(Debug)]
pub enum Input {
    Trusted {
        txin: TxIn,
        amount: u64,
        device_sig: DeviceSig,
    },
    Untrusted {
        txin: TxIn,
        amount: u64,
    },
    Segwit {
        txin: TxIn,
        amount: u64,
    },
}

impl Input {
    pub fn new_trusted(
        outpoint: OutPoint,
        script_sig: Script,
        sequence: u32,
        amount: u64,
        device_sig: DeviceSig,
    ) -> Input {
        Input::Trusted {
            txin: TxIn {
                previous_output: outpoint,
                script_sig: script_sig,
                sequence: sequence,
                witness: Vec::new(),
            },
            amount: amount,
            device_sig: device_sig,
        }
    }
    pub fn new_untrusted(txin: TxIn, amount: u64) -> Input {
        Input::Untrusted {
            txin: txin,
            amount: amount,
        }
    }
    pub fn new_segwit(txin: TxIn, amount: u64) -> Input {
        Input::Segwit {
            txin: txin,
            amount: amount,
        }
    }
}
