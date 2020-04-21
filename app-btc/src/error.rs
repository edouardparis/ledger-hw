use bitcoin::consensus::encode;

use ledger_hw::Status;
use ledger_hw_transport::TransportError;

#[derive(Debug)]
pub enum AppError<T> {
    ConsensusEncode(encode::Error),
    Deserialization(String),
    Unexpected,
    ResponseStatus(Status),
    Transport(TransportError<T>),
}
