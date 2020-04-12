use bitcoin::consensus::encode;
use bitcoin::util::bip32;
use bitcoin::util::key;

use ledger_hw::Status;
use ledger_hw_transport::TransportError;

#[derive(Debug)]
pub enum AppError<T> {
    ConsensusEncode(encode::Error),
    BIP32(bip32::Error),
    KeyError(key::Error),
    Deserialization,
    Unexpected,
    ResponseStatus(Status),
    Transport(TransportError<T>),
}

#[derive(Debug)]
pub enum DevError<T> {
    InvalidSeedLength,
    Deserialization,
    Unexpected,
    ResponseStatus(Status),
    Transport(TransportError<T>),
}
