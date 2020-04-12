use std::io::Write;
use std::marker::Sync;
use std::str::{from_utf8, FromStr};

use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::encode::{Encodable, VarInt};
use bitcoin::util::address::Address;
use bitcoin::util::bip32::{ChainCode, ChildNumber, DerivationPath};
use bitcoin::util::key::PublicKey;

use ledger_hw::Status;
use ledger_hw_transport::Transport;

use crate::constant::{
    BTCHIP_CLA, BTCHIP_INS_GET_TRUSTED_INPUT, BTCHIP_INS_GET_WALLET_PUBLIC_KEY,
    BTCHIP_INS_HASH_INPUT_FINALIZE, BTCHIP_INS_HASH_INPUT_START, BTCHIP_INS_HASH_SIGN,
    BTCHIP_INS_SIGN_MESSAGE, MAX_SCRIPT_BLOCK,
};
use crate::error::AppError;

fn btc_encode<T, W: Write, E: Encodable>(e: &E, w: W) -> Result<usize, AppError<T>> {
    e.consensus_encode(w)
        .map_err(|e| AppError::ConsensusEncode(e))
}

fn path_to_be_bytes(path: DerivationPath) -> Vec<u8> {
    let child_numbers: Vec<ChildNumber> = path.into();
    let p: Vec<u32> = child_numbers.iter().map(|&x| u32::from(x)).collect();
    let mut data: Vec<u8> = vec![child_numbers.len() as u8];
    for child_number in p {
        data.extend(&child_number.to_be_bytes());
    }
    data
}

fn check_status<T>(actual: Status, expected: Status) -> Result<(), AppError<T>> {
    if actual != expected {
        return Err(AppError::ResponseStatus(actual));
    }
    Ok(())
}

#[derive(Debug)]
pub enum AddressFormat {
    Legacy,
    P2sh,
    Bech32,
}

// path a BIP 32 path
// verify (boolean) will ask user to confirm the address on the device
// format ("legacy" | "p2sh" | "bech32") to use different bitcoin address formatter
// returns (public_key, bitcoin_address, chaincode)
pub async fn get_wallet_public_key<T: Transport + Sync>(
    transport: &T,
    path: DerivationPath,
    verify: bool,
    format: AddressFormat,
) -> Result<(PublicKey, Address, ChainCode), AppError<T::Err>> {
    let p1: u8 = if verify { 1 } else { 0 };
    let p2: u8 = match format {
        AddressFormat::Legacy => 0,
        AddressFormat::P2sh => 1,
        AddressFormat::Bech32 => 2,
    };
    let data = path_to_be_bytes(path);

    let (res, status) = transport
        .send(BTCHIP_CLA, BTCHIP_INS_GET_WALLET_PUBLIC_KEY, p1, p2, &data)
        .await
        .map_err(|e| AppError::Transport(e))?;
    check_status(status, Status::OK)?;

    if let Some((&pk_length, pk_bytes)) = res.split_first() {
        let mut pk_bytes = pk_bytes.to_vec();
        if let Some((&address_length, address_bytes)) =
            pk_bytes.split_off(pk_length as usize).split_first()
        {
            let pk = PublicKey::from_slice(&pk_bytes).map_err(|_| AppError::Deserialization)?;

            let mut address_bytes = address_bytes.to_vec();
            let chaincode_bytes = address_bytes.split_off(address_length as usize);
            let chaincode = ChainCode::from(&chaincode_bytes[..]);

            let address_str = from_utf8(&address_bytes).map_err(|_| AppError::Deserialization)?;
            let address = Address::from_str(address_str).map_err(|_| AppError::Deserialization)?;

            return Ok((pk, address, chaincode));
        }
    }

    Err(AppError::Unexpected)
}

pub async fn get_trusted_input<T: Transport + Sync>(
    transport: &T,
    transaction: Transaction,
    index: usize,
) -> Result<Vec<u8>, AppError<T::Err>> {
    // First Exchange:
    // - index    (4 bytes)
    // - version  (consensus)
    // - nb input (consensus)
    let mut data: Vec<u8> = (index as u32).to_be_bytes().to_vec();
    btc_encode(&transaction.version, &mut data)?;
    btc_encode(&VarInt(transaction.input.len() as u64), &mut data)?;

    let (_, status) = transport
        .send(BTCHIP_CLA, BTCHIP_INS_GET_TRUSTED_INPUT, 0x00, 0x00, &data)
        .await
        .map_err(|e| AppError::Transport(e))?;
    check_status(status, Status::OK)?;

    // Exchange inputs
    for input in &transaction.input {
        // Fist exchange prevout and script length
        let mut data: Vec<u8> = Vec::new();
        btc_encode(&input.previous_output, &mut data)?;
        btc_encode(&VarInt(input.script_sig.len() as u64), &mut data)?;

        let (_, status) = transport
            .send(BTCHIP_CLA, BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00, &data)
            .await
            .map_err(|e| AppError::Transport(e))?;
        check_status(status, Status::OK)?;

        // exchange chunks of input script_sig bytes
        for chunk in input.script_sig.as_bytes().chunks(MAX_SCRIPT_BLOCK) {
            let mut data = chunk.to_vec();
            if chunk.len() < MAX_SCRIPT_BLOCK {
                btc_encode(&input.sequence, &mut data)?;
            }
            let (_, status) = transport
                .send(BTCHIP_CLA, BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00, &data)
                .await
                .map_err(|e| AppError::Transport(e))?;
            check_status(status, Status::OK)?;
        }
    }

    // Exchange outputs
    let mut data: Vec<u8> = Vec::new();
    btc_encode(&VarInt(transaction.output.len() as u64), &mut data)?;
    let (_, status) = transport
        .send(BTCHIP_CLA, BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00, &data)
        .await
        .map_err(|e| AppError::Transport(e))?;
    check_status(status, Status::OK)?;

    for output in &transaction.output {
        let mut data: Vec<u8> = Vec::new();
        btc_encode(&output.value, &mut data)?;
        btc_encode(&VarInt(output.script_pubkey.len() as u64), &mut data)?;
        let (_, status) = transport
            .send(BTCHIP_CLA, BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00, &data)
            .await
            .map_err(|e| AppError::Transport(e))?;
        check_status(status, Status::OK)?;

        // exchange chunks of output script_pubkey bytes
        for chunk in output.script_pubkey.as_bytes().chunks(MAX_SCRIPT_BLOCK) {
            let (_, status) = transport
                .send(BTCHIP_CLA, BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00, &chunk)
                .await
                .map_err(|e| AppError::Transport(e))?;
            check_status(status, Status::OK)?;
        }
    }

    let mut data: Vec<u8> = Vec::new();
    btc_encode(&transaction.lock_time, &mut data)?;
    let (res, status) = transport
        .send(BTCHIP_CLA, BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00, &data)
        .await
        .map_err(|e| AppError::Transport(e))?;
    check_status(status, Status::OK)?;
    Ok(res)
}

pub enum Input {
    Trusted(Vec<u8>),
    Untrusted(Vec<u8>),
}

impl Input {
    pub fn as_slice(&self) -> &[u8] {
        return match self {
            Input::Trusted(inp) => inp,
            Input::Untrusted(inp) => inp,
        };
    }
}

pub async fn start_untrusted_hash_transaction_input<T: Transport + Sync>(
    transport: &T,
    new_tx: bool,
    version: u32,
    input_idx: usize,
    inputs: &[Input],
    redeem_script: Script,
    bip143: bool,
) -> Result<(), AppError<T::Err>> {
    let mut data: Vec<u8> = Vec::new();
    btc_encode(&version, &mut data)?;
    btc_encode(&VarInt(inputs.len() as u64), &mut data)?;

    let p2 = if new_tx {
        if bip143 {
            0x02
        } else {
            0x00
        }
    } else {
        if bip143 {
            0x10
        } else {
            0x80
        }
    };
    let (_, status) = transport
        .send(BTCHIP_CLA, BTCHIP_INS_HASH_INPUT_START, 0x00, p2, &data)
        .await
        .map_err(|e| AppError::Transport(e))?;
    check_status(status, Status::OK)?;

    let script = redeem_script.as_bytes();
    let sequence: Vec<u8> = vec![0xFF, 0xFF, 0xFF, 0xFF];

    for (i, input) in inputs.iter().enumerate() {
        let mut data: Vec<u8> = Vec::new();
        if bip143 {
            data.push(0x02);
        } else {
            match input {
                Input::Trusted(_) => {
                    data.push(0x01);
                }
                Input::Untrusted(_) => data.push(0x00),
            }
        }
        match input {
            Input::Trusted(tx) => {
                data.push(tx.len() as u8);
                data.extend(tx)
            }
            Input::Untrusted(tx) => data.extend(tx),
        }

        if i == input_idx {
            btc_encode(&VarInt(script.len() as u64), &mut data)?;
        } else {
            data.push(0x00);
            data.extend(&sequence);
        }
        let (_, status) = transport
            .send(BTCHIP_CLA, BTCHIP_INS_HASH_INPUT_START, 0x80, 0x00, &data)
            .await
            .map_err(|e| AppError::Transport(e))?;
        check_status(status, Status::OK)?;

        if i != input_idx {
            continue;
        }

        let mut offset: usize = 0;
        for chunk in script.chunks(MAX_SCRIPT_BLOCK) {
            let mut data = chunk.to_vec();
            offset += chunk.len();
            if offset == script.len() {
                data.extend(&sequence);
            }

            let (_, status) = transport
                .send(BTCHIP_CLA, BTCHIP_INS_HASH_INPUT_START, 0x80, 0x00, &data)
                .await
                .map_err(|e| AppError::Transport(e))?;
            check_status(status, Status::OK)?;
        }
    }
    Ok(())
}

pub async fn finalize_input<T: Transport + Sync>(
    transport: &T,
    path: DerivationPath,
    address: Address,
    amount: u64,
    fee: u64,
) -> Result<Vec<u8>, AppError<T::Err>> {
    let a = address.to_string();
    let addr = a.as_bytes();
    let mut data: Vec<u8> = vec![addr.len() as u8];
    data.extend(addr);
    data.extend(&(amount.to_be_bytes()));
    data.extend(&(fee.to_be_bytes()));
    let p = path_to_be_bytes(path);
    data.extend(&p);
    let (_, status) = transport
        .send(
            BTCHIP_CLA,
            BTCHIP_INS_HASH_INPUT_FINALIZE,
            0x80,
            0x00,
            &data,
        )
        .await
        .map_err(|e| AppError::Transport(e))?;
    check_status(status, Status::OK)?;
    Err(AppError::Unexpected)
}

// signTransaction
pub async fn untrusted_hash_sign<T: Transport + Sync>(
    transport: &T,
    path: DerivationPath,
    lock_time: u32,
    sighash_type: u8,
    pin: Option<String>,
) -> Result<Vec<u8>, AppError<T::Err>> {
    let mut data = path_to_be_bytes(path);
    if let Some(p) = pin {
        let pin_bytes = p.into_bytes();
        data.push(pin_bytes.len() as u8);
        data.extend(pin_bytes);
    }
    data.extend(&(lock_time.to_be_bytes()));
    data.push(sighash_type);
    let (mut res, status) = transport
        .send(BTCHIP_CLA, BTCHIP_INS_HASH_SIGN, 0x00, 0x00, &data)
        .await
        .map_err(|e| AppError::Transport(e))?;
    check_status(status, Status::OK)?;
    if res.len() > 0 {
        res[0] = 0x30;
    }
    Ok(res)
}

pub async fn sign_message<T: Transport + Sync>(
    transport: &T,
    path: DerivationPath,
    message: &[u8],
) -> Result<(u8, Vec<u8>, Vec<u8>), AppError<T::Err>> {
    let mut data: Vec<u8> = path_to_be_bytes(path);
    data.extend(&(message.len() as u16).to_be_bytes());
    data.extend(message);

    for (i, chunk) in data.chunks(MAX_SCRIPT_BLOCK).enumerate() {
        let p2: u8 = if i != 0 { 0x80 } else { 0x01 };
        let (_, status) = transport
            .send(BTCHIP_CLA, BTCHIP_INS_SIGN_MESSAGE, 0x00, p2, &chunk)
            .await
            .map_err(|e| AppError::Transport(e))?;
        check_status(status, Status::OK)?;
    }

    return sign_message_sign(transport).await;
}

pub async fn sign_message_sign<T: Transport + Sync>(
    transport: &T,
) -> Result<(u8, Vec<u8>, Vec<u8>), AppError<T::Err>> {
    let end: Vec<u8> = vec![0x00];
    let (res, status) = transport
        .send(BTCHIP_CLA, BTCHIP_INS_SIGN_MESSAGE, 0x80, 0x00, &end)
        .await
        .map_err(|e| AppError::Transport(e))?;
    check_status(status, Status::OK)?;

    if res.len() < 4 {
        return Err(AppError::Unexpected);
    }

    let v = res[0] - 0x30;
    let mut r = &res[4..4 + res[3] as usize];
    if r[0] == 0x00 {
        r = &r[1..];
    }
    let offset = 4 + res[3] as usize + 2;
    let mut s = &res[offset..offset + res[offset - 1] as usize];
    if s[0] == 0x00 {
        s = &s[1..];
    }
    Ok((v, r.to_vec(), s.to_vec()))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use futures_await_test::async_test;

    use ledger_hw_transport_mock::{RecordStore, TransportReplayer};

    use super::*;
    #[async_test]
    async fn test_get_wallet_public_key() {
        let mock = TransportReplayer::new(
            RecordStore::from_str(
                "=> e040000011048000002c800000008000000000000000
                <= 410486b865b52b753d0a84d09bc20063fab5d8453ec33c215d4019a5801c9c6438b917770b2782e29a9ecc6edb67cd1f0fbf05ec4c1236884b6d686d6be3b1588abb2231334b453654666641724c683466564d36756f517a7673597135767765744a63564dbce80dd580792cd18af542790e56aa813178dc28644bb5f03dbd44c85f2d2e7a9000
                ",
                ).unwrap()
        );

        let path = DerivationPath::from_str("m/44'/0'/0'/0").unwrap();
        let (key, address, chaincode) =
            get_wallet_public_key(&mock, path, false, AddressFormat::Legacy)
                .await
                .unwrap();

        assert_eq!(
            Address::from_str("13KE6TffArLh4fVM6uoQzvsYq5vwetJcVM").unwrap(),
            address
        );
        assert_eq!(
            PublicKey::from_str("0486b865b52b753d0a84d09bc20063fab5d8453ec33c215d4019a5801c9c6438b917770b2782e29a9ecc6edb67cd1f0fbf05ec4c1236884b6d686d6be3b1588abb").unwrap(),
            key
        );
        let chaincode_bytes =
            hex::decode("bce80dd580792cd18af542790e56aa813178dc28644bb5f03dbd44c85f2d2e7a")
                .unwrap();
        assert_eq!(ChainCode::from(&chaincode_bytes[..]), chaincode);
    }

    #[async_test]
    async fn test_sign_message() {
        let mock = TransportReplayer::new(RecordStore::from_str("
            => e04e00011d058000002c800000008000000000000000000000000006666f6f626172
            <= 00009000
            => e04e80000100
            <= 314402205eac720be544d3959a760d9bfd6a0e7c86d128fd1030038f06d85822608804e20220385d83273c9d03c469596292fb354b07d193034f83c2633a4c1f057838e12a5b9000
            ").unwrap());

        let path = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
        let (v, r, s) = sign_message(&mock, path, "foobar".as_bytes())
            .await
            .unwrap();
        assert_eq!(1 as u8, v);
        assert_eq!(
            hex::decode("5eac720be544d3959a760d9bfd6a0e7c86d128fd1030038f06d85822608804e2")
                .unwrap(),
            r
        );
        assert_eq!(
            hex::decode("385d83273c9d03c469596292fb354b07d193034f83c2633a4c1f057838e12a5b")
                .unwrap(),
            s
        );
    }
}
