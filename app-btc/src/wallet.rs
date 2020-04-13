use std::io::Write;
use std::marker::Sync;
use std::str::{from_utf8, FromStr};

use bitcoin::blockdata::transaction::{OutPoint, Transaction};
use bitcoin::consensus::encode::{deserialize, Encodable, Error as EncodeError, VarInt};
use bitcoin::hash_types::Txid;
use bitcoin::util::address::Address;
use bitcoin::util::bip32::{ChainCode, ChildNumber, DerivationPath};
use bitcoin::util::key::PublicKey;

use ledger_hw::device::LEDGER_PACKET_SIZE;
use ledger_hw::Status;
use ledger_hw_transport::Transport;

use crate::constant::{
    BTCHIP_CLA, BTCHIP_INS_GET_TRUSTED_INPUT, BTCHIP_INS_GET_WALLET_PUBLIC_KEY,
    BTCHIP_INS_HASH_INPUT_FINALIZE, BTCHIP_INS_HASH_INPUT_START, BTCHIP_INS_HASH_SIGN,
    BTCHIP_INS_SIGN_MESSAGE, MAX_SCRIPT_BLOCK,
};
use crate::error::AppError;
use crate::input::{DeviceSig, Input};

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
) -> Result<(OutPoint, u64, DeviceSig), AppError<T::Err>> {
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
        let script = output.script_pubkey.as_bytes();
        if script.len() + data.len() <= LEDGER_PACKET_SIZE {
            data.extend(script);
        }
        let (_, status) = transport
            .send(BTCHIP_CLA, BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00, &data)
            .await
            .map_err(|e| AppError::Transport(e))?;
        check_status(status, Status::OK)?;

        if script.len() + data.len() <= LEDGER_PACKET_SIZE {
            continue;
        }

        // exchange chunks of output script_pubkey bytes
        for chunk in script.chunks(MAX_SCRIPT_BLOCK) {
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

    let mut data: [u8; 56] = [0; 56];
    data.copy_from_slice(&res);
    ledger_decode_outpoint(&data).map_err(|e| AppError::ConsensusEncode(e))
}

pub fn ledger_decode_outpoint(data: &[u8; 56]) -> Result<(OutPoint, u64, DeviceSig), EncodeError> {
    let mut magic: [u8; 4] = [0; 4];
    magic.copy_from_slice(&data[0..4]);
    let mut vout: [u8; 4] = [0; 4];
    vout.copy_from_slice(&data[36..40]);
    let txid: Txid = deserialize(&data[4..36])?;
    let mut amt: [u8; 8] = [0; 8];
    amt.copy_from_slice(&data[40..48]);
    let mut sig: [u8; 8] = [0; 8];
    sig.copy_from_slice(&data[48..56]);
    Ok((
        OutPoint::new(txid, u32::from_le_bytes(vout)),
        u64::from_le_bytes(amt),
        DeviceSig {
            magic: magic,
            sig: sig,
        },
    ))
}

pub async fn start_untrusted_hash_transaction_input<T: Transport + Sync>(
    transport: &T,
    new_tx: bool,
    version: u32,
    input_idx: usize,
    inputs: &[Input],
) -> Result<(), AppError<T::Err>> {
    let mut data: Vec<u8> = Vec::new();
    btc_encode(&version, &mut data)?;
    btc_encode(&VarInt(inputs.len() as u64), &mut data)?;
    let mut have_segwit = false;
    for input in inputs {
        if let Input::Segwit { txin: _, amount: _ } = input {
            have_segwit = true;
            break;
        }
    }

    let p2 = if new_tx {
        if have_segwit {
            0x02
        } else {
            0x00
        }
    } else {
        if have_segwit {
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

    for (i, input) in inputs.iter().enumerate() {
        let mut data: Vec<u8> = Vec::new();
        let mut script: &[u8] = &[];
        let mut sequence = [0xFF, 0xFF, 0xFF, 0xFF];

        match input {
            Input::Trusted {
                txin,
                amount,
                device_sig,
            } => {
                data.push(0x01);
                data.push(0x38);
                data.extend(&device_sig.magic);
                btc_encode(&txin.previous_output, &mut data)?;
                data.extend(&(amount.to_le_bytes()));
                data.extend(&device_sig.sig);
                script = txin.script_sig.as_bytes();
                if txin.sequence != 0 {
                    sequence = txin.sequence.to_be_bytes();
                }
            }
            Input::Untrusted { txin, amount: _ } => {
                data.push(0x00);
                btc_encode(&txin.previous_output, &mut data)?;
                script = txin.script_sig.as_bytes();
                if txin.sequence != 0 {
                    sequence = txin.sequence.to_be_bytes();
                }
            }
            Input::Segwit { txin, amount } => {
                data.push(0x02);
                btc_encode(&txin.previous_output, &mut data)?;
                data.extend(&(amount.to_le_bytes()));
                if txin.sequence != 0 {
                    sequence = txin.sequence.to_be_bytes();
                }
            }
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::consensus::encode::deserialize;
    // use bitcoin::hash_types::PubkeyHash;
    // use bitcoin::hashes::Hash;
    // use bitcoin::util::address::Payload;
    use bitcoin::Script;
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
    #[async_test]
    async fn test_get_trusted_input() {
        let raw_tx = hex::decode("01000000014ea60aeac5252c14291d428915bd7ccd1bfc4af009f4d4dc57ae597ed0420b71010000008a47304402201f36a12c240dbf9e566bc04321050b1984cd6eaf6caee8f02bb0bfec08e3354b022012ee2aeadcbbfd1e92959f57c15c1c6debb757b798451b104665aa3010569b49014104090b15bde569386734abf2a2b99f9ca6a50656627e77de663ca7325702769986cf26cc9dd7fdea0af432c8e2becc867c932e1b9dd742f2a108997c2252e2bdebffffffff0281b72e00000000001976a91472a5d75c8d2d0565b656a5232703b167d50d5a2b88aca0860100000000001976a9144533f5fb9b4817f713c48f0bfe96b9f50c476c9b88ac00000000")
            .expect("could not decode raw tx");
        let tx: Transaction = deserialize(&raw_tx).expect("tx non valid");
        let mock = TransportReplayer::new(
            RecordStore::from_str("
                => e042000009000000010100000001
                <= 9000
                => e0428000254ea60aeac5252c14291d428915bd7ccd1bfc4af009f4d4dc57ae597ed0420b71010000008a
                <= 9000
                => e04280003247304402201f36a12c240dbf9e566bc04321050b1984cd6eaf6caee8f02bb0bfec08e3354b022012ee2aeadcbbfd1e92959f
                <= 9000
                => e04280003257c15c1c6debb757b798451b104665aa3010569b49014104090b15bde569386734abf2a2b99f9ca6a50656627e77de663ca7
                <= 9000
                => e04280002a325702769986cf26cc9dd7fdea0af432c8e2becc867c932e1b9dd742f2a108997c2252e2bdebffffffff
                <= 9000
                => e04280000102
                <= 9000
                => e04280002281b72e00000000001976a91472a5d75c8d2d0565b656a5232703b167d50d5a2b88ac
                <= 9000
                => e042800022a0860100000000001976a9144533f5fb9b4817f713c48f0bfe96b9f50c476c9b88ac
                <= 9000
                => e04280000400000000
                <= 32005df4c773da236484dae8f0fdba3d7e0ba1d05070d1a34fc44943e638441262a04f1001000000a086010000000000b890da969aa6f3109000
            ",
            )
            .unwrap(),
        );

        let (outpoint, amount, magic_sig) = get_trusted_input(&mock, tx, 1).await.unwrap();
        assert_eq!(
            OutPoint::from_str(
                "104fa062124438e64349c44fa3d17050d0a10b7e3dbafdf0e8da846423da73c7:1"
            )
            .unwrap(),
            outpoint
        );
        let amt: u64 = 100000;
        assert_eq!(amt, amount);
        assert_eq!("b890da969aa6f310", hex::encode(&magic_sig.sig));
    }
    #[async_test]
    async fn test_start_untrusted_hash_transaction_input() {
        let mock = TransportReplayer::new(
            RecordStore::from_str("
                => e04000000d03800000000000000000000000
                <= 41046666422d00f1b308fc7527198749f06fedb028b979c09f60d0348ef79c985e4138b86996b354774c434488d61c7fb20a83293ef3195d422fde9354e6cf2a74ce223137383731457244716465764c544c57424836577a6a556331454b4744517a434d41612d17bc55b7aa153ae07fba348692c2976e6889b769783d475ba7488fb547709000
                => e0440000050100000001
                <= 9000
                => e04480003b013832005df4c773da236484dae8f0fdba3d7e0ba1d05070d1a34fc44943e638441262a04f1001000000a086010000000000b890da969aa6f31019
                <= 9000
                => e04480001d76a9144533f5fb9b4817f713c48f0bfe96b9f50c476c9b88acffffffff
                <= 9000
                => e04a80002301905f0100000000001976a91472a5d75c8d2d0565b656a5232703b167d50d5a2b88ac
                <= 00009000
                => e04800001303800000000000000000000000000000000001
                <= 3145022100ff492ad0b3a634aa7751761f7e063bf6ef4148cd44ef8930164580d5ba93a17802206fac94b32e296549e2e478ce806b58d61cfacbfed35ac4ceca26ac531f92b20a019000
            ",
            )
            .unwrap(),
        );

        let path = DerivationPath::from_str("m/0'/0/0").unwrap();
        let (_key, _address, _chaincode) =
            get_wallet_public_key(&mock, path, false, AddressFormat::Legacy)
                .await
                .unwrap();
        // let pk = compress_public_key(&key);
        // let mut hash_engine = PubkeyHash::engine();
        // pk.write_into(&mut hash_engine);
        // let script = Payload::PubkeyHash(PubkeyHash::from_engine(hash_engine)).script_pubkey();
        let s = hex::decode("76a9144533f5fb9b4817f713c48f0bfe96b9f50c476c9b88ac").unwrap();
        let script: Script = s.into();

        let trusted_input_exchange = hex::decode("32005df4c773da236484dae8f0fdba3d7e0ba1d05070d1a34fc44943e638441262a04f1001000000a086010000000000b890da969aa6f310").unwrap();
        let mut res: [u8; 56] = [0; 56];
        res.copy_from_slice(&trusted_input_exchange);
        let (outpoint, amount, magic_sig) = ledger_decode_outpoint(&res).unwrap();

        println!(
            "{}",
            hex::encode(vec![
                118, 169, 20, 69, 51, 245, 251, 155, 72, 23, 247, 19, 196, 143, 11, 254, 150, 185,
                245, 12, 71, 108, 155, 136, 172
            ])
        );

        println!(
            "{:?}",
            hex::decode("e04480001d76a9144533f5fb9b4817f713c48f0bfe96b9f50c476c9b88acffffffff")
                .unwrap()
        );

        let input = Input::new_trusted(outpoint, script, 0, amount, magic_sig);
        let inputs: Vec<Input> = vec![input];
        start_untrusted_hash_transaction_input(&mock, true, 1, 0, &inputs)
            .await
            .unwrap();
    }

    // fn compress_public_key(key: &PublicKey) -> PublicKey {
    //     let pk = key.to_bytes();
    //     let mut data: Vec<u8> = Vec::new();
    //     if (pk[64] & 1) != 0 {
    //         data.push(0x03);
    //     } else {
    //         data.push(0x02);
    //     }
    //     data.extend(&pk[1..33]);

    //     let p = PublicKey::from_slice(&data).unwrap();
    //     p
    // }
}
