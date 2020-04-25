use bitcoin::blockdata::transaction::OutPoint;
use bitcoin::consensus::deserialize;
use bitcoin::consensus::serialize;
use bitcoin::util::bip32;
use bitcoin::Address;
use bitcoin::Script;
use bitcoin::SigHashType;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use ledger_hw_app_btc::get_wallet_public_key;
use ledger_hw_app_btc::wallet::compress_key;
use ledger_hw_app_btc::wallet::hash_output_full;
use ledger_hw_app_btc::wallet::provide_output_full_change_path;
use ledger_hw_app_btc::wallet::start_untrusted_hash_transaction_input;
use ledger_hw_app_btc::wallet::untrusted_hash_sign;
use ledger_hw_app_btc::AddressFormat;
use ledger_hw_transport_hid::HidTransport;
use std::str::FromStr;

#[tokio::main]
async fn main() {
    let transport = HidTransport::new().unwrap();
    let raw_tx =
        hex::decode("020000000001047bcf930af3e9418f55a76492b0e0dc37dac52aa1869aa689b913e73281f05f58010000001716001445812562f7679124ac4bf094ff00c87746a6af5affffffff4b48350e98cdbb8dc72ff4bc16a7b8941dd1f274ffbe34b8b6132a4a1db809b5000000001716001415fbad3c95f5cdc45350684d1861856feac474f2fffffffffd8e81eadc0ed9c95c58fe1b143ea1073a22454bd10df45b7e151883facf2d42010000001716001494a2dfdf4205bdaaf382955ff40a71581d9bdb97ffffffff93d99712ce1f73c6c6518cffa9dc0122438392df21042bb71a976a4378afb4ab000000001716001415fbad3c95f5cdc45350684d1861856feac474f2ffffffff0240420f000000000016001445562222d974c4940f76a041e19639a8e88b76b2af8b44000000000017a91452d81b97a7164ca9d95348c8d60c8f334d8dc46987024830450221009c53db135b62abf589dad77135bb7f24010093badd26dba38d89bb254633e970022013b10e66719b6fae289e69f362e3031af41a72e8c4f8f484370523108c39c676012102b1f7fcfb59c972ddef066c84c2e7f7124ca941b1df3899fa3f70946e6558f9fd02483045022100d3525233da16f7a3d2d62d7e18966e101eafbde70dac5d702931b305fa691dc702205f098d71ed8a514d3b454f0ff0eabfd0ef06f5cd513313c43ddeedad0462a9f7012103ff6cdb7c1afb74e2eba79dd775722b24fd30bb514ca2a9382df3954e946744990247304402207dcb2701ba420a606e6d72a217f336b0ad6e3bdd53fcc9c35f702c11039d398b0220383feb3ec30ce4c83f44720898e721be964fae4d688d5a6dad7584fb0fab4a72012103d5603fccb7dc397e9be2c4c3f0683d4dd52c80ace5b1123bbc1d9fb4baa5c2190247304402201866ac9b596117f5a0c8cfbf81fcc8fa38e776b795332c2e45fffd55a160bcbe0220466c07b73c31314598ec97ebbb2eb48c5ac0a6edbea64b3d59daa700f3317170012103ff6cdb7c1afb74e2eba79dd775722b24fd30bb514ca2a9382df3954e9467449900000000").unwrap();
    let previous_tx: Transaction = deserialize(&raw_tx).unwrap();

    let path = bip32::DerivationPath::from_str("m/84'/0'/0'/0/0").unwrap();
    let (pubkey, _address, _chaincode) =
        get_wallet_public_key(&transport, &path, false, AddressFormat::Bech32)
            .await
            .unwrap();

    let outpoint = OutPoint::new(previous_tx.txid(), 0);
    let amount = previous_tx.output[0].value;

    start_untrusted_hash_transaction_input(
        &transport,
        true,
        1,
        0,
        &[(&outpoint, 0, amount, None)],
        // &previous_tx.output[0].script_pubkey,
        &Script::new(),
        true,
    )
    .await
    .unwrap();

    let dest_address = Address::from_str("2ND26wSA3zauZHNXWT1TyNWqjDZvpMzr74Q").unwrap();
    let txout1 = TxOut {
        value: 800000,
        script_pubkey: dest_address.script_pubkey(),
    };
    let change_address_path = bip32::DerivationPath::from_str("m/84'/0'/0'/1/0").unwrap();
    let (_, change_address, _) = get_wallet_public_key(
        &transport,
        &change_address_path,
        false,
        AddressFormat::Bech32,
    )
    .await
    .unwrap();
    let txout2 = TxOut {
        value: 195000,
        script_pubkey: change_address.script_pubkey(),
    };

    provide_output_full_change_path(&transport, &change_address_path)
        .await
        .unwrap();

    hash_output_full(&transport, &[&txout1, &txout2])
        .await
        .unwrap();

    start_untrusted_hash_transaction_input(
        &transport,
        false,
        1,
        0,
        &[(&outpoint, 0, amount, None)],
        &previous_tx.output[0].script_pubkey,
        true,
    )
    .await
    .unwrap();

    let sig = untrusted_hash_sign(&transport, &path, 0, SigHashType::All, None)
        .await
        .unwrap();
    println!("{}", hex::encode(&sig));
    println!("size {}", sig.len());

    let compressed_key = compress_key(&pubkey).unwrap().to_bytes();

    let mut witness: Vec<Vec<u8>> = Vec::new();
    witness.push(sig);
    witness.push(compressed_key);

    let target_tx: Transaction = Transaction {
        lock_time: 0,
        version: 1,
        input: vec![TxIn {
            sequence: u32::max_value(),
            script_sig: Script::new(),
            previous_output: outpoint,
            witness: witness,
        }],
        output: vec![txout1, txout2],
    };
    println!("{}", hex::encode(serialize(&target_tx)));
}
