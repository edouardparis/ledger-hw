use bitcoin::consensus::deserialize;
use bitcoin::consensus::serialize;
use bitcoin::util::bip32;
use bitcoin::Address;
use bitcoin::SigHashType;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use ledger_hw_app_btc::get_trusted_input;
use ledger_hw_app_btc::get_wallet_public_key;
use ledger_hw_app_btc::wallet::compress_key;
use ledger_hw_app_btc::wallet::hash_output_full;
use ledger_hw_app_btc::wallet::start_untrusted_hash_transaction_input;
use ledger_hw_app_btc::wallet::untrusted_hash_sign;
use ledger_hw_app_btc::AddressFormat;
use ledger_hw_transport_hid::HidTransport;
use std::str::FromStr;

#[tokio::main]
async fn main() {
    let transport = HidTransport::new().unwrap();
    let raw_tx =
        hex::decode("02000000000101e74f5fb02fa4d03989b07dbaea0c4a5c8034d848a4e8472fd548eedc6350a3ad0100000017160014d5c680724d84ad7d76eb3829ff3e7ea32198f16affffffff02a0860100000000001976a914a5c2e71801a99165c83a1acb3646d81bdd5ef61288acf71602000000000017a914819e4a71d0d611be47d98ec2eeb248ba92c0df3e8702483045022100be314ac077cebcbaf63701d905d36c1e56be6a6d0ae24e2a8448d5ec4041ebae022072c1ce91a715e1b5114b90d6cedf7283c5abbd7cf959479df746a8c13463ab60012102d3cba7e68c83da2a9fcce874244d56c9152ef4edb662979b14671c00f2f780a100000000").unwrap();
    let previous_tx: Transaction = deserialize(&raw_tx).unwrap();

    let path = bip32::DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
    let (pubkey, _address, _chaincode) =
        get_wallet_public_key(&transport, &path, false, AddressFormat::Legacy)
            .await
            .unwrap();

    let (outpoint, amount, magic_sig) = get_trusted_input(&transport, &previous_tx, 0)
        .await
        .unwrap();

    println!("outpoint: {}", outpoint);
    println!("amount: {}", amount);

    start_untrusted_hash_transaction_input(
        &transport,
        true,
        1,
        0,
        &[(&outpoint, 0, amount, Some(magic_sig))],
        &previous_tx.output[0].script_pubkey,
        false,
    )
    .await
    .unwrap();

    let address = Address::from_str("2N5x2pMGRSsEwEwyBP4Z21mFuc1KXjnjyvF").unwrap();

    let txout = TxOut {
        value: 80000,
        script_pubkey: address.script_pubkey(),
    };

    hash_output_full(&transport, &[&txout]).await.unwrap();

    let sig = untrusted_hash_sign(&transport, &path, 0, SigHashType::All, None)
        .await
        .unwrap();
    println!("{}", hex::encode(&sig));
    println!("size {}", sig.len());

    let compressed_key = compress_key(&pubkey).unwrap().to_bytes();

    let mut script_sig: Vec<u8> = vec![sig.len() as u8];
    script_sig.extend(&sig);
    script_sig.push(compressed_key.len() as u8);
    script_sig.extend(&compressed_key);

    let target_tx: Transaction = Transaction {
        lock_time: 0,
        version: 1,
        input: vec![TxIn {
            sequence: u32::max_value(),
            script_sig: script_sig.into(),
            previous_output: outpoint,
            witness: Vec::new(),
        }],
        output: vec![txout],
    };
    println!("{}", hex::encode(serialize(&target_tx)));
}

// 0100000001fd8e81eadc0ed9c95c58fe1b143ea1073a22454bd10df45b7e151883facf2d42000000006b483045022100ae01410f1ebda1d01c2bb35f96b228ff2ebed34f62689d69f422d34e6d73aebd02205396e627bd3443ab0c5f6e213cb9302cfd9a6518c405fac93004d2d034997ccf01210276a4087f5fdf7b93e26323f9e9542a3946073e6d2f364d3fb2745ba0c34ef622ffffffff01803801000000000017a9148b593d1061685ee9b25d2856ea50f8223f932ba48700000000
// {
//   "txid": "abb4af78436a971ab72b0421df9283432201dca9ff8c51c6c6731fce1297d993",
//   "wtxid": "abb4af78436a971ab72b0421df9283432201dca9ff8c51c6c6731fce1297d993",
//   "size": 190,
//   "weight": 760,
//   "vsize": 190,
//   "version": 1,
//   "locktime": 0,
//   "inputs": [
//     {
//       "prevout": "422dcffa8318157e5bf40dd14b45223a07a13e141bfe585cc9d90edcea818efd:0",
//       "txid": "422dcffa8318157e5bf40dd14b45223a07a13e141bfe585cc9d90edcea818efd",
//       "vout": 0,
//       "script_sig": {
//         "hex": "483045022100ae01410f1ebda1d01c2bb35f96b228ff2ebed34f62689d69f422d34e6d73aebd02205396e627bd3443ab0c5f6e213cb9302cfd9a6518c405fac93004d2d034997ccf01210276a4087f5fdf7b93e26323f9e9542a3946073e6d2f364d3fb2745ba0c34ef622",
//         "asm": "OP_PUSHBYTES_72 3045022100ae01410f1ebda1d01c2bb35f96b228ff2ebed34f62689d69f422d34e6d73aebd02205396e627bd3443ab0c5f6e213cb9302cfd9a6518c405fac93004d2d034997ccf01 OP_PUSHBYTES_33 0276a4087f5fdf7b93e26323f9e9542a3946073e6d2f364d3fb2745ba0c34ef622"
//       },
//       "sequence": 4294967295,
//       "witness": null
//     }
//   ],
//   "outputs": [
//     {
//       "value": 80000,
//       "script_pub_key": {
//         "hex": "a9148b593d1061685ee9b25d2856ea50f8223f932ba487",
//         "asm": "OP_HASH160 OP_PUSHBYTES_20 8b593d1061685ee9b25d2856ea50f8223f932ba4 OP_EQUAL",
//         "type": "p2sh",
//         "address": "3EPpkcLPqQjb3ALdhvw9PpGePf7N2n8Rfb"
//       }
//     }
//   ]
// }%
