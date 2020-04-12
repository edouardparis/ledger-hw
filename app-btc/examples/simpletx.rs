use std::str::FromStr;

use bitcoin::util::bip32;

use ledger_hw_transport_hid::HidTransport;

use ledger_hw_app_btc::constant::{FEATURE_RFC6979, OPERATION_MODE_WALLET};
use ledger_hw_app_btc::get_wallet_public_key;
use ledger_hw_app_btc::setup::{setup, verify_pin};
use ledger_hw_app_btc::AddressFormat;

// const SEED: &'static str = "1762F9A3007DBC825D0DD9958B04880284E88F10C57CF569BB3DADF7B1027F2D";
// const UTX: &'static str = "01000000014ea60aeac5252c14291d428915bd7ccd1bfc4af009f4d4dc57ae597ed0420b71010000008a47304402201f36a12c240dbf9e566bc04321050b1984cd6eaf6caee8f02bb0bfec08e3354b022012ee2aeadcbbfd1e92959f57c15c1c6debb757b798451b104665aa3010569b49014104090b15bde569386734abf2a2b99f9ca6a50656627e77de663ca7325702769986cf26cc9dd7fdea0af432c8e2becc867c932e1b9dd742f2a108997c2252e2bdebffffffff0281b72e00000000001976a91472a5d75c8d2d0565b656a5232703b167d50d5a2b88aca0860100000000001976a9144533f5fb9b4817f713c48f0bfe96b9f50c476c9b88ac00000000";
// const SIGNATURE: &'static str = "3045022100ea6df031b47629590daf5598b6f0680ad0132d8953b401577f01e8cc46393fe602202201b7a19d706a0213dcfeb7033719b92c6fd58a2d1d53411de71c4d8353154b01";
// const TRANSACTION: &'static str = "0100000001c773da236484dae8f0fdba3d7e0ba1d05070d1a34fc44943e638441262a04f10010000006b483045022100ea6df031b47629590daf5598b6f0680ad0132d8953b401577f01e8cc46393fe602202201b7a19d706a0213dcfeb7033719b92c6fd58a2d1d53411de71c4d8353154b01210348bb1fade0adde1bf202726e6db5eacd2063fce7ecf8bbfd17377f09218d5814ffffffff01905f0100000000001976a91472a5d75c8d2d0565b656a5232703b167d50d5a2b88ac00000000";
// const UTXO_INDEX: usize = 1;
// const ADDRESS: &'static str = "1BTChipvU14XH6JdRiK9CaenpJ2kJR9Rn";
// const AMOUNT: u64 = 90000;
// const FEES: u64 = 10000;

#[tokio::main]
async fn main() {
    // let seed = hex::decode(SEED).unwrap();
    // let utx = hex::decode(UTX).unwrap();
    let transport = HidTransport::new().unwrap();

    // setup(
    //     &transport,
    //     OPERATION_MODE_WALLET,
    //     FEATURE_RFC6979,
    //     0x00,
    //     0x05,
    //     "1234",
    //     None,
    //     &seed,
    //     None,
    // )
    // .await
    // .unwrap();

    verify_pin(&transport, "1234").await.unwrap();

    let path = bip32::DerivationPath::from_str("m/0'/0/0").unwrap();
    let (pk, address, chaincode) =
        get_wallet_public_key(&transport, path, true, AddressFormat::Legacy)
            .await
            .unwrap();
    println!("pk: {}", pk);
    println!("address: {}", address);
    println!("chaincode: {}", chaincode);
}
