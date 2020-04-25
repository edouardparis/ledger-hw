use bitcoin::util::bip32;
use ledger_hw_app_btc::get_wallet_public_key;
use ledger_hw_app_btc::AddressFormat;
use ledger_hw_transport_hid::HidTransport;
use std::str::FromStr;

#[tokio::main]
async fn main() {
    let transport = HidTransport::new().unwrap();
    let path = bip32::DerivationPath::from_str("m/84'/0'/0'/0/0").unwrap();
    let (pk, address, chaincode) =
        get_wallet_public_key(&transport, &path, true, AddressFormat::Bech32)
            .await
            .unwrap();
    println!("pk: {}", pk);
    println!("address: {}", address);
    println!("chaincode: {}", chaincode);
}
