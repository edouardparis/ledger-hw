# Helpers for the Ledger Bitcoin application [WIP]

A transport implementing the `ledger_hw` trait is needed in most of the
helpers.

example:

```rust
use bitcoin::util::bip32;
use ledger_hw_app_btc::get_wallet_public_key;
use ledger_hw_app_btc::AddressFormat;
use ledger_hw_transport_hid::HidTransport;
use std::str::FromStr;

#[tokio::main]
async fn main() {
    let transport = HidTransport::new().unwrap();
    let path = bip32::DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
    let (pk, address, chaincode) = get_wallet_public_key(&transport, &path, true, AddressFormat::Legacy)
            .await
            .unwrap();
    println!("pk: {}", pk);
    println!("address: {}", address);
    println!("chaincode: {}", chaincode);
}
```

TODO:

## mod wallet

- [x] get_wallet_public_key
- [x] get_trusted_input
- [x] sign_message
    - [ ] sign_message_prepare
        - [ ] sign_message_prepare_v1
        - [ ] sign_message_prepare_v2
    - [x] sign_message_sign
- [x] start_untrusted_hash_transaction_input [need test]
- [ ] finalize_input [need test]
- [x] untrusted_hash_sign [need test]

## mod util

- [x] get_firmware_version
