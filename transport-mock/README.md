# transport-mock

[![ledger-hw-transport-mock on crates.io](https://img.shields.io/crates/v/ledger-hw-transport-mock.svg)](https://crates.io/crates/ledger-hw-transport-mock)
[![ledger-hw-transport-mock on docs.rs](https://docs.rs/ledger-hw-transport-mock/badge.svg)](https://docs.rs/ledger-hw-transport-mock)

A mock implementation of the `ledger_hw_transport::Transport` Trait.

example:

```rust
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
    let (key, address, chaincode) = get_wallet_public_key(&mock, &path, false, AddressFormat::Legacy).await.unwrap();

    assert_eq!(Address::from_str("13KE6TffArLh4fVM6uoQzvsYq5vwetJcVM").unwrap(), address);
    assert_eq!(PublicKey::from_str("0486b865b52b753d0a84d09bc20063fab5d8453ec33c215d4019a5801c9c6438b917770b2782e29a9ecc6edb67cd1f0fbf05ec4c1236884b6d686d6be3b1588abb").unwrap(), key);
    let chaincode_bytes = hex::decode("bce80dd580792cd18af542790e56aa813178dc28644bb5f03dbd44c85f2d2e7a").unwrap();
    assert_eq!(ChainCode::from(&chaincode_bytes[..]), chaincode);
}
    ```
