//! https://github.com/edouardparis/ledger-hw
//!
//! Example:
//!
//! ```
//! use std::str::FromStr;
//! use bitcoin::util::bip32::DerivationPath;
//! use ledger_hw_transport_hid::HidTransport;
//!
//! use ledger_hw_app_btc::{AddressFormat, get_wallet_public_key};
//!
//! #[tokio::main]
//! async fn main() {
//!     let transport = HidTransport::new().unwrap();
//!     let path = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
//!     let format = AddressFormat::Legacy;
//!     let (pk, address, chaincode) = get_wallet_public_key(&transport, &path, true, format)
//!         .await
//!         .unwrap();
//!     println!("pk: {}", pk);
//!     println!("address: {}", address);
//!     println!("chaincode: {}", chaincode);
//! }
//! ```

pub mod constant;
pub mod error;
pub mod util;
pub mod wallet;

pub use util::get_firmware_version;
pub use wallet::get_trusted_input;
pub use wallet::get_wallet_public_key;
pub use wallet::hash_output_full;
pub use wallet::sign_message;
pub use wallet::start_untrusted_hash_transaction_input;
pub use wallet::untrusted_hash_sign;
pub use wallet::AddressFormat;
