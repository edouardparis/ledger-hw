use ledger_hw_app_btc::util::get_firmware_version;
use ledger_hw_transport_hid::HidTransport;

#[tokio::main]
async fn main() {
    let transport = HidTransport::new().unwrap();
    let (_, _, v) = get_firmware_version(&transport).await.unwrap();
    println!("firmware version: {}", v);
}
