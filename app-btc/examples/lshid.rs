use hidapi::HidApi;
use ledger_hw_transport_hid::get_device_path;

fn main() {
    println!("Printing all available hid devices:");

    match HidApi::new() {
        Ok(api) => {
            let path = get_device_path(&api).unwrap();
            println!("path: {}", path.to_str().unwrap())
        }
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }
}
