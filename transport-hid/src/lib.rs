use std::ffi::CStr;
use std::io::Cursor;
use std::sync::Mutex;

use async_trait::async_trait;
use byteorder::{BigEndian, ReadBytesExt};
use hidapi::HidApi;

use ledger_hw::device::{LEDGER_CHANNEL, LEDGER_PACKET_SIZE, LEDGER_USAGE_PAGE, LEDGER_VENDOR_ID};
use ledger_hw_transport::Transport;

#[macro_use]
extern crate nix;
pub mod linux;

const LEDGER_TIMEOUT: i32 = 10_000_000;

#[allow(dead_code)]
pub struct HidTransport {
    device: Mutex<hidapi::HidDevice>,
}

impl HidTransport {
    pub fn new() -> Result<HidTransport, HidTransportError> {
        let api = HidApi::new().map_err(|e| HidTransportError::HidError(e))?;
        let path = get_device_path(&api)?;
        let device = api
            .open_path(&path)
            .map_err(|e| HidTransportError::HidError(e))?;
        Ok(HidTransport {
            device: Mutex::new(device),
        })
    }
}

#[async_trait]
impl Transport for HidTransport {
    type Error = HidTransportError;
    async fn exchange(&self, command: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let mut payload = Vec::with_capacity(command.len() as usize + 2);
        let length = (command.len() as u16).to_be_bytes();
        payload.extend_from_slice(&length);
        payload.extend_from_slice(&command);

        let mut buffer = vec![0u8; LEDGER_PACKET_SIZE];
        let channel_bytes = LEDGER_CHANNEL.to_be_bytes();
        buffer[..2].copy_from_slice(&channel_bytes);
        buffer[2] = 0x05u8;

        let guard = self.device.lock().unwrap();

        for (i, chunk) in payload.chunks(LEDGER_PACKET_SIZE - 5).enumerate() {
            let idx_bytes = (i as u16).to_be_bytes();
            buffer[3..5].copy_from_slice(&idx_bytes);
            buffer[5..5 + chunk.len()].copy_from_slice(chunk);

            let size = guard
                .write(&buffer)
                .map_err(|e| HidTransportError::HidError(e))?;
            if size < buffer.len() {
                return Err(HidTransportError::RequestError);
            }
        }

        let mut answer: Vec<u8> = Vec::with_capacity(256);
        let mut buffer = vec![0u8; LEDGER_PACKET_SIZE];

        let first = guard
            .read_timeout(&mut buffer, LEDGER_TIMEOUT)
            .map_err(|e| HidTransportError::HidError(e))?;
        if first < 7 {
            return Err(HidTransportError::RequestError);
        }
        let mut reader = Cursor::new(&buffer);
        let (_channel, _tag, _idx) = read_channel_tag_idx(&mut reader)?;
        let length = reader
            .read_u16::<BigEndian>()
            .map_err(|_| HidTransportError::Deserialization)? as usize;
        let chunk = &buffer[reader.position() as usize..buffer.len()];
        answer.extend_from_slice(chunk);

        while answer.len() < length {
            let res = guard
                .read_timeout(&mut buffer, LEDGER_TIMEOUT)
                .map_err(|e| HidTransportError::HidError(e))?;
            if res < 5 {
                return Err(HidTransportError::RequestError);
            }

            let mut rdr = Cursor::new(&buffer);
            let (_channel, _tag, _idx) = read_channel_tag_idx(&mut rdr)?;

            let available: usize = buffer.len() - rdr.position() as usize;
            let missing: usize = length - answer.len();
            let end_p = rdr.position() as usize + std::cmp::min(available, missing);

            let new_chunk = &buffer[rdr.position() as usize..end_p];
            answer.extend_from_slice(new_chunk);
        }
        answer.truncate(length);
        Ok(answer)
    }
}

fn read_channel_tag_idx(
    reader: &mut Cursor<&Vec<u8>>,
) -> Result<(u16, u8, u16), HidTransportError> {
    let channel = reader
        .read_u16::<BigEndian>()
        .map_err(|_| HidTransportError::Deserialization)?;
    let tag = reader
        .read_u8()
        .map_err(|_| HidTransportError::Deserialization)?;
    let idx = reader
        .read_u16::<BigEndian>()
        .map_err(|_| HidTransportError::Deserialization)?;
    Ok((channel, tag, idx))
}

#[cfg(target_os = "linux")]
pub fn get_device_path(api: &HidApi) -> Result<&CStr, HidTransportError> {
    for device in api.device_list() {
        if device.vendor_id() == LEDGER_VENDOR_ID {
            let usage = if device.usage_page() != 0 {
                device.usage_page()
            } else {
                linux::get_usage_page(device.path())
                    .map_err(|e| HidTransportError::DeviceUsagePageUnreachable(e))?
            };
            if usage == LEDGER_USAGE_PAGE {
                return Ok(device.path());
            }
        }
    }
    return Err(HidTransportError::DeviceNotFound);
}

#[cfg(not(target_os = "linux"))]
pub fn get_device_path(api: &HidApi) -> Result<&CStr, HidTransportError> {
    for device in api.device_list() {
        if device.vendor_id() == LEDGER_VENDOR_ID && device.usage_page() == LEDGER_USAGE_PAGE {
            return Ok(device.path());
        }
    }
    return Err(HidTransportError::DeviceNotFound);
}

#[derive(Debug)]
pub enum HidTransportError {
    Deserialization,
    RequestError,
    HidError(hidapi::HidError),
    DeviceUsagePageUnreachable(linux::Error),
    DeviceNotFound,
}
