use ledger_hw::Status;
use ledger_hw_transport::Transport;

use crate::constant::{BTCHIP_CLA, BTCHIP_INS_SETUP, BTCHIP_INS_SET_KEYMAP, BTCHIP_INS_VERIFY_PIN};
use crate::error::DevError;

pub async fn setup<T: Transport + Sync>(
    transport: &T,
    operation_mode_flag: u8,
    feature_flag: u8,
    key_version: u8,
    key_version_p2sh: u8,
    user_pin: &str,
    wipe_pin: Option<&str>,
    seed: &[u8],
    dev_key: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>), DevError<T::Err>> {
    let mut data: Vec<u8> = vec![
        operation_mode_flag,
        feature_flag,
        key_version,
        key_version_p2sh,
    ];

    data.push(user_pin.len() as u8);
    data.extend(user_pin.as_bytes());

    if let Some(wpin) = wipe_pin {
        let w = wpin.as_bytes();
        data.push(w.len() as u8);
        data.extend(w);
    } else {
        data.push(0x00);
    }

    if seed.len() < 32 || seed.len() > 64 {
        return Err(DevError::InvalidSeedLength);
    }
    data.push(seed.len() as u8);
    data.extend(seed);

    if let Some(dkey) = dev_key {
        data.push(dkey.len() as u8);
        data.extend(dkey);
    } else {
        data.push(0x00);
    }
    let (mut res, status) = transport
        .send(BTCHIP_CLA, BTCHIP_INS_SETUP, 0x00, 0x00, &data)
        .await
        .map_err(|e| DevError::Transport(e))?;
    if status != Status::OK {
        return Err(DevError::ResponseStatus(status));
    }
    let res2 = res.split_off(16);
    Ok((res, res2))
}

pub async fn set_keymap_encoding<T: Transport + Sync>(
    transport: &T,
    keymap_encoding: &[u8],
) -> Result<(), DevError<T::Err>> {
    let mut data: Vec<u8> = vec![keymap_encoding.len() as u8];
    data.extend(keymap_encoding);
    let (_, status) = transport
        .send(BTCHIP_CLA, BTCHIP_INS_SET_KEYMAP, 0x00, 0x00, &data)
        .await
        .map_err(|e| DevError::Transport(e))?;
    if status != Status::OK {
        return Err(DevError::ResponseStatus(status));
    }
    Ok(())
}

pub async fn verify_pin<T: Transport + Sync>(
    transport: &T,
    pin: &str,
) -> Result<(), DevError<T::Err>> {
    let mut data: Vec<u8> = vec![pin.len() as u8];
    data.extend(pin.as_bytes());
    let (_, status) = transport
        .send(BTCHIP_CLA, BTCHIP_INS_VERIFY_PIN, 0x00, 0x00, &data)
        .await
        .map_err(|e| DevError::Transport(e))?;
    if status != Status::OK {
        return Err(DevError::ResponseStatus(status));
    }
    Ok(())
}
