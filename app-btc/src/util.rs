use ledger_hw::Status;
use ledger_hw_transport::Transport;

use crate::constant::{BTCHIP_CLA, BTCHIP_INS_GET_FIRMWARE_VERSION};

use crate::error::AppError;

pub async fn get_firmware_version<T: Transport + Sync>(
    transport: &T,
) -> Result<(bool, u8, String), AppError<T::Err>> {
    let (mut res, status) = transport
        .send(BTCHIP_CLA, BTCHIP_INS_GET_FIRMWARE_VERSION, 0x00, 0x00, &[])
        .await
        .map_err(|e| AppError::Transport(e))?;
    if status == Status::ConditionsOfUseNotSatisfied {
        res = vec![0x00, 0x00, 0x01, 0x04, 0x03];
    } else if status != Status::OK {
        return Err(AppError::ResponseStatus(status));
    }
    if res.len() < 5 {
        return Err(AppError::Unexpected);
    }
    Ok((
        res[0] == 0x01,
        res[1],
        format!("{}.{}.{}", res[2], res[3], res[4]),
    ))
}
