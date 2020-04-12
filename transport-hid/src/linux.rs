/*******************************************************************************
*   (c) 2018 ZondaX GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

extern crate libc;
use std::{ffi::CStr, mem};

// example from hidapi examples
const HID_MAX_DESCRIPTOR_SIZE: usize = 4096;

#[repr(C)]
pub struct HidrawReportDescriptor {
    size: u32,
    value: [u8; HID_MAX_DESCRIPTOR_SIZE],
}

#[derive(Debug)]
pub enum Error {
    FileNotFound,
    Ioctl(nix::Error),
}

pub fn get_usage_page(device_path: &CStr) -> Result<u16, Error> {
    // #define HIDIOCGRDESCSIZE	_IOR('H', 0x01, int)
    // #define HIDIOCGRDESC		_IOR('H', 0x02, struct HidrawReportDescriptor)
    ioctl_read!(hid_read_descr_size, b'H', 0x01, libc::c_int);
    ioctl_read!(hid_read_descr, b'H', 0x02, HidrawReportDescriptor);

    use std::fs::OpenOptions;
    use std::os::unix::{fs::OpenOptionsExt, io::AsRawFd};

    let file_name = device_path.to_str().unwrap();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(file_name)
        .map_err(|_| Error::FileNotFound)?;

    let mut desc_size = 0;

    unsafe {
        let fd = file.as_raw_fd();

        if let Err(e) = hid_read_descr_size(fd, &mut desc_size) {
            return Err(Error::Ioctl(e));
        }
        let mut desc_raw_uninit =
            mem::MaybeUninit::<HidrawReportDescriptor>::new(HidrawReportDescriptor {
                size: desc_size as u32,
                value: [0u8; 4096],
            });
        if let Err(e) = hid_read_descr(fd, desc_raw_uninit.as_mut_ptr()) {
            return Err(Error::Ioctl(e));
        }
        let desc_raw = desc_raw_uninit.assume_init();

        let data = &desc_raw.value[..desc_raw.size as usize];

        let mut data_len;
        let mut key_size;
        let mut i = 0 as usize;

        while i < desc_size as usize {
            let key = data[i];
            let key_cmd = key & 0xFC;

            if key & 0xF0 == 0xF0 {
                data_len = 0;
                key_size = 3;
                if i + 1 < desc_size as usize {
                    data_len = data[i + 1];
                }
            } else {
                key_size = 1;
                data_len = key & 0x03;
                if data_len == 3 {
                    data_len = 4;
                }
            }

            if key_cmd == 0x04 {
                let usage_page = match data_len {
                    1 => u16::from(data[i + 1]),
                    2 => (u16::from(data[i + 2]) * 256 + u16::from(data[i + 1])),
                    _ => 0 as u16,
                };

                return Ok(usage_page);
            }

            i += (data_len + key_size) as usize;
        }
    }
    Ok(0)
}
