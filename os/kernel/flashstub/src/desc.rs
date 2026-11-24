// SPDX-License-Identifier: AGPL-3.0-only
//! USB descriptors of the flash stub (USB 2.0 spec chapter 9; Microsoft OS 2.0 Descriptors specification).
//!
//! One configuration, one vendor-class interface (0xff / 0x48 'H' / 0x01 = HQFL v1, ADR 0070 D4) with one bulk OUT
//! (0x01) and one bulk IN (0x82) endpoint, 512-byte packets at high speed. bcdUSB 2.01 so a host asks for the BOS,
//! which carries the MS OS 2.0 platform capability: Windows then fetches the descriptor set with a vendor request and
//! binds WinUSB to the device without an INF (ADR 0070 D2 / Q4), which is what WebUSB needs on Windows.

/// pid.codes test VID/PID — a PLACEHOLDER (ADR 0070 Q2) until a pid.codes allocation or a vendor ID exists. The
/// browser side (`tools/flash/web`) uses the same pair.
pub const VID: u16 = 0x1209;
pub const PID: u16 = 0x0001;
/// bcdDevice: the HQFL protocol version in the high byte.
pub const BCD_DEVICE: u16 = 0x0100;

pub const EP_OUT: u8 = 1;
pub const EP_IN: u8 = 2;
pub const EP0_MPS: u16 = 64;
pub const HS_BULK_MPS: u16 = 512;
pub const FS_BULK_MPS: u16 = 64;

/// bRequest of the vendor request that returns the MS OS 2.0 descriptor set (wIndex = 7).
pub const MS_VENDOR_CODE: u8 = 0x48;
pub const MS_OS_20_DESCRIPTOR_INDEX: u16 = 7;

pub const DEVICE: [u8; 18] = [
    18, 0x01, // bLength, DEVICE
    0x01, 0x02, // bcdUSB 2.01 (BOS present)
    0x00, 0x00, 0x00, // class at the interface
    EP0_MPS as u8,
    (VID & 0xff) as u8, (VID >> 8) as u8,
    (PID & 0xff) as u8, (PID >> 8) as u8,
    (BCD_DEVICE & 0xff) as u8, (BCD_DEVICE >> 8) as u8,
    1, 2, 3, // iManufacturer, iProduct, iSerialNumber
    1,       // bNumConfigurations
];

pub const QUALIFIER: [u8; 10] = [10, 0x06, 0x01, 0x02, 0x00, 0x00, 0x00, EP0_MPS as u8, 1, 0];

pub const CONFIG_LEN: usize = 9 + 9 + 7 + 7;

/// The configuration descriptor for a bulk packet size (`ty` = 0x02 CONFIGURATION or 0x07 OTHER_SPEED_CONFIGURATION).
pub const fn config(ty: u8, bulk_mps: u16) -> [u8; CONFIG_LEN] {
    let (lo, hi) = ((bulk_mps & 0xff) as u8, (bulk_mps >> 8) as u8);
    [
        9, ty, CONFIG_LEN as u8, 0, 1, 1, 0, 0xC0, 50, // 1 interface, value 1, self-powered, 100 mA
        9, 0x04, 0, 0, 2, 0xFF, 0x48, 0x01, 4, // interface 0: vendor ff/48/01, iInterface 4
        7, 0x05, EP_OUT, 0x02, lo, hi, 0, // bulk OUT
        7, 0x05, 0x80 | EP_IN, 0x02, lo, hi, 0, // bulk IN
    ]
}

const fn le16(v: usize) -> [u8; 2] {
    [(v & 0xff) as u8, (v >> 8) as u8]
}

/// The registry property name and the interface GUID (REG_MULTI_SZ: the string, then an empty string).
const PROP_NAME: &str = "DeviceInterfaceGUIDs";
/// The device interface GUID WinUSB registers this interface under (our own, generated for the stub).
pub const INTERFACE_GUID: &str = "{7D3A1C52-9E48-4B6F-A1D0-5C2E8F4B9A61}";
const NAME_LEN: usize = (PROP_NAME.len() + 1) * 2;
const DATA_LEN: usize = (INTERFACE_GUID.len() + 2) * 2;
const REG_LEN: usize = 10 + NAME_LEN + DATA_LEN;
pub const MSOS20_LEN: usize = 10 + 20 + REG_LEN;

/// Copy `s` as UTF-16LE (ASCII only) into `out` at `at`.
const fn utf16_into<const N: usize>(mut out: [u8; N], at: usize, s: &str) -> [u8; N] {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        out[at + 2 * i] = b[i];
        i += 1;
    }
    out
}

/// The MS OS 2.0 descriptor set: set header, compatible ID "WINUSB", the DeviceInterfaceGUIDs registry property.
pub const MSOS20_SET: [u8; MSOS20_LEN] = {
    let mut d = [0u8; MSOS20_LEN];
    let h = le16(10);
    d[0] = h[0];
    d[1] = h[1];
    // wDescriptorType 0 = MS_OS_20_SET_HEADER_DESCRIPTOR; dwWindowsVersion 0x06030000 (Windows 8.1)
    d[4] = 0x00;
    d[5] = 0x00;
    d[6] = 0x03;
    d[7] = 0x06;
    let t = le16(MSOS20_LEN);
    d[8] = t[0];
    d[9] = t[1];
    // Compatible ID descriptor (20 bytes): type 3, "WINUSB\0\0", sub-compatible ID all zero
    d[10] = 20;
    d[12] = 0x03;
    let id = b"WINUSB";
    let mut i = 0;
    while i < id.len() {
        d[14 + i] = id[i];
        i += 1;
    }
    // Registry property descriptor: type 4, REG_MULTI_SZ (7)
    let r = 30;
    let l = le16(REG_LEN);
    d[r] = l[0];
    d[r + 1] = l[1];
    d[r + 2] = 0x04;
    d[r + 4] = 0x07;
    let nl = le16(NAME_LEN);
    d[r + 6] = nl[0];
    d[r + 7] = nl[1];
    d = utf16_into(d, r + 8, PROP_NAME);
    let dl = le16(DATA_LEN);
    d[r + 8 + NAME_LEN] = dl[0];
    d[r + 9 + NAME_LEN] = dl[1];
    utf16_into(d, r + 10 + NAME_LEN, INTERFACE_GUID)
};

pub const BOS_LEN: usize = 5 + 28;

/// BOS with one platform capability: MS OS 2.0 (UUID D8DD60DF-4589-4CC7-9CD2-659D9E648A9F).
pub const BOS: [u8; BOS_LEN] = {
    let t = le16(MSOS20_LEN);
    [
        5, 0x0F, BOS_LEN as u8, 0, 1, // BOS: total length, 1 capability
        28, 0x10, 0x05, 0x00, // DEVICE CAPABILITY, PLATFORM
        0xDF, 0x60, 0xDD, 0xD8, 0x89, 0x45, 0xC7, 0x4C, 0x9C, 0xD2, 0x65, 0x9D, 0x9E, 0x64, 0x8A, 0x9F,
        0x00, 0x00, 0x03, 0x06, // dwWindowsVersion 0x06030000
        t[0], t[1], // wMSOSDescriptorSetTotalLength
        MS_VENDOR_CODE, 0x00, // bMS_VendorCode, bAltEnumCode
    ]
};

pub const MANUFACTURER: &str = "HookProbe";
pub const PRODUCT: &str = "heqk flash stub (HQFL v1)";
pub const INTERFACE: &str = "HQFL v1";

/// A string descriptor (index > 0) into `out`; returns its length. Index 0 is the language list (en-US).
pub fn string(idx: u8, serial: &str, out: &mut [u8; 64]) -> Option<usize> {
    let s = match idx {
        0 => {
            out[..4].copy_from_slice(&[4, 0x03, 0x09, 0x04]);
            return Some(4);
        }
        1 => MANUFACTURER,
        2 => PRODUCT,
        3 => serial,
        4 => INTERFACE,
        _ => return None,
    };
    let n = 2 + 2 * s.len().min(31);
    out[0] = n as u8;
    out[1] = 0x03;
    for (i, b) in s.bytes().take(31).enumerate() {
        out[2 + 2 * i] = b;
        out[3 + 2 * i] = 0;
    }
    Some(n)
}

/// The serial-number string: "HQFL-" and the first 8 bytes of the stub's build hash in hex. A serial number lets
/// Chrome keep its permission across a reset of the same device (ADR 0070 D1); it is NOT the board serial, which
/// lives in OTP and is never read by the stub (D3.6).
pub fn serial(build: &[u8; 32], out: &mut [u8; 21]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    out[..5].copy_from_slice(b"HQFL-");
    for i in 0..8 {
        out[5 + 2 * i] = HEX[(build[i] >> 4) as usize];
        out[6 + 2 * i] = HEX[(build[i] & 15) as usize];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msos20_set_layout() {
        assert_eq!(MSOS20_LEN, 162);
        assert_eq!(u16::from_le_bytes([MSOS20_SET[8], MSOS20_SET[9]]) as usize, MSOS20_LEN);
        assert_eq!(&MSOS20_SET[14..20], b"WINUSB");
        assert_eq!(u16::from_le_bytes([MSOS20_SET[30], MSOS20_SET[31]]) as usize, MSOS20_LEN - 30);
        assert_eq!(u16::from_le_bytes([BOS[2], BOS[3]]) as usize, BOS_LEN);
        assert_eq!(u16::from_le_bytes([BOS[29], BOS[30]]) as usize, MSOS20_LEN);
        // the GUID string ends with "}\0" then the REG_MULTI_SZ terminator "\0"
        let end = MSOS20_LEN;
        assert_eq!(&MSOS20_SET[end - 6..], &[b'}', 0, 0, 0, 0, 0]);
    }

    #[test]
    fn config_is_vendor_hqfl_with_two_bulk_endpoints() {
        let c = config(2, HS_BULK_MPS);
        assert_eq!(c[2] as usize, c.len());
        assert_eq!(&c[9 + 5..9 + 8], &[0xFF, 0x48, 0x01]);
        assert_eq!((c[18 + 2], c[18 + 3], c[18 + 5]), (0x01, 0x02, 0x02));
        assert_eq!((c[25 + 2], c[25 + 3], c[25 + 5]), (0x82, 0x02, 0x02));
    }
}
