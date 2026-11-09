//! Raw UEFI FFI — only the handful of services efiboot uses (UEFI 2.x spec layouts).
//! No crate dependency: every struct offset here is checked against the spec tables.

use core::fmt;

pub type Handle = *mut core::ffi::c_void;
pub type Status = usize;
pub const SUCCESS: Status = 0;

#[repr(C)]
pub struct TableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

#[repr(C)]
pub struct SimpleTextOutput {
    pub reset: extern "efiapi" fn(*mut SimpleTextOutput, bool) -> Status,
    pub output_string: extern "efiapi" fn(*mut SimpleTextOutput, *const u16) -> Status,
    // remaining members unused
}

#[repr(C)]
pub struct ConfigTable {
    pub guid: [u8; 16],
    pub table: *const u8,
}

#[repr(C)]
pub struct SystemTable {
    pub hdr: TableHeader,
    pub firmware_vendor: *const u16,
    pub firmware_revision: u32,
    pub console_in_handle: Handle,
    pub con_in: *mut core::ffi::c_void,
    pub console_out_handle: Handle,
    pub con_out: *mut SimpleTextOutput,
    pub stderr_handle: Handle,
    pub std_err: *mut SimpleTextOutput,
    pub runtime_services: *const RuntimeServices,
    pub boot_services: *const BootServices,
    pub number_of_table_entries: usize,
    pub configuration_table: *const ConfigTable,
}

/// EFI_BOOT_SERVICES — function-pointer table; unused slots kept as `usize` so the
/// offsets of the ones we call stay exact.
#[repr(C)]
pub struct BootServices {
    pub hdr: TableHeader,
    _raise_tpl: usize,
    _restore_tpl: usize,
    pub allocate_pages: extern "efiapi" fn(u32, u32, usize, *mut u64) -> Status,
    _free_pages: usize,
    pub get_memory_map:
        extern "efiapi" fn(*mut usize, *mut u8, *mut usize, *mut usize, *mut u32) -> Status,
    _allocate_pool: usize,
    _free_pool: usize,
    _create_event: usize,
    _set_timer: usize,
    _wait_for_event: usize,
    _signal_event: usize,
    _close_event: usize,
    _check_event: usize,
    _install_protocol_interface: usize,
    _reinstall_protocol_interface: usize,
    _uninstall_protocol_interface: usize,
    _handle_protocol: usize,
    _reserved: usize,
    _register_protocol_notify: usize,
    _locate_handle: usize,
    _locate_device_path: usize,
    _install_configuration_table: usize,
    _load_image: usize,
    _start_image: usize,
    _exit: usize,
    _unload_image: usize,
    pub exit_boot_services: extern "efiapi" fn(Handle, usize) -> Status,
    _get_next_monotonic_count: usize,
    _stall: usize,
    pub set_watchdog_timer: extern "efiapi" fn(usize, u64, usize, *const u16) -> Status,
}

#[repr(C)]
pub struct RuntimeServices {
    pub hdr: TableHeader,
    _get_time: usize,
    _set_time: usize,
    _get_wakeup_time: usize,
    _set_wakeup_time: usize,
    _set_virtual_address_map: usize,
    _convert_pointer: usize,
    _get_variable: usize,
    _get_next_variable_name: usize,
    _set_variable: usize,
    _get_next_high_monotonic_count: usize,
    pub reset_system: extern "efiapi" fn(u32, Status, usize, *const u8) -> !,
}

pub const RESET_SHUTDOWN: u32 = 2;

/// EFI_ACPI_20_TABLE_GUID 8868e871-e4f1-11d3-bc22-0080c73c8881 (mixed-endian byte form).
pub const ACPI20_GUID: [u8; 16] = [
    0x71, 0xe8, 0x68, 0x88, 0xf1, 0xe4, 0xd3, 0x11, 0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81,
];

// EFI_MEMORY_TYPE values we classify.
pub const MT_LOADER_CODE: u32 = 1;
pub const MT_LOADER_DATA: u32 = 2;
pub const MT_BOOT_CODE: u32 = 3;
pub const MT_BOOT_DATA: u32 = 4;
pub const MT_CONVENTIONAL: u32 = 7;

/// Firmware console writer (ConOut). UTF-16, LF -> CRLF, chunked through a stack buffer.
pub struct ConOut(pub *mut SimpleTextOutput);

impl fmt::Write for ConOut {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let mut buf = [0u16; 129];
        let mut n = 0;
        let flush = |buf: &mut [u16; 129], n: &mut usize| {
            buf[*n] = 0;
            unsafe { ((*self.0).output_string)(self.0, buf.as_ptr()) };
            *n = 0;
        };
        for c in s.chars() {
            if n >= 126 {
                flush(&mut buf, &mut n);
            }
            if c == '\n' {
                buf[n] = '\r' as u16;
                n += 1;
            }
            buf[n] = if (c as u32) < 0x10000 { c as u16 } else { '?' as u16 };
            n += 1;
        }
        if n > 0 {
            flush(&mut buf, &mut n);
        }
        Ok(())
    }
}
