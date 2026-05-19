// SPDX-License-Identifier: GPL-2.0

//! Support for firmware binaries designed to run on a RISC-V core. Such firmwares files have a
//! dedicated header.

use kernel::{
    device,
    dma::Coherent,
    firmware::Firmware,
    prelude::*,
    transmute::FromBytes, //
};

use crate::firmware::Tlv;

/// Descriptor for microcode running on a RISC-V core.
#[repr(C)]
#[derive(Debug)]
struct RmRiscvUCodeDesc {
    version: u32,
    bootloader_offset: u32,
    bootloader_size: u32,
    bootloader_param_offset: u32,
    bootloader_param_size: u32,
    riscv_elf_offset: u32,
    riscv_elf_size: u32,
    app_version: u32,
    manifest_offset: u32,
    manifest_size: u32,
    monitor_data_offset: u32,
    monitor_data_size: u32,
    monitor_code_offset: u32,
    monitor_code_size: u32,
}

// SAFETY: all bit patterns are valid for this type, and it doesn't use interior mutability.
unsafe impl FromBytes for RmRiscvUCodeDesc {}

impl RmRiscvUCodeDesc {
    /// Interprets the beginning of slice `desc` as a [`RmRiscvUCodeDesc`] and returns it.
    ///
    /// Fails if is the slice is too small.
    fn new(desc: &[u8]) -> Result<Self> {
        desc
            .get(..size_of::<RmRiscvUCodeDesc>())
            .and_then(RmRiscvUCodeDesc::from_bytes_copy)
            .ok_or(EINVAL)
    }
}

/// A parsed firmware for a RISC-V core, ready to be loaded and run.
pub(crate) struct RiscvFirmware {
    /// Offset at which the code starts in the firmware image.
    pub(crate) code_offset: u32,
    /// Offset at which the data starts in the firmware image.
    pub(crate) data_offset: u32,
    /// Offset at which the manifest starts in the firmware image.
    pub(crate) manifest_offset: u32,
    /// Application version.
    pub(crate) app_version: u32,
    /// Device-mapped firmware image.
    pub(crate) ucode: Coherent<[u8]>,
}

impl RiscvFirmware {
    pub(crate) fn new(dev: &device::Device<device::Bound>, fw: &Firmware) -> Result<Self> {
        let tlv = Tlv::new(fw.data())?;

        let desc = tlv.get_bytes("DESC")?;
        let riscv_desc = RmRiscvUCodeDesc::new(desc)?;

        let ucode = Coherent::from_slice(dev, tlv.get_bytes("BLOB")?, GFP_KERNEL)?;

        Ok(Self {
            ucode,
            code_offset: riscv_desc.monitor_code_offset,
            data_offset: riscv_desc.monitor_data_offset,
            manifest_offset: riscv_desc.manifest_offset,
            app_version: riscv_desc.app_version,
        })
    }
}
