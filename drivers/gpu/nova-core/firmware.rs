// SPDX-License-Identifier: GPL-2.0

//! Contains structures and functions dedicated to the parsing, building and patching of firmwares
//! to be loaded into a given execution unit.

use core::marker::PhantomData;
use core::ops::Deref;

use kernel::{
    device,
    firmware,
    prelude::*,
    str::{CStr, CString},
    transmute::FromBytes, //
};

use crate::{
    falcon::{
        FalconDmaLoadTarget,
        FalconFirmware, //
    },
    gpu,
    num::IntoSafeCast,
};

pub(crate) mod booter;
pub(crate) mod fwsec;
pub(crate) mod gsp;
pub(crate) mod riscv;

/// Requests the GPU firmware TLV `name` suitable for `chipset`.
#[allow(unused)]
fn request_tlv(
    dev: &device::Device,
    chipset: gpu::Chipset,
    name: &str,
) -> Result<firmware::Firmware> {
    let chip_name = chipset.name();

    dev_info!(dev, "loading firmware image {}.tlv\n", name);

    CString::try_from_fmt(fmt!("nvidia/{chip_name}/gsp/{name}.tlv"))
        .and_then(|path| firmware::Firmware::request(&path, dev))
}

/// Structure used to describe some firmwares, notably FWSEC-FRTS.
#[repr(C)]
#[derive(Debug, Clone)]
pub(crate) struct FalconUCodeDescV2 {
    /// Header defined by 'NV_BIT_FALCON_UCODE_DESC_HEADER_VDESC*' in OpenRM.
    hdr: u32,
    /// Stored size of the ucode after the header, compressed or uncompressed
    stored_size: u32,
    /// Uncompressed size of the ucode.  If store_size == uncompressed_size, then the ucode
    /// is not compressed.
    pub(crate) uncompressed_size: u32,
    /// Code entry point
    pub(crate) virtual_entry: u32,
    /// Offset after the code segment at which the Application Interface Table headers are located.
    pub(crate) interface_offset: u32,
    /// Base address at which to load the code segment into 'IMEM'.
    pub(crate) imem_phys_base: u32,
    /// Size in bytes of the code to copy into 'IMEM' (includes both secure and non-secure
    /// segments).
    pub(crate) imem_load_size: u32,
    /// Virtual 'IMEM' address (i.e. 'tag') at which the code should start.
    pub(crate) imem_virt_base: u32,
    /// Virtual address of secure IMEM segment.
    pub(crate) imem_sec_base: u32,
    /// Size of secure IMEM segment.
    pub(crate) imem_sec_size: u32,
    /// Offset into stored (uncompressed) image at which DMEM begins.
    pub(crate) dmem_offset: u32,
    /// Base address at which to load the data segment into 'DMEM'.
    pub(crate) dmem_phys_base: u32,
    /// Size in bytes of the data to copy into 'DMEM'.
    pub(crate) dmem_load_size: u32,
    /// "Alternate" Size of data to load into IMEM.
    pub(crate) alt_imem_load_size: u32,
    /// "Alternate" Size of data to load into DMEM.
    pub(crate) alt_dmem_load_size: u32,
}

// SAFETY: all bit patterns are valid for this type, and it doesn't use interior mutability.
unsafe impl FromBytes for FalconUCodeDescV2 {}

/// Structure used to describe some firmwares, notably FWSEC-FRTS.
#[repr(C)]
#[derive(Debug, Clone)]
pub(crate) struct FalconUCodeDescV3 {
    /// Header defined by `NV_BIT_FALCON_UCODE_DESC_HEADER_VDESC*` in OpenRM.
    hdr: u32,
    /// Stored size of the ucode after the header.
    stored_size: u32,
    /// Offset in `DMEM` at which the signature is expected to be found.
    pub(crate) pkc_data_offset: u32,
    /// Offset after the code segment at which the app headers are located.
    pub(crate) interface_offset: u32,
    /// Base address at which to load the code segment into `IMEM`.
    pub(crate) imem_phys_base: u32,
    /// Size in bytes of the code to copy into `IMEM`.
    pub(crate) imem_load_size: u32,
    /// Virtual `IMEM` address (i.e. `tag`) at which the code should start.
    pub(crate) imem_virt_base: u32,
    /// Base address at which to load the data segment into `DMEM`.
    pub(crate) dmem_phys_base: u32,
    /// Size in bytes of the data to copy into `DMEM`.
    pub(crate) dmem_load_size: u32,
    /// Mask of the falcon engines on which this firmware can run.
    pub(crate) engine_id_mask: u16,
    /// ID of the ucode used to infer a fuse register to validate the signature.
    pub(crate) ucode_id: u8,
    /// Number of signatures in this firmware.
    pub(crate) signature_count: u8,
    /// Versions of the signatures, used to infer a valid signature to use.
    pub(crate) signature_versions: u16,
    _reserved: u16,
}

// SAFETY: all bit patterns are valid for this type, and it doesn't use
// interior mutability.
unsafe impl FromBytes for FalconUCodeDescV3 {}

/// Enum wrapping the different versions of Falcon microcode descriptors.
///
/// This allows handling both V2 and V3 descriptor formats through a
/// unified type, providing version-agnostic access to firmware metadata
/// via the [`FalconUCodeDescriptor`] trait.
#[derive(Debug, Clone)]
pub(crate) enum FalconUCodeDesc {
    V2(FalconUCodeDescV2),
    V3(FalconUCodeDescV3),
}

impl Deref for FalconUCodeDesc {
    type Target = dyn FalconUCodeDescriptor;

    fn deref(&self) -> &Self::Target {
        match self {
            FalconUCodeDesc::V2(v2) => v2,
            FalconUCodeDesc::V3(v3) => v3,
        }
    }
}

/// Trait providing a common interface for accessing Falcon microcode descriptor fields.
///
/// This trait abstracts over the different descriptor versions ([`FalconUCodeDescV2`] and
/// [`FalconUCodeDescV3`]), allowing code to work with firmware metadata without needing to
/// know the specific descriptor version. Fields not present return zero.
pub(crate) trait FalconUCodeDescriptor {
    fn hdr(&self) -> u32;
    fn imem_load_size(&self) -> u32;
    fn interface_offset(&self) -> u32;
    fn dmem_load_size(&self) -> u32;
    fn pkc_data_offset(&self) -> u32;
    fn engine_id_mask(&self) -> u16;
    fn ucode_id(&self) -> u8;
    fn signature_count(&self) -> u8;
    fn signature_versions(&self) -> u16;

    /// Returns the size in bytes of the header.
    fn size(&self) -> usize {
        let hdr = self.hdr();

        const HDR_SIZE_SHIFT: u32 = 16;
        const HDR_SIZE_MASK: u32 = 0xffff0000;
        ((hdr & HDR_SIZE_MASK) >> HDR_SIZE_SHIFT).into_safe_cast()
    }

    fn imem_sec_load_params(&self) -> FalconDmaLoadTarget;
    fn imem_ns_load_params(&self) -> Option<FalconDmaLoadTarget>;
    fn dmem_load_params(&self) -> FalconDmaLoadTarget;
}

impl FalconUCodeDescriptor for FalconUCodeDescV2 {
    fn hdr(&self) -> u32 {
        self.hdr
    }
    fn imem_load_size(&self) -> u32 {
        self.imem_load_size
    }
    fn interface_offset(&self) -> u32 {
        self.interface_offset
    }
    fn dmem_load_size(&self) -> u32 {
        self.dmem_load_size
    }
    fn pkc_data_offset(&self) -> u32 {
        0
    }
    fn engine_id_mask(&self) -> u16 {
        0
    }
    fn ucode_id(&self) -> u8 {
        0
    }
    fn signature_count(&self) -> u8 {
        0
    }
    fn signature_versions(&self) -> u16 {
        0
    }

    fn imem_sec_load_params(&self) -> FalconDmaLoadTarget {
        // `imem_sec_base` is the *virtual* start address of the secure IMEM segment, so subtract
        // `imem_virt_base` to get its physical offset.
        let imem_sec_start = self.imem_sec_base.saturating_sub(self.imem_virt_base);

        FalconDmaLoadTarget {
            src_start: imem_sec_start,
            dst_start: self.imem_phys_base.saturating_add(imem_sec_start),
            len: self.imem_sec_size,
        }
    }

    fn imem_ns_load_params(&self) -> Option<FalconDmaLoadTarget> {
        Some(FalconDmaLoadTarget {
            // Non-secure code always starts at offset 0.
            src_start: 0,
            dst_start: self.imem_phys_base,
            // `imem_load_size` includes the size of the secure segment, so subtract it to
            // get the correct amount of data to copy.
            len: self.imem_load_size.saturating_sub(self.imem_sec_size),
        })
    }

    fn dmem_load_params(&self) -> FalconDmaLoadTarget {
        FalconDmaLoadTarget {
            src_start: self.dmem_offset,
            dst_start: self.dmem_phys_base,
            len: self.dmem_load_size,
        }
    }
}

impl FalconUCodeDescriptor for FalconUCodeDescV3 {
    fn hdr(&self) -> u32 {
        self.hdr
    }
    fn imem_load_size(&self) -> u32 {
        self.imem_load_size
    }
    fn interface_offset(&self) -> u32 {
        self.interface_offset
    }
    fn dmem_load_size(&self) -> u32 {
        self.dmem_load_size
    }
    fn pkc_data_offset(&self) -> u32 {
        self.pkc_data_offset
    }
    fn engine_id_mask(&self) -> u16 {
        self.engine_id_mask
    }
    fn ucode_id(&self) -> u8 {
        self.ucode_id
    }
    fn signature_count(&self) -> u8 {
        self.signature_count
    }
    fn signature_versions(&self) -> u16 {
        self.signature_versions
    }

    fn imem_sec_load_params(&self) -> FalconDmaLoadTarget {
        FalconDmaLoadTarget {
            // IMEM segment always starts at offset 0.
            src_start: 0,
            dst_start: self.imem_phys_base,
            len: self.imem_load_size,
        }
    }

    fn imem_ns_load_params(&self) -> Option<FalconDmaLoadTarget> {
        // Not used on V3 platforms
        None
    }

    fn dmem_load_params(&self) -> FalconDmaLoadTarget {
        FalconDmaLoadTarget {
            // DMEM segment starts right after the IMEM one.
            src_start: self.imem_load_size,
            dst_start: self.dmem_phys_base,
            len: self.dmem_load_size,
        }
    }
}

/// Trait implemented by types defining the signed state of a firmware.
trait SignedState {}

/// Type indicating that the firmware must be signed before it can be used.
struct Unsigned;
impl SignedState for Unsigned {}

/// Type indicating that the firmware is signed and ready to be loaded.
struct Signed;
impl SignedState for Signed {}

/// Microcode to be loaded into a specific falcon.
///
/// This is module-local and meant for sub-modules to use internally.
///
/// After construction, a firmware is [`Unsigned`], and must generally be patched with a signature
/// before it can be loaded (with an exception for development hardware). The
/// [`Self::patch_signature`] and [`Self::no_patch_signature`] methods are used to transition the
/// firmware to its [`Signed`] state.
// TODO: Consider replacing this with a coherent memory object once `CoherentAllocation` supports
// temporary CPU-exclusive access to the object without unsafe methods.
struct FirmwareObject<F: FalconFirmware, S: SignedState>(KVVec<u8>, PhantomData<(F, S)>);

/// Trait for signatures to be patched directly into a given firmware.
///
/// This is module-local and meant for sub-modules to use internally.
trait FirmwareSignature<F: FalconFirmware>: AsRef<[u8]> {}

impl<F: FalconFirmware> FirmwareObject<F, Unsigned> {
    /// Patches the firmware at offset `signature_start` with `signature`.
    fn patch_signature<S: FirmwareSignature<F>>(
        mut self,
        signature: &S,
        signature_start: usize,
    ) -> Result<FirmwareObject<F, Signed>> {
        let signature_bytes = signature.as_ref();
        let signature_end = signature_start
            .checked_add(signature_bytes.len())
            .ok_or(EOVERFLOW)?;
        let dst = self
            .0
            .get_mut(signature_start..signature_end)
            .ok_or(EINVAL)?;

        // PANIC: `dst` and `signature_bytes` have the same length.
        dst.copy_from_slice(signature_bytes);

        Ok(FirmwareObject(self.0, PhantomData))
    }

    /// Mark the firmware as signed without patching it.
    ///
    /// This method is used to explicitly confirm that we do not need to sign the firmware, while
    /// allowing us to continue as if it was. This is typically only needed for development
    /// hardware.
    fn no_patch_signature(self) -> FirmwareObject<F, Signed> {
        FirmwareObject(self.0, PhantomData)
    }
}

pub(crate) struct ModInfoBuilder<const N: usize>(firmware::ModInfoBuilder<N>);

impl<const N: usize> ModInfoBuilder<N> {
    const fn make_entry_file(self, chipset: &str, fw: &str) -> Self {
        ModInfoBuilder(
            self.0
                .new_entry()
                .push("nvidia/")
                .push(chipset)
                .push("/gsp/")
                .push(fw),
        )
    }

    const fn make_entry_chipset(self, chipset: gpu::Chipset) -> Self {
        let name = chipset.name();

        let this = self
            .make_entry_file(name, "booter_load.tlv")
            .make_entry_file(name, "booter_unload.tlv")
            .make_entry_file(name, "gsp_bootloader.tlv")
            .make_entry_file(name, "gsp.tlv")
            .make_entry_file(name, "gsp.bin");

        if chipset.needs_fwsec_bootloader() {
            this.make_entry_file(name, "gen_bootloader.tlv")
        } else {
            this
        }
    }

    pub(crate) const fn create(
        module_name: &'static core::ffi::CStr,
    ) -> firmware::ModInfoBuilder<N> {
        let mut this = Self(firmware::ModInfoBuilder::new(module_name));
        let mut i = 0;

        while i < gpu::Chipset::ALL.len() {
            this = this.make_entry_chipset(gpu::Chipset::ALL[i]);
            i += 1;
        }

        this.0
    }
}

pub(crate) struct TlvBlock<'a> {
    pub(crate) tag: &'a str,
    pub(crate) value: &'a [u8],
}

/// On-wire TLV block header: 4-byte ASCII tag + little-endian payload length (bytes, excluding
/// padding to a 4-byte boundary).
struct TlvBlockHeader<'a> {
    tag: &'a str,
    length: usize,
}

impl<'a> TlvBlockHeader<'a> {
    const SIZE: usize = size_of::<[u8; 4]>() + size_of::<u32>();

    /// Parses the first [`Self::SIZE`] bytes of `hdr` (caller may pass a longer slice).
    fn parse(hdr: &'a [u8]) -> Option<Self> {
        let hdr = hdr.get(..Self::SIZE)?;
        let tag_bytes = hdr.get(..4)?;
        let tag = core::str::from_utf8(tag_bytes).ok()?;
        if !tag.is_ascii() {
            return None;
        }
        let len_arr = <[u8; 4]>::try_from(hdr.get(4..Self::SIZE)?).ok()?;
        let length = u32::from_le_bytes(len_arr) as usize;
        Some(Self { tag, length })
    }
}

/// Sequential scan over [`Tlv`]. Unlike [`Tlv`], this type carries a cursor (`pos`) into the
/// parent blob; it is not interchangeable with a fresh [`Tlv`] view of the same bytes.
struct TlvIter<'tlv, 'a> {
    tlv: &'tlv Tlv<'a>,
    pos: usize,
}

impl<'tlv, 'a> Iterator for TlvIter<'tlv, 'a> {
    type Item = TlvBlock<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.tlv.data.len() {
            return None;
        }

        let tail = &self.tlv.data[self.pos..];

        // SAFETY: `Tlv::new` validated this payload as an exact sequence of well-formed blocks;
        // `tail` starts at a block boundary and contains a full header.
        let hdr = unsafe { tail.get_unchecked(..TlvBlockHeader::SIZE) };
        // SAFETY: same header bytes as validated in `Tlv::new` for this offset.
        let header = unsafe { TlvBlockHeader::parse(hdr).unwrap_unchecked() };

        let stored_size = header.length.next_multiple_of(4);
        let advance = TlvBlockHeader::SIZE + stored_size;
        let payload_end = TlvBlockHeader::SIZE + header.length;

        // SAFETY: `advance` and `payload_end` are exactly the stored and logical payload extents
        // `Tlv::new` accepted for this block.
        let value = unsafe {
            let block = tail.get_unchecked(..advance);
            block.get_unchecked(TlvBlockHeader::SIZE..payload_end)
        };

        self.pos += advance;

        Some(TlvBlock {
            tag: header.tag,
            value,
        })
    }
}

/// The payload of a validated TLV (type, length, value) firmware image.
///
/// TLV firmware images start with a 4-byte "NVFW" magic header, followed by a sequence of
/// blocks. Each block has a 4-byte type tag, a 4-byte length field, and a data payload whose
/// stored size is the length rounded up to the nearest multiple of 4.
///
/// [`Self::new`] checks the magic header and walks every block: tags must be ASCII, lengths and
/// padding must fit without overflow, and the byte stream after
/// `NVFW` must be exactly partitionable into blocks (no trailing partial header or slack). After
/// that, [`TlvIter`] only signals end-of-stream via [`None`], not parse failure.
#[allow(dead_code)]
pub(crate) struct Tlv<'a> {
    data: &'a [u8],
}

#[allow(dead_code)]
impl<'a> Tlv<'a> {
    const MAGIC: &'static [u8; 4] = b"NVFW";

    /// Parses `data` as a TLV firmware image, returning [`EINVAL`] if the image is malformed.
    pub(crate) fn new(data: &'a [u8]) -> Result<Self> {
        // Verify that the magic bytes exist and are the correct value
        let magic_len = Self::MAGIC.len();
        if data
            .get(..magic_len)
            .is_none_or(|magic| magic != Self::MAGIC)
        {
            return Err(EINVAL);
        }

        // The payload is the contiguous sequence of TLV blocks after the magic.
        let payload = data.get(magic_len..).ok_or(EINVAL)?;

        let mut pos = 0usize;
        while pos < payload.len() {
            // Get the next TLV block.
            let Some(rest) = payload.get(pos..) else {
                return Err(EINVAL);
            };
            // Validate and extract the header (type, length).
            let Some(header) = rest
                .get(..TlvBlockHeader::SIZE)
                .and_then(TlvBlockHeader::parse)
            else {
                return Err(EINVAL);
            };
            // The `length` field of a TLV block contains the actual byte length of the
            // value, but each TLV block is aligned to a 4-byte boundary.
            let Some(stored_size) = header.length.checked_next_multiple_of(4) else {
                return Err(EINVAL);
            };
            let end = pos
                .checked_add(TlvBlockHeader::SIZE)
                .and_then(|p| p.checked_add(stored_size))
                .ok_or(EINVAL)?;
            if end > payload.len() {
                return Err(EINVAL);
            }
            pos = end;
        }

        Ok(Self { data: payload })
    }

    fn iter(&self) -> TlvIter<'_, 'a> {
        TlvIter { tlv: self, pos: 0 }
    }

    pub(crate) fn len(&self, tag: &str) -> Result<usize> {
        let tlv = self.iter().find(|b| b.tag == tag).ok_or(EINVAL)?;

        Ok(tlv.value.len())
    }

    pub(crate) fn get_bytes(&self, tag: &str) -> Result<&'a [u8]> {
        let tlv = self.iter().find(|b| b.tag == tag).ok_or(EINVAL)?;

        Ok(tlv.value)
    }

    pub(crate) fn get_u32(&self, tag: &str) -> Result<u32> {
        let tlv = self.iter().find(|b| b.tag == tag).ok_or(EINVAL)?;

        tlv.value
            .try_into()
            .ok()
            .map(u32::from_le_bytes)
            .ok_or(EINVAL)
    }

    pub(crate) fn get_string(&self, tag: &str) -> Result<&'a str> {
        let tlv = self.iter().find(|b| b.tag == tag).ok_or(EINVAL)?;

        // For now, handle the possibility that the value is null-terminated.
        let bytes = match CStr::from_bytes_until_nul(tlv.value) {
            Ok(cstr) => cstr.to_bytes(),
            Err(_) => tlv.value,
        };

        // But do require it to be all ASCII
        if !bytes.is_ascii() {
            return Err(EINVAL);
        }

        core::str::from_utf8(bytes).map_err(|_| EINVAL)
    }

    pub(crate) fn get_nth_chunk(&self, tag: &str, sigsize: usize, n: usize) -> Result<&'a [u8]> {
        let sigs = self
            .iter()
            .find(|b| b.tag == tag)
            .map(|b| b.value)
            .ok_or(EINVAL)?;

        let start = sigsize.checked_mul(n).ok_or(EINVAL)?;
        let end = start.checked_add(sigsize).ok_or(EINVAL)?;

        sigs.get(start..end).ok_or(EINVAL)
    }
}
