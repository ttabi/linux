// SPDX-License-Identifier: GPL-2.0

use crate::driver::Bar0;
use crate::falcon::{Falcon, FalconEngine};
use crate::regs;
use kernel::device;
use kernel::prelude::*;

/// Type specifying the `Fsp` falcon engine. Cannot be instantiated.
pub(crate) struct Fsp(());

impl FalconEngine for Fsp {
    // FSP falcon base address:
    const BASE: usize = 0x8f2000;
}

/// Helper function to log EMEM data in nouveau's format
fn log_emem_data(dev: &device::Device<device::Bound>, offset: u32, data: &[u8], is_write: bool) {
    let direction = if is_write { "<-" } else { "->" };

    // Log the header like nouveau: "fsp:fsp: emem 00000000 <- 00000364 bytes at 00000000"
    dev_info!(
        dev,
        "fsp:fsp: emem {:08x} {} {:08x} bytes at {:08x}\n",
        offset,
        direction,
        data.len(),
        offset
    );

    // Log data in 16-byte lines like nouveau does, displaying as 32-bit words
    for (line_offset, chunk) in data.chunks(16).enumerate() {
        let addr = offset + (line_offset * 16) as u32;

        // Convert bytes to 32-bit words in little-endian format (like Nouveau)
        let mut words = [0u32; 4];
        for (word_idx, word_bytes) in chunk.chunks(4).enumerate() {
            if word_idx < 4 && word_bytes.len() == 4 {
                words[word_idx] = u32::from_le_bytes([
                    word_bytes[0],
                    word_bytes[1],
                    word_bytes[2],
                    word_bytes[3],
                ]);
            }
        }

        // Display in Nouveau's format: "emem 00000000 <- c0000000 1410de7e 035c0002 15f40000"
        if chunk.len() >= 16 {
            dev_info!(
                dev,
                "emem {:08x} {} {:08x} {:08x} {:08x} {:08x}\n",
                addr,
                direction,
                words[0],
                words[1],
                words[2],
                words[3]
            );
        } else {
            // Handle partial lines - log available words
            match chunk.len() {
                1..=4 => dev_info!(dev, "emem {:08x} {} {:08x}\n", addr, direction, words[0]),
                5..=8 => dev_info!(
                    dev,
                    "emem {:08x} {} {:08x} {:08x}\n",
                    addr,
                    direction,
                    words[0],
                    words[1]
                ),
                9..=12 => dev_info!(
                    dev,
                    "emem {:08x} {} {:08x} {:08x} {:08x}\n",
                    addr,
                    direction,
                    words[0],
                    words[1],
                    words[2]
                ),
                13..=15 => dev_info!(
                    dev,
                    "emem {:08x} {} {:08x} {:08x} {:08x} {:08x}\n",
                    addr,
                    direction,
                    words[0],
                    words[1],
                    words[2],
                    words[3]
                ),
                _ => {}
            }
        }
    }
}

impl Falcon<Fsp> {
    /// Write data to FSP external memory using Falcon PIO (Programmed I/O).
    ///
    /// This function writes data to the FSP (Falcon Security Processor) external
    /// memory space using the Falcon's indirect memory access interface.
    ///
    /// # Arguments
    /// * `dev` - Device for logging FSP emem operations
    /// * `bar` - BAR0 memory mapping for register access
    /// * `offset` - Byte offset within FSP external memory to start writing
    /// * `data` - Slice of bytes to write to memory (must be 4-byte aligned)
    ///
    /// # Returns
    /// `Ok(())` on successful write, or an error if register operations fail.
    ///
    /// # Note
    /// The data length must be 4-byte aligned as required by the falcon hardware.
    pub(crate) fn write_emem(
        &self,
        dev: &device::Device<device::Bound>,
        bar: &Bar0,
        offset: u32,
        data: &[u8],
    ) -> Result {
        // Log FSP emem write operation like nouveau
        log_emem_data(dev, offset, data, true);

        // Use GP102 EMEM PIO registers like Nouveau does for FSP
        // Initialize EMEM write: BIT(24) | emem_base (matching Nouveau's gp102_flcn_pio_emem_wr_init)
        regs::NV_PFALCON_FALCON_EMEM_CTL::default()
            .set_value((1 << 24) | offset)
            .write(bar, Fsp::BASE);

        // Write data in 4-byte chunks using GP102 EMEM data register
        // (matching Nouveau's gp102_flcn_pio_emem_wr)
        for chunk in data.chunks(4) {
            let mut word = 0u32;
            for (i, &byte) in chunk.iter().enumerate() {
                word |= (byte as u32) << (i * 8);
            }

            regs::NV_PFALCON_FALCON_EMEM_DATA::default()
                .set_data(word)
                .write(bar, Fsp::BASE);
        }

        Ok(())
    }

    /// Read data from FSP external memory using Falcon PIO (Programmed I/O).
    ///
    /// This function reads data from the FSP (Falcon Security Processor) external
    /// memory space using the Falcon's indirect memory access interface.
    ///
    /// # Arguments
    /// * `dev` - Device for logging FSP emem operations
    /// * `bar` - BAR0 memory mapping for register access
    /// * `offset` - Byte offset within FSP external memory to start reading
    /// * `data` - Mutable slice to store the read data (must be 4-byte aligned)
    ///
    /// # Returns
    /// `Ok(())` on successful read, or an error if register operations fail.
    ///
    /// # Note
    /// The data length must be 4-byte aligned as required by the falcon hardware.
    pub(crate) fn read_emem(
        &self,
        dev: &device::Device<device::Bound>,
        bar: &Bar0,
        offset: u32,
        data: &mut [u8],
    ) -> Result {
        // Use GP102 EMEM PIO registers like Nouveau does for FSP
        // Initialize EMEM read: BIT(25) | emem_base (different from write which uses BIT(24))
        regs::NV_PFALCON_FALCON_EMEM_CTL::default()
            .set_value((1 << 25) | offset)
            .write(bar, Fsp::BASE);

        // Read data in 4-byte chunks using GP102 EMEM data register
        for chunk in data.chunks_mut(4) {
            let word = regs::NV_PFALCON_FALCON_EMEM_DATA::read(bar, Fsp::BASE).data();

            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte = ((word >> (i * 8)) & 0xff) as u8;
            }
        }

        // Log FSP emem read operation like nouveau
        log_emem_data(dev, offset, data, false);

        Ok(())
    }
}
