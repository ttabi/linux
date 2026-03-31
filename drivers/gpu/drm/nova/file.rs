// SPDX-License-Identifier: GPL-2.0

use crate::driver::{NovaDevice, NovaDriver};
use crate::gem::NovaObject;
use kernel::{
    bindings,
    drm::{self, gem::BaseObject},
    prelude::*,
    uapi,
};

pub(crate) struct File;

impl drm::file::DriverFile for File {
    type Driver = NovaDriver;

    fn open(_dev: &NovaDevice) -> Result<Pin<KBox<Self>>> {
        Ok(KBox::new(Self, GFP_KERNEL)?.into())
    }
}

impl File {
    /// IOCTL: get_param: Query GPU / driver metadata.
    pub(crate) fn get_param(
        dev: &NovaDevice,
        getparam: &mut uapi::drm_nova_getparam,
        _file: &drm::File<File>,
    ) -> Result<u32> {
        let parent = dev.adev.parent();
        let parent_raw = parent.as_raw();

        // Rust won't let us match u64 against u32, so we have to create u64 versions
        // of any parameters we support.
        const VRAM_BAR_SIZE: u64 = uapi::NOVA_GETPARAM_VRAM_BAR_SIZE as u64;

        getparam.value = match getparam.param {
            VRAM_BAR_SIZE => {
                // SAFETY: `parent_raw` is the parent device from our auxiliary device.
                unsafe { bindings::nova_core_vram_bar_size(parent_raw) }
            }
            _ => return Err(EINVAL),
        };

        Ok(0)
    }

    /// IOCTL: gem_create: Create a new DRM GEM object.
    pub(crate) fn gem_create(
        dev: &NovaDevice,
        req: &mut uapi::drm_nova_gem_create,
        file: &drm::File<File>,
    ) -> Result<u32> {
        let obj = NovaObject::new(dev, req.size.try_into()?)?;

        req.handle = obj.create_handle(file)?;

        Ok(0)
    }

    /// IOCTL: gem_info: Query GEM metadata.
    pub(crate) fn gem_info(
        _dev: &NovaDevice,
        req: &mut uapi::drm_nova_gem_info,
        file: &drm::File<File>,
    ) -> Result<u32> {
        let bo = NovaObject::lookup_handle(file, req.handle)?;

        req.size = bo.size().try_into()?;

        Ok(0)
    }
}
