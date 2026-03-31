// SPDX-License-Identifier: GPL-2.0

//! Interface between Nova Core and Nova DRM over the auxiliary bus.
//!
//! Nova DRM calls the exported functions directly with the parent device pointer.
//! The aux bus ensures the parent-child relationship; we use dev_get_drvdata to
//! obtain the NovaCore instance.

use kernel::bindings;

use crate::driver::NovaCore;

/// Return the VRAM BAR size in bytes for the given parent device.
/// Returns 0 if the parent is invalid.
#[allow(unreachable_pub)]
#[no_mangle]
pub extern "C" fn nova_core_vram_bar_size(parent: *mut bindings::device) -> u64 {
    if parent.is_null() {
        return 0;
    }

    // SAFETY: `parent` is non-null (checked above). The caller is responsible for passing
    // a valid `struct device` pointer. nova-drm obtains this pointer from its
    // auxiliary_device parent, which the aux bus keeps valid for the child's lifetime.
    let ptr = unsafe { bindings::dev_get_drvdata(parent) };
    if ptr.is_null() {
        return 0;
    }

    // SAFETY: `ptr` is non-null (checked above). The caller is responsible for passing a
    // device whose `drvdata` is a valid `NovaCore` instance.
    let core = unsafe { &*ptr.cast::<NovaCore>() };
    core.gpu.vram_bar_size()
}
