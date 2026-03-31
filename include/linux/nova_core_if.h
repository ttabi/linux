/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Interface between the Nova DRM driver (auxiliary driver) and the Nova Core
 * driver (parent PCI driver) over the auxiliary bus.
 *
 * Nova DRM calls the exported functions directly with the parent device pointer.
 */

#ifndef _LINUX_NOVA_CORE_IF_H
#define _LINUX_NOVA_CORE_IF_H

#include <linux/types.h>

struct device;

/**
 * nova_core_vram_bar_size - Return the VRAM BAR size in bytes.
 * @parent: The parent PCI device.
 *
 * Returns the size in bytes, or 0 on error.
 */
__u64 nova_core_vram_bar_size(struct device *parent);

#endif /* _LINUX_NOVA_CORE_IF_H */
