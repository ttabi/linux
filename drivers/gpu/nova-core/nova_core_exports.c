// SPDX-License-Identifier: GPL-2.0
/*
 * Export Nova Core interface symbols so nova-drm.ko can resolve them.
 * Implementation is in Rust (iface.rs).
 */

#include <linux/device.h>

/* Implemented in Rust (nova_core iface.rs). */
extern __u64 nova_core_vram_bar_size(struct device *parent);

EXPORT_SYMBOL_GPL(nova_core_vram_bar_size);
