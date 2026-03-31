/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Simple test program to query the VRAM BAR size from nova-drm.
 *
 * Build from kernel source root:
 *   make -C tools/nova
 *
 * Or: gcc -Wall -O2 -o vram_bar_size tools/nova/vram_bar_size.c
 *
 * Usage:
 *   ./vram_bar_size [device]
 *
 * Default device is /dev/dri/card0. Use /dev/dri/renderD128 for a render node
 * (doesn't require root for many operations).
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/ioctl.h>

/* Must match include/uapi/drm/nova_drm.h */
#define NOVA_GETPARAM_VRAM_BAR_SIZE  0x1

struct drm_nova_getparam {
	uint64_t param;
	uint64_t value;
};

/* Must match DRM_IOCTL_NOVA_GETPARAM from kernel UAPI */
#define DRM_IOCTL_BASE      'd'
#define DRM_COMMAND_BASE    0x40
#define DRM_NOVA_GETPARAM   0x00
#define DRM_IOCTL_NOVA_GETPARAM  _IOWR(DRM_IOCTL_BASE, DRM_COMMAND_BASE + DRM_NOVA_GETPARAM, struct drm_nova_getparam)

int main(int argc, char *argv[])
{
	const char *path = argc > 1 ? argv[1] : "/dev/dri/card0";
	struct drm_nova_getparam getparam = {
		.param = NOVA_GETPARAM_VRAM_BAR_SIZE,
		.value = 0,
	};
	int fd, ret;

	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
		return 1;
	}

	ret = ioctl(fd, DRM_IOCTL_NOVA_GETPARAM, &getparam);
	close(fd);

	if (ret < 0) {
		fprintf(stderr, "NOVA_GETPARAM ioctl failed: %s\n", strerror(errno));
		return 1;
	}

	printf("VRAM BAR size: %llu bytes (%.2f MiB)\n",
	       (unsigned long long)getparam.value,
	       getparam.value / (1024.0 * 1024.0));
	return 0;
}
