# SPDX-License-Identifier: GPL-2.0
#
# Build Nova userspace test tools.
# Run from kernel source root: make -C tools/nova
#
CFLAGS ?= -Wall -O2

vram_bar_size: vram_bar_size.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f vram_bar_size

.PHONY: clean
