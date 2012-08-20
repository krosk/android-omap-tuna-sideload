/*
 * arch/arm/common/fast_switch.h
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __FAST_SWITCH_H
#define __FAST_SWITCH_H

#define BLANK_VALUE 		0xC0C0C0C0
#define FSW_BASE 		0xAC000000
#define FSW_MAGIC		0x00
#define FSW_MAGIC_VALUE		0xDEADBEEF
#define FSW_CURR		0x04
#define FSW_TARG 		0x08
#define FSW_MODE		0x0c
#define FSW_MODE_NULL		0
#define FSW_MODE_BOOT		1
#define FSW_MODE_SUSPEND	2
#define FSW_MODE_RESUME		3
#define FSW_MODE_LAST		4
#define FSW_WAKELOCK		0x10
#define FSW_WAKELOCK_SKIP	0xDEADBEEF
#define FSW_WAKELOCK_NOSKIP	0
#define FSW_FLAG		0x14
#define FSW_FLAG_VALUE		0xDEADBEEF

#define FSW_INST_MAX		3
#define FSW_INST_SHIFT		10
#define FSW_INST_BOOT		0x00
#define FSW_INST_JUMP		0x10
#define FSW_INST_REGS		0x20

#define ARM_ZIMAGE_MAGIC_OFFSET	0x24
#define ARM_ZIMAGE_MAGIC	0x016F2818

#ifndef __ASSEMBLY__
/* The layout must be consistent with the offsets */
struct fsw_page {
	unsigned int magic_tag;
	unsigned int current_instance;
	unsigned int target_instance;
	unsigned int switch_mode;
	unsigned int skip_wakelock;
	unsigned int allow_core[4]; /* one flag per core */
	unsigned int boot_psize; /* size of boot_pparam, in char */
	char *boot_pparam;
};

struct fsw_inst_page {
	unsigned int boot_tags[4]; /* boot info (like atags) address */
	unsigned int jump_address[4]; /* one jump address per core */
	unsigned int *regs;
};

#ifdef CONFIG_FAST_SWITCH
extern struct fsw_page *fsw_base; /* Fixed once, not relocatable */
extern int __init fsw_init(void);
extern int fsw_disabled(void);
extern void *fsw_instance(unsigned int);
extern void fsw_reserve(long unsigned int, long unsigned int);
#else
static struct fsw_page *fsw_base = NULL;
static int __init fsw_init(void) { return 0; }
static int fsw_disabled(void) { return 1; }
static void *fsw_instance(unsigned int) { return NULL; }
static void fsw_reserve(long unsigned int, long unsigned int) {}
}
#endif
#endif

#endif
