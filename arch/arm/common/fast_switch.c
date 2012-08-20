/*
 * arch/arm/common/fast_switch.c
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

/* Notice : this code can pretty much be moved outside of arch folder */

#include <linux/io.h>
#include <linux/kobject.h>
#include <linux/suspend.h>
#include <linux/memblock.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/syscalls.h>

#include <asm-generic/mman-common.h>

#include <asm/setup.h>
#include <asm/uaccess.h>
#include <asm/fast_switch.h>

#if 0
const char *const fsw_modes[FSW_MODE_LAST] = {
	[FSW_MODE_BOOT]		= "boot",
	[FSW_MODE_SUSPEND]	= "suspend",
};
#endif

/* Virtual address of the fsw page */
struct fsw_page *fsw_base = NULL;

static bool fsw_reserve_enable = true;

/* Remove from memory */
static int __init fsw_init_block(void)
{
	/* regardless of the address of fsw_base, we try.
	   If it crash, then the value is not the one expected */
	memblock_remove(FSW_BASE, PAGE_SIZE);
	pr_info("Fastswitch: removing fsw_base\n");
	return 0;
}
early_initcall(fsw_init_block);

/* The master kernel may need to reserve memory ranges susceptible to be rewritten
 * by bootloader */
void fsw_reserve(long unsigned int start, long unsigned int size)
{
	if (!fsw_reserve_enable)
		return;

	if (memblock_is_region_reserved(start,size) | memblock_reserve(start,size)) {
		pr_err("Fastswitch: failed to reserve memory [0x%lx+0x%lx]\n", start, size);
		return;
	}
	pr_info("Fastswitch: reserved memory [0x%lx+0x%lx]\n", start, size);
}

/* If kernel is a child instance, memory reserve is not necessary.
 * May also be used if we explicitely don't want to use fastswitch.
 * Set fsw_no_reserve in boot parameters */
static int __init fsw_skip_reserve(char *str)
{
	fsw_reserve_enable = false;
	return 1;
}
early_param("fsw_no_reserve", fsw_skip_reserve);

/* to use only after fsw_init() has been called
   disabled means fsw_base has no valid value and should not be used */
int fsw_disabled(void)
{
	return (fsw_base == NULL);
}

/* to get the address of an instance parameter */
void *fsw_instance(unsigned int instance)
{
	return ((void *)fsw_base) + (instance<<FSW_INST_SHIFT);
}


#ifndef CONFIG_ATAGS_PROC
/* arbitrary: it is half of what atags.c specify as the maximum. The real(?) maximum
   overlaps with the first instance parameters. This can be resolved by raising
   FSW_INST_SHIFT (and possibly the size of fsw_page) */
#define BOOT_PARAMS_SIZE 768
/* This one is arm specific, we know it is atags (struct tag) */
static char boot_params[BOOT_PARAMS_SIZE];
/* (Fastswitch) Called in early arch init. We can not save atags directly
   into fsw_page, as we still don't know if it exist nor allocated. */
void save_atags(struct tag *tags)
{
	memcpy(&boot_params, tags, sizeof(boot_params));
	pr_info("Fastswitch: atags successfully retrieved\n");
}
#endif

/* Write the boot tags inside fsw_page, must be called after boot_params has been filled */
/* Note: this one is specific for arm, part of the code copied from atags.c */
static void fsw_write_boot(unsigned int *size, void *start)
{
#ifdef CONFIG_ATAGS_PROC
	pr_info("Fastswitch: atags retrieval not implemented, see /proc/atags\n");
#else
	struct tag *tag = (void *) boot_params;
	/* Detect the boundaries of the tag; We don't want unwanted data to be copied */
	if (tag->hdr.tag != ATAG_CORE) {
		pr_info("Fastswitch: no atags identified\n");
		*size = 0;
		return;
	}

	for (; tag->hdr.size; tag = tag_next(tag))
		;
	/* Include the ATAG_NONE size */
	*size = (char *)tag - boot_params + sizeof(struct tag_header);

	memcpy(start, &boot_params, *size);
	pr_info("Fastswitch: atags registered to 0x%p+0x%x\n", start, *size);
#endif
}

#if 0
static int __init fsw_base_detect(char *str)
{
	unsigned long start;
	char *end = NULL;

	/* No arg provided, skip */
	if (!str)
		goto empty;
	start = memparse(str, &end);
	if (str == end) {
empty:
		pr_info("Fastswitch: provided fsw_phys empty, ignoring\n");
		return -1;
	}

	if (start) {
		pr_info("Fastswitch: provided fsw_phys [0x%lx]\n", start);
		fsw_phys_base = start;
	}
	else
		pr_info("Fastswitch: could not identify fsw_phys: %s\n", str);

	return -1;
}
early_param("fsw_phys", fsw_base_detect);
#endif

/* Debugfs interface configuration */
enum {
	FSW_READ_STATUS = 0,
	FSW_READ_ARM_ATAG,
	FSW_READ_TEST,
	FSW_WRITE_LOAD_FILE,
	FSW_WRITE_SWITCH,
};

/* "read" actions */
static int fsw_read_status(struct seq_file *s, void *unused)
{
	void __iomem *fsw_inst_base = NULL;
	unsigned int i;
	long unsigned int val;

	if (fsw_disabled()) {
		seq_printf(s, "Disabled\n");
		return 0;
	}

	seq_printf(s, "Current instance: %d\n", fsw_base->current_instance);

	fsw_inst_base = fsw_instance(fsw_base->current_instance);
	for_each_present_cpu(i) {
		/* TODO replace with a proper memory read, we are not doing IO */
		val = __raw_readl(fsw_inst_base + FSW_INST_JUMP + i*4);
		seq_printf(s, "Resume address (core %d): [0x%lx] 0x%lx\n", i,
			   val, __phys_to_virt(val));
	}

	seq_printf(s, "Boot parameters size: 0x%x\n", fsw_base->boot_psize);

	return 0;
}
static int fsw_read_atag(struct seq_file *s, void *unused)
{
	unsigned long size = fsw_base->boot_psize;
	int i;
	if (fsw_disabled()) {
		seq_printf(s, "Disabled\n");
		return 0;
	}
	/* We can not show the full atag as a string because \0 is likely to appear.
	   Therefore, we must print it char by char */
	for (i = 0; i < size; i++)
		seq_printf(s, "%c", *((char *) &fsw_base->boot_pparam + i));
	return 0;
}
static int fsw_read_test(struct seq_file *s, void *unused)
{
	if (fsw_disabled()) {
		seq_printf(s, "Disabled\n");
		return 0;
	}
	seq_printf(s, "Reading memory\n");
	memblock_add(0x96000000, 0x4000000);
	return 0;
}

/* "write" actions */
static int fsw_write_load_image(const char *buf, size_t len)
{
	int ret, fd, err;
	mm_segment_t old_fs;
	struct stat file_sb;
	unsigned long target_phys_addr, file_addr;
	void *target_virt_addr, *target_inst_base;
	char *filename;
	char *nature; unsigned int target = 0;
	unsigned long capped_size;

	/* default return value */
	ret = len;

	filename = kmalloc(len, GFP_KERNEL);
	if (!filename) {
		pr_err("Fastswitch: [load] Could not malloc for %s\n", buf);
		return -ENOMEM;
	}
	nature = kmalloc(len, GFP_KERNEL);
	if (!nature) {
		pr_err("Fastswitch: [load] Could not malloc for %s\n", buf);
		goto cancel_malloc;
	}

	/* Temporary: the nature of the file is set as the third arg */
	if (sscanf(buf, "%lx %s %s %d", &target_phys_addr, filename,
		   nature, &target) < 2) {
		pr_err("Fastswitch: [load] invalid values %s\n", buf);
		ret = -EINVAL;
		goto cancel_malloc2;
	}

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	/* TODO process error number instead */
	if ((err = sys_newstat(filename, &file_sb)) < 0) {
		pr_err("Fastswitch: [load] (stat) invalid file %s err %d\n", filename, err);
		ret = -EINVAL;
		goto cancel_fs;
	}
	/* file must be a regular readable file */
	if ((file_sb.st_mode & (S_IFREG | S_IRUSR)) != (S_IFREG | S_IRUSR)) {
		pr_err("Fastswitch: [load] (stat) not a file / bad permission %s\n", filename);
		ret = -EINVAL;
		goto cancel_fs;
	}
	if ((fd = sys_open(filename, O_RDONLY, 0)) < 0) {
		pr_err("Fastswitch: [load] (open) invalid file %s err %d\n", filename, fd);
		ret = -EINVAL;
		goto cancel_fs;
	}

	/* mappings */
	file_addr = sys_mmap_pgoff(0, file_sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file_addr == -1) {
		pr_err("Fastswitch: [load] could not mmap %s\n", filename);
		ret = -ENOMEM;
		goto cancel_open;
	}
	pr_info("Fastswitch: [load] %s at 0x%lx+(0x%lx)\n",
		filename, file_addr, file_sb.st_size);

	/* the target mapping should map full pages */
	/* Choice: we ignore what there is before target_phys_addr,
	   but it should be '\0' until the next page. capped_size
	   should reflect the mapping size up to the next page */
	capped_size = (target_phys_addr + file_sb.st_size +
		       PAGE_SIZE - sizeof(unsigned long)) & PAGE_MASK;
	capped_size = capped_size - target_phys_addr;

	/* TODO there is still the problem of knowing if provided address
	   respects the memory boundaries... */
	/* purists might not like this physical remapping */
	target_virt_addr = ioremap(target_phys_addr, capped_size);
	if (!target_virt_addr) {
		pr_err("Fastswitch: [load] failed to mmap address 0x%lx\n", target_phys_addr);
		ret = -EINVAL;
		goto cancel_mmap;
	}
	pr_info("Fastswitch: [load] addr 0x%lx mapped to 0x%p+(0x%lx)\n",
		target_phys_addr, target_virt_addr, capped_size);

	/* Erase target zone, because data until the end of the last page
	   belongs to the copied image */
	memset(target_virt_addr, '\0', capped_size);

	/* Copy */
	/* it is likely that they don't overlap...
	   remember that the target memory should be reserved? */
	memcpy(target_virt_addr, (void *) file_addr, file_sb.st_size);
	pr_info("Fastswitch: [load] copy successful to 0x%lx+(0x%lx)\n",
		target_phys_addr, capped_size);

	/* temporary : update fsw_base values */
	if (target <= FSW_INST_MAX) {
		target_inst_base = fsw_instance(target);
		if (strcmp(nature, "kernel") == 0)
		    __raw_writel(target_phys_addr, target_inst_base + FSW_INST_JUMP);
		if (strcmp(nature, "param") == 0)
		    __raw_writel(target_phys_addr, target_inst_base + FSW_INST_BOOT);
	}

	iounmap(target_virt_addr);
cancel_mmap:
	sys_munmap(file_addr, file_sb.st_size);
cancel_open:
	sys_close(fd);
cancel_fs:
	set_fs(old_fs);
cancel_malloc2:
	kfree(nature);
cancel_malloc:
	kfree(filename);
	return ret;
}
extern void request_suspend_state(suspend_state_t);
static int fsw_write_switch(const char *buf, size_t len)
{
	unsigned int mode, target;
	if (sscanf(buf, "%d %d", &mode, &target) == 2) {
		if (mode >= FSW_MODE_LAST || mode == 0) {
			pr_err("Fastswitch: [switch] invalid mode\n");
			return -EINVAL;
		}
		if (target > FSW_INST_MAX || target == 0) {
			pr_err("Fastswitch: [switch] invalid target\n");
			return -EINVAL;
		}

		fsw_base->switch_mode = mode;
		fsw_base->target_instance = target;

		/* Mode check to take action */
		if ((mode == FSW_MODE_SUSPEND) || (mode == FSW_MODE_BOOT)) {
			pr_info("Fastswitch: [switch] trying suspend\n");
			request_suspend_state(PM_SUSPEND_MEM);
			return len;
		}
	} else {
		pr_err("Fastswitch: [switch] <mode> <target>\n");
	}
	return -EINVAL;
}

/* On read operations, fsw_control_open is the procedure selector */
static int fsw_control_open(struct inode *inode, struct file *file)
{
	switch ((int)inode->i_private) {
	case FSW_READ_STATUS:
		return single_open(file, fsw_read_status, &inode->i_private);
	case FSW_READ_ARM_ATAG:
		return single_open(file, fsw_read_atag, &inode->i_private);
	case FSW_READ_TEST:
		return single_open(file, fsw_read_test, &inode->i_private);
	case FSW_WRITE_LOAD_FILE:
	case FSW_WRITE_SWITCH:
		file->private_data = inode->i_private;
		return nonseekable_open(inode, file);
	default:
		return 0;
	};
}
/* On write operations, fsw_control_write is the procedure selector */
static int fsw_control_write(struct file *file, const char __user *buf,
			  size_t len, loff_t *ppos)
{
	switch ((int) file->private_data) {
	case FSW_WRITE_LOAD_FILE:
		return fsw_write_load_image(buf, len);
	case FSW_WRITE_SWITCH:
		return fsw_write_switch(buf, len);
	default:
		return -EINVAL;
	}
}

static const struct file_operations fsw_control_read_fops = {
	.open = fsw_control_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
static const struct file_operations fsw_control_write_fops = {
	.open = fsw_control_open,
	.write = fsw_control_write,
	.llseek = generic_file_llseek,
};

/* Architecture independant initialization */
int __init fsw_init(void)
{
	int i;
	struct dentry *root;
#if 0
	/* setup fsw_base and fsw_phys_base */
	if (fsw_phys_base) {
		/* Notice : at this point, this mapping will succeed in any non
		   reserved/blocked memory. Any inapproriate mapping (in memory
		   used by running kernel or out of bound) may result in a crash */
		fsw_base = ioremap(fsw_phys_base, PAGE_SIZE);
		if (!fsw_base) {
			pr_err("Fastswitch: fsw_phys could not be mapped, aborting\n");
			return -1;
		}
	} else {
		/* (master branch) no fsw_phys_base has been provided, allocate one */
		fsw_base = kmalloc(PAGE_SIZE, GFP_KERNEL);

		if (!fsw_base) {
			pr_err("Fastswitch: failed to malloc Fastswitch page\n");
			fsw_base = NULL;
			return -1;
		}
		fsw_phys_base = __virt_to_phys((long unsigned int) fsw_base);
		/* memory is unclean, and we do comparison after */
		memset(fsw_base, '0', PAGE_SIZE);
		pr_info("Fastswitch: allocated fsw at %p [0x%lx] %p\n",
			fsw_base, fsw_phys_base, &fsw_phys_base);
	}
#else
	fsw_base = ioremap(FSW_BASE, PAGE_SIZE);
	if (!fsw_base) {
		pr_err("Fastswitch: failed to map Fastswitch page\n");
		fsw_base = NULL;
		return -ENXIO;
	}
#endif
	fsw_base->magic_tag 		= FSW_MAGIC_VALUE;

	/* detect the instance : a child instance is on MODE_BOOT */
	/* Assumption : memory should be empty on clean boot */
	if (fsw_base->switch_mode == FSW_MODE_BOOT) {
		if (fsw_base->target_instance > FSW_INST_MAX ||
		    fsw_base->target_instance == 0) {
			pr_info("Fastswitch: wrong id for current instance (%d)\n", 
				fsw_base->target_instance);
			fsw_base->target_instance = 0;
		} else {
			pr_info("Fastswitch: current instance is child (%d)\n", 
				fsw_base->target_instance);
			fsw_base->current_instance = fsw_base->target_instance;
		}
	} else {
		pr_info("Fastswitch: current instance is master (1)\n");
		fsw_base->current_instance = 1;
	}
	fsw_base->target_instance 	= 0;
	fsw_base->switch_mode		= FSW_MODE_NULL;
	fsw_base->skip_wakelock		= FSW_WAKELOCK_NOSKIP;

	/* clear any residual jump flags, TODO : one for each core */
	for_each_present_cpu(i) {
		fsw_base->allow_core[i] = 0;
	}

	/* Master instance should copy the boot parameters provided by bootloader */
	if (fsw_base->current_instance == 1) {
		fsw_write_boot(&fsw_base->boot_psize, &fsw_base->boot_pparam);
	}

	/* TODO need a policy about debugfs : whether should we show it if
	   fsw_base failed to be allocated */
	root = debugfs_create_dir("fsw", NULL);
	if (!root) {
		return -ENXIO;
	}
	debugfs_create_file("status", S_IRUGO, root,
			    (void *) FSW_READ_STATUS, &fsw_control_read_fops);
	debugfs_create_file("instance_atags", S_IRUGO, root,
			    (void *) FSW_READ_ARM_ATAG, &fsw_control_read_fops);
	debugfs_create_file("load_file", S_IWUGO, root,
			    (void *) FSW_WRITE_LOAD_FILE, &fsw_control_write_fops);
	debugfs_create_file("switch", S_IWUGO, root,
			    (void *) FSW_WRITE_SWITCH, &fsw_control_write_fops);
	debugfs_create_file("test", S_IRUGO, root,
			    (void *) FSW_READ_TEST, &fsw_control_read_fops);
	return 0;
}
