/*
 * kernel/power/suspend.c - Suspend to RAM and standby functionality.
 *
 * Copyright (c) 2003 Patrick Mochel
 * Copyright (c) 2003 Open Source Development Lab
 * Copyright (c) 2009 Rafael J. Wysocki <rjw@sisk.pl>, Novell Inc.
 *
 * This file is released under the GPLv2.
 */

#include <linux/string.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/console.h>
#include <linux/cpu.h>
#include <linux/syscalls.h>
#include <linux/gfp.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/suspend.h>
#include <linux/syscore_ops.h>
#include <trace/events/power.h>

#ifdef CONFIG_FAST_SWITCH
#include <asm/fast_switch.h>
#include <linux/fs.h>
#endif
#include "power.h"

const char *const pm_states[PM_SUSPEND_MAX] = {
#ifdef CONFIG_EARLYSUSPEND
	[PM_SUSPEND_ON]		= "on",
#endif
	[PM_SUSPEND_STANDBY]	= "standby",
	[PM_SUSPEND_MEM]	= "mem",
};

static const struct platform_suspend_ops *suspend_ops;

/**
 *	suspend_set_ops - Set the global suspend method table.
 *	@ops:	Pointer to ops structure.
 */
void suspend_set_ops(const struct platform_suspend_ops *ops)
{
	mutex_lock(&pm_mutex);
	suspend_ops = ops;
	mutex_unlock(&pm_mutex);
}

bool valid_state(suspend_state_t state)
{
	/*
	 * All states need lowlevel support and need to be valid to the lowlevel
	 * implementation, no valid callback implies that none are valid.
	 */
	return suspend_ops && suspend_ops->valid && suspend_ops->valid(state);
}

/**
 * suspend_valid_only_mem - generic memory-only valid callback
 *
 * Platform drivers that implement mem suspend only and only need
 * to check for that in their .valid callback can use this instead
 * of rolling their own .valid callback.
 */
int suspend_valid_only_mem(suspend_state_t state)
{
	return state == PM_SUSPEND_MEM;
}

static int suspend_test(int level)
{
#ifdef CONFIG_PM_DEBUG
	if (pm_test_level == level) {
		printk(KERN_INFO "suspend debug: Waiting for 5 seconds.\n");
		mdelay(5000);
		return 1;
	}
#endif /* !CONFIG_PM_DEBUG */
	return 0;
}

/**
 *	suspend_prepare - Do prep work before entering low-power state.
 *
 *	This is common code that is called for each state that we're entering.
 *	Run suspend notifiers, allocate a console and stop all processes.
 */
static int suspend_prepare(void)
{
	int error;

	if (!suspend_ops || !suspend_ops->enter)
		return -EPERM;

	pm_prepare_console();

	error = pm_notifier_call_chain(PM_SUSPEND_PREPARE);
	if (error)
		goto Finish;

	error = usermodehelper_disable();
	if (error)
		goto Finish;

	error = suspend_freeze_processes();
	if (!error)
		return 0;

	suspend_thaw_processes();
	usermodehelper_enable();
 Finish:
	pm_notifier_call_chain(PM_POST_SUSPEND);
	pm_restore_console();
	return error;
}

/* default implementation */
void __attribute__ ((weak)) arch_suspend_disable_irqs(void)
{
	local_irq_disable();
}

/* default implementation */
void __attribute__ ((weak)) arch_suspend_enable_irqs(void)
{
	local_irq_enable();
}

/**
 *	suspend_enter - enter the desired system sleep state.
 *	@state:		state to enter
 *
 *	This function should be called after devices have been suspended.
 */
static int suspend_enter(suspend_state_t state)
{
	int error;

#ifdef CONFIG_FAST_SWITCH
	void __iomem *img_base = NULL;
	void __iomem *fsw_inst_base = NULL;
	int i;

	/* fsw_base should have been allocated at boot */
	if (fsw_disabled()) {
		pr_err("Fastswitch: failed to map Fast Switch page\n");
		goto endswitch;
	}

	/* Note: if fsw_base is defined, fsw is also */
	switch (fsw_base->switch_mode) {
	case FSW_MODE_BOOT:
		goto boot_mode;
	case FSW_MODE_SUSPEND:
		goto suspend_mode;
	default:
		pr_info("Fastswitch: no switch detected\n");
		goto skipswitch;
	}

boot_mode:
	/* Instance number must be specified correctly (2..MAX),
	   otherwise we can't retrieve a JUMP address */
	if ((fsw_base->target_instance > FSW_INST_MAX) ||
	    (fsw_base->target_instance <= 1)) {
		pr_err("Fastswitch: switch-booting mode, specify an instance number"
			 " (read %d)\n", fsw_base->target_instance);
		goto skipswitch;
	}

	fsw_inst_base = fsw_instance(fsw_base->target_instance);

	pr_info("Fastswitch: boot mode, instance %d (params at %p)\n",
		 fsw_base->target_instance, fsw_inst_base);

	/* FSW_INST_JUMP must be within the physical ram range, since we will want to
	   map it. TODO This is a hard limit that should be detected somewhere... */
	if (__raw_readl(fsw_inst_base + FSW_INST_JUMP) > 0xAC000000 ||
	    __raw_readl(fsw_inst_base + FSW_INST_JUMP) < 0x80000000) {
		pr_err("Fastswitch: zImage address [0x%08x] is out of limits\n",
			 __raw_readl(fsw_inst_base + FSW_INST_JUMP));
		__raw_writel(BLANK_VALUE, fsw_inst_base + FSW_INST_JUMP);
		goto skipswitch;
	}

	/* Apply a page mask before ioremap */
	//*(fsw_base + FSW_JUMP) = *(fsw_base + FSW_JUMP) & PAGE_MASK;

	/* image must be outside the active ram ? because ioremap doesn't work on ram.
	   mapping size should be higher than magic number offset 0x24, otherwise
	   can't check for magic number */
	img_base = ioremap(__raw_readl(fsw_inst_base + FSW_INST_JUMP), PAGE_SIZE);
	if (!img_base) {
		pr_err("Fastswitch: failed to map image at [0x%x]\n",
			 __raw_readl(fsw_inst_base + FSW_INST_JUMP));
		goto skipswitch;
	}

	/* detect magic number presence */
	/* TODO we are in architecture independant code. Ideally, this code should
	   not be there. */
	if (__raw_readl(img_base + ARM_ZIMAGE_MAGIC_OFFSET) != ARM_ZIMAGE_MAGIC) {
		pr_err("Fastswitch: Failed to find magic number for zImage [0x%08x]\n",
			 __raw_readl(fsw_inst_base + FSW_INST_JUMP));
		fsw_base->allow_core[0] = 0;
		goto skipswitch;
	}
	pr_info("Fastswitch: Found zImage at [0x%08x], ready to switch-boot\n",
		 __raw_readl(fsw_inst_base + FSW_INST_JUMP));
	fsw_base->allow_core[0] = FSW_FLAG_VALUE;

	goto endswitch;
suspend_mode:
       /* Instance number must be specified correctly (1..MAX), otherwise
	   we can't retrieve a jump address */
	if ((fsw_base->target_instance > FSW_INST_MAX) ||
	    (fsw_base->target_instance <= 0)) {
		pr_err("Fastswitch: switch-suspend mode, specify an instance number"
			 " (read %d)\n", fsw_base->target_instance);
		goto skipswitch;
	}

	fsw_inst_base = fsw_instance(fsw_base->target_instance);

	pr_info("Fastswitch: switch-suspend mode, boot instance %x (params at %p)\n",
		 fsw_base->target_instance, fsw_inst_base);

	/* FSW_INST_JUMP must be within the physical ram range. This is a hard
	   limit that should be detected somewhere... */
	/* TODO: make a check for every address */
	if (__raw_readl(fsw_inst_base + FSW_INST_JUMP) > 0xAC000000 ||
	    __raw_readl(fsw_inst_base + FSW_INST_JUMP) < 0x80000000) {
		pr_err("Fastswitch: core0 switch address [0x%08x] is out of limits\n",
			 __raw_readl(fsw_inst_base + FSW_INST_JUMP));
		__raw_writel(BLANK_VALUE, fsw_inst_base + FSW_INST_JUMP);
		goto skipswitch;
	}

	/* everything looks ok, jump */
	/* write one flag for every core */
	for_each_present_cpu(i) {
		fsw_base->allow_core[i] = FSW_FLAG_VALUE;
	}
	pr_info("Fastswitch: ready to switch-suspend to instance %d\n",
		fsw_base->target_instance);

	goto endswitch;

skipswitch:
	fsw_base->switch_mode = FSW_MODE_NULL;
endswitch:
	//if (fsw_base)
	//	iounmap(fsw_base);
	if (img_base)
		iounmap(img_base);
#endif

	if (suspend_ops->prepare) {
		error = suspend_ops->prepare();
		if (error)
			goto Platform_finish;
	}

	error = dpm_suspend_noirq(PMSG_SUSPEND);
	if (error) {
		printk(KERN_ERR "PM: Some devices failed to power down\n");
		goto Platform_finish;
	}

	if (suspend_ops->prepare_late) {
		error = suspend_ops->prepare_late();
		if (error)
			goto Platform_wake;
	}

	if (suspend_test(TEST_PLATFORM))
		goto Platform_wake;

	error = disable_nonboot_cpus();
	if (error || suspend_test(TEST_CPUS))
		goto Enable_cpus;

	arch_suspend_disable_irqs();
	BUG_ON(!irqs_disabled());

	error = syscore_suspend();
	if (!error) {
		if (!(suspend_test(TEST_CORE) || pm_wakeup_pending())) {
			error = suspend_ops->enter(state);
			events_check_enabled = false;
		}
		syscore_resume();
	}

	arch_suspend_enable_irqs();
	BUG_ON(irqs_disabled());

 Enable_cpus:
	enable_nonboot_cpus();

 Platform_wake:
	if (suspend_ops->wake)
		suspend_ops->wake();

	dpm_resume_noirq(PMSG_RESUME);

 Platform_finish:
	if (suspend_ops->finish)
		suspend_ops->finish();

#ifdef CONFIG_FAST_SWITCH
	//fsw_base = ioremap(FSW_BASE, PAGE_SIZE);
	if (fsw_base) {
		if (error) {
			pr_info("Fastswitch: suspend did not occur, cancelling\n");
			fsw_base->switch_mode 		= FSW_MODE_NULL;
			fsw_base->target_instance 	= 0;
			for_each_present_cpu(i) {
				fsw_base->allow_core[i] = 0;
			}
		} else if (fsw_base->switch_mode == FSW_MODE_SUSPEND) {
			/* Post switch-suspend processing */
			if (error) {
				pr_info("Fastswitch: resumed from instance %d"
					 " to instance %d\n", fsw_base->current_instance,
					 fsw_base->target_instance);
			} else {
				pr_info("Fastswitch: resumed from instance %d"
					 " to instance %d\n", fsw_base->current_instance,
					 fsw_base->target_instance);
			}
			fsw_base->current_instance = fsw_base->target_instance;
			fsw_base->target_instance = 0;
			fsw_base->switch_mode = FSW_MODE_NULL;

			/* notify that the device must go out of dormant state */
			request_suspend_state(PM_SUSPEND_ON);
		}
		//iounmap(fsw_base);
	}
	else
		pr_err("Fastswitch: failed to map Fast Switch page\n");
#endif
	return error;
}

/**
 *	suspend_devices_and_enter - suspend devices and enter the desired system
 *				    sleep state.
 *	@state:		  state to enter
 */
int suspend_devices_and_enter(suspend_state_t state)
{
	int error;

	if (!suspend_ops)
		return -ENOSYS;

	trace_machine_suspend(state);
	if (suspend_ops->begin) {
		error = suspend_ops->begin(state);
		if (error)
			goto Close;
	}
	suspend_console();
	suspend_test_start();
	error = dpm_suspend_start(PMSG_SUSPEND);
	if (error) {
		printk(KERN_ERR "PM: Some devices failed to suspend\n");
		goto Recover_platform;
	}
	suspend_test_finish("suspend devices");
	if (suspend_test(TEST_DEVICES))
		goto Recover_platform;

	error = suspend_enter(state);

 Resume_devices:
	suspend_test_start();
	dpm_resume_end(PMSG_RESUME);
	suspend_test_finish("resume devices");
	resume_console();
 Close:
	if (suspend_ops->end)
		suspend_ops->end();
	trace_machine_suspend(PWR_EVENT_EXIT);
	return error;

 Recover_platform:
	if (suspend_ops->recover)
		suspend_ops->recover();
	goto Resume_devices;
}

/**
 *	suspend_finish - Do final work before exiting suspend sequence.
 *
 *	Call platform code to clean up, restart processes, and free the
 *	console that we've allocated. This is not called for suspend-to-disk.
 */
static void suspend_finish(void)
{
	suspend_thaw_processes();
	usermodehelper_enable();
	pm_notifier_call_chain(PM_POST_SUSPEND);
	pm_restore_console();
}

/**
 *	enter_state - Do common work of entering low-power state.
 *	@state:		pm_state structure for state we're entering.
 *
 *	Make sure we're the only ones trying to enter a sleep state. Fail
 *	if someone has beat us to it, since we don't want anything weird to
 *	happen when we wake up.
 *	Then, do the setup for suspend, enter the state, and cleaup (after
 *	we've woken up).
 */
int enter_state(suspend_state_t state)
{
	int error;

	if (!valid_state(state))
		return -ENODEV;

	if (!mutex_trylock(&pm_mutex))
		return -EBUSY;

	printk(KERN_INFO "PM: Syncing filesystems ... ");
	sys_sync();
	printk("done.\n");

	pr_debug("PM: Preparing system for %s sleep\n", pm_states[state]);
	error = suspend_prepare();
	if (error)
		goto Unlock;

	if (suspend_test(TEST_FREEZER))
		goto Finish;

	pr_debug("PM: Entering %s sleep\n", pm_states[state]);
	pm_restrict_gfp_mask();
	error = suspend_devices_and_enter(state);
	pm_restore_gfp_mask();

 Finish:
	pr_debug("PM: Finishing wakeup.\n");
	suspend_finish();
 Unlock:
	mutex_unlock(&pm_mutex);
	return error;
}

/**
 *	pm_suspend - Externally visible function for suspending system.
 *	@state:		Enumerated value of state to enter.
 *
 *	Determine whether or not value is within range, get state
 *	structure, and enter (above).
 */
int pm_suspend(suspend_state_t state)
{
	if (state > PM_SUSPEND_ON && state <= PM_SUSPEND_MAX)
		return enter_state(state);
	return -EINVAL;
}
EXPORT_SYMBOL(pm_suspend);
