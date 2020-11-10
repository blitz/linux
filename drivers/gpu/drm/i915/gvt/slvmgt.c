/* Copyright Cyberus Technology GmbH *
 *        All rights reserved        */

/* SPDX-License-Identifier: GPL-2.0  */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cyberus Technology GmbH");
MODULE_DESCRIPTION("SuperNOVA Linux Virtualization Module GVT-g Support");

/*
 * MODULE LIFECYCLE
 */

static int __init slvmgt_init(void)
{
	return 0;
}

static void __exit slvmgt_cleanup(void)
{
}

module_init(slvmgt_init);
module_exit(slvmgt_cleanup);
