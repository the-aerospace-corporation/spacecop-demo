#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif


static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xb1ad28e0, "__gnu_mcount_nc" },
	{ 0x92997ed8, "_printk" },
	{ 0xefd6cf06, "__aeabi_unwind_cpp_pr0" },
	{ 0xb86758bf, "unregister_kprobe" },
	{ 0xf63825ff, "netlink_kernel_release" },
	{ 0x633cb2c6, "register_kprobe" },
	{ 0x5f754e5a, "memset" },
	{ 0x6bdf5570, "init_net" },
	{ 0xd481af3e, "__netlink_kernel_create" },
	{ 0x3ea1b6e4, "__stack_chk_fail" },
	{ 0x8f678b07, "__stack_chk_guard" },
	{ 0x97255bdf, "strlen" },
	{ 0x8526c5a3, "__alloc_skb" },
	{ 0xdb13f2dd, "kfree_skb_reason" },
	{ 0x739a12df, "__nlmsg_put" },
	{ 0xeea0399, "strscpy" },
	{ 0x472c0f19, "netlink_unicast" },
	{ 0x24428be5, "strncpy_from_user" },
	{ 0xc358aaf8, "snprintf" },
	{ 0x2e5810c6, "__aeabi_unwind_cpp_pr1" },
	{ 0xc84d16dc, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "9313D524836A1BCEA57B509");
