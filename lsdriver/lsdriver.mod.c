#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

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
	{ 0x7c24b32d, "module_layout" },
	{ 0xdcb764ad, "memset" },
	{ 0x4829a47e, "memcpy" },
	{ 0x23f6655a, "failure_tracking" },
	{ 0xacfe4142, "page_pinner_inited" },
	{ 0xaf56600a, "arm64_use_ng_mappings" },
	{ 0xb1307de2, "init_task" },
	{ 0x8900b200, "kmalloc_caches" },
	{ 0xec2fc692, "cpu_hwcap_keys" },
	{ 0x14b89635, "arm64_const_caps_ready" },
	{ 0x9688de8b, "memstart_addr" },
	{ 0x9b2b597c, "sysfs_remove_link" },
	{ 0xf524bddc, "kobject_del" },
	{ 0x4d9b652b, "rb_erase" },
	{ 0xe1537255, "__list_del_entry_valid" },
	{ 0x12a38747, "usleep_range" },
	{ 0x336a06, "__page_pinner_migration_failed" },
	{ 0x1022e36e, "__put_page" },
	{ 0xf9a482f9, "msleep" },
	{ 0x1270d593, "vmap" },
	{ 0x8151d0b3, "get_user_pages_remote" },
	{ 0xe2d5255a, "strcmp" },
	{ 0xa4304a36, "wake_up_process" },
	{ 0xd9aa98a4, "kthread_create_on_node" },
	{ 0x2469810f, "__rcu_read_unlock" },
	{ 0x8d522714, "__rcu_read_lock" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0xb38391e9, "kmem_cache_alloc_trace" },
	{ 0x296695f, "refcount_warn_saturate" },
	{ 0x9a80f9a6, "__put_task_struct" },
	{ 0x6b50e951, "up_read" },
	{ 0x3355da1c, "down_read" },
	{ 0x88f5cdef, "down_read_trylock" },
	{ 0x3b938c8d, "input_event" },
	{ 0xb2ef0fff, "input_mt_sync_frame" },
	{ 0x3fcaa46c, "input_mt_report_slot_state" },
	{ 0x18b23dc5, "unregister_kprobe" },
	{ 0xc502eb6d, "register_kprobe" },
	{ 0xb7c0f443, "sort" },
	{ 0xc5850110, "printk" },
	{ 0x2e72ceb5, "d_path" },
	{ 0x12aec6f2, "find_vpid" },
	{ 0x918779bc, "pid_task" },
	{ 0x349cba85, "strchr" },
	{ 0x2d39b0a7, "kstrdup" },
	{ 0x1e6d26a8, "strstr" },
	{ 0xa378a2f4, "get_task_mm" },
	{ 0xd3c5d4d0, "put_pid" },
	{ 0xd15a2984, "get_pid_task" },
	{ 0xdca62649, "find_get_pid" },
	{ 0x825a3481, "mmput" },
	{ 0x51e77c97, "pfn_valid" },
	{ 0x999e8297, "vfree" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0x37a0cba, "kfree" },
	{ 0x837ac1f4, "input_set_abs_params" },
	{ 0xbc44cef7, "put_device" },
	{ 0x54f79951, "get_device" },
	{ 0xd2b0e789, "class_for_each_device" },
	{ 0xe8b268ae, "mutex_unlock" },
	{ 0xeb9065d9, "mutex_lock" },
};

MODULE_INFO(depends, "");

