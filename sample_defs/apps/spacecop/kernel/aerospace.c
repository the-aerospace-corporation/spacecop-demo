// Copyright © 2025 Aerospace Corporation
// Project Title: SpaceCop
// All rights reserved.
//
//This software is provided "as is" without any warranty of any, kind either express, implied, or statutory, including, but not
//limited to, any warranty that the software will conform to, specifications any implied warranties of merchantability, fitness
//for a particular purpose, and freedom from infringement, and any warranty that the documentation will conform to the program, or
//any warranty that the software will be error free.
//
//In no event shall the Aerospace Corporation be liable for any damages, including, but not limited to direct, indirect, special or consequential damages,
//arising out of, resulting from, or in any way connected with the software or its documentation.  Whether or not based upon warranty,
//contract, tort or otherwise, and whether or not loss was sustained from, or arose out of the results of, or use of, the software,
//documentation or services provided hereunder
//
// For any questions, please contact:
// Randi Tinney (randi.j.tinney@aero.org)
// Charles Tucker (charles.tucker@aero.org)

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>
#include <linux/uidgid.h>

#include <net/sock.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("rjt34234");
MODULE_DESCRIPTION("Kernel module for SpaceCOP - Multi-architecture");
MODULE_VERSION("1.0");

// Architecture detection
#if defined(__x86_64__) || defined(__amd64__)
    #define ARCH_X86_64
    #define ARCH_NAME "x86_64"
#elif defined(__arm__) || defined(__aarch32__)
    #define ARCH_ARM32
    #define ARCH_NAME "ARM32"
#elif defined(__aarch64__)
    #define ARCH_ARM64
    #define ARCH_NAME "ARM64"
#else
    #warning "Unknown architecture - defaulting to generic"
    #define ARCH_GENERIC
    #define ARCH_NAME "Generic"
#endif

unsigned long **syscall_table;

#define MAX_FILENAME_LEN 256
#define NETLINK_USER 31
#define MAX_MSG_LEN 1024

static struct sock *nl_sk = NULL;
static int user_pid = -1;

// Helper macros for register access
#ifdef ARCH_X86_64
    #define GET_REG_ARG0(regs) ((regs)->di)
    #define GET_REG_ARG1(regs) ((regs)->si)
    #define GET_REG_ARG2(regs) ((regs)->dx)
    #define GET_REG_ARG3(regs) ((regs)->r10)
#elif defined(ARCH_ARM32)
    #define GET_REG_ARG0(regs) ((regs)->ARM_r0)
    #define GET_REG_ARG1(regs) ((regs)->ARM_r1)
    #define GET_REG_ARG2(regs) ((regs)->ARM_r2)
    #define GET_REG_ARG3(regs) ((regs)->ARM_r3)
#elif defined(ARCH_ARM64)
    #define GET_REG_ARG0(regs) ((regs)->regs[0])
    #define GET_REG_ARG1(regs) ((regs)->regs[1])
    #define GET_REG_ARG2(regs) ((regs)->regs[2])
    #define GET_REG_ARG3(regs) ((regs)->regs[3])
#else
    #error "Unsupported architecture"
#endif

static void netlink_recv_msg(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	char *received_msg;

	nlh = (struct nlmsghdr *)skb->data;
	received_msg = (char *)nlmsg_data(nlh);
	user_pid = nlh->nlmsg_pid;

	printk(KERN_INFO "[SPACECOP] Kernel received message: %s\n", received_msg);
	printk(KERN_INFO "[SPACECOP] User-space server PID saved: %d\n", user_pid);
}

static void send_netlink_msg(const char *buf)
{
	struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
    int res;

    if(user_pid < 0)
    {
    	printk(KERN_ERR "[SPACECOP] User-space server PID is not set.\n");
    	return;
    }

    skb_out = nlmsg_new(strlen(buf), 0);
    if(!skb_out)
    {
        printk(KERN_ERR "[SPACECOP] Error allocating memory for netlink socket.\n");
        return;
    }
   
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, strlen(buf), 0);
    
    if(!nlh)
    {
    	kfree_skb(skb_out);
    	printk(KERN_ERR "[SPACECOP] Failed to allocate skb\n");
    	return;
    }

	strscpy(nlmsg_data(nlh), buf, strlen(buf) + 1);
    res = nlmsg_unicast(nl_sk, skb_out, user_pid); 
    if(res < 0)
    {
        pr_info("[%s] Error sending msg to userspace: %d\n", THIS_MODULE->name, res);
    }
    else
    {
        pr_debug("[%s] Sent message to userspace\n", THIS_MODULE->name);
    }
}

// For fchmodat: arg0=dirfd, arg1=filename, arg2=mode
static int chmod_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	char kfile[256];
	char msg[1024];
	unsigned long filename_ptr;

#ifdef ARCH_X86_64
	struct pt_regs *user_regs = task_pt_regs(current);
	filename_ptr = GET_REG_ARG1(user_regs);
#else
	filename_ptr = GET_REG_ARG1(regs);
#endif

	if(filename_ptr)
	{
		if (strncpy_from_user(kfile, (char __user *)filename_ptr, sizeof(kfile)) > 0) {
            kfile[sizeof(kfile) - 1] = '\0';  
            printk(KERN_INFO "[SPACECOP]\tSyscall %s called with filename: %s \n", p->symbol_name, kfile);
            snprintf(msg, sizeof(msg), "Syscall %s called with filename: %s \n", p->symbol_name, kfile);
        } 
        else
        {
        	printk(KERN_INFO "[SPACECOP]\tSyscall %s called \n", p->symbol_name);
        	snprintf(msg, sizeof(msg), "Syscall %s called\n", p->symbol_name);
        }

        msg[sizeof(msg)-1] = '\0';
        send_netlink_msg(msg);
	}

	return 0;
}

// Generic syscall handler
static int syscall_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	char kfile[256];
	char msg[1024];
	unsigned long filename_ptr;

#ifdef ARCH_X86_64
	struct pt_regs *user_regs = task_pt_regs(current);
	filename_ptr = GET_REG_ARG1(user_regs);
#else
	filename_ptr = GET_REG_ARG1(regs);
#endif

	if(filename_ptr)
	{
		if (strncpy_from_user(kfile, (char __user *)filename_ptr, sizeof(kfile)) > 0) {
            kfile[sizeof(kfile) - 1] = '\0';  
            printk(KERN_INFO "[SPACECOP]\tSyscall %s called with filename: %s \n", p->symbol_name, kfile);
            snprintf(msg, sizeof(msg), "Syscall %s called with filename: %s \n", p->symbol_name, kfile);	
        } 
        else
        {
        	printk(KERN_INFO "[SPACECOP]\tSyscall %s called \n", p->symbol_name);
        	snprintf(msg, sizeof(msg), "Syscall %s called\n", p->symbol_name);
        }

        msg[sizeof(msg)-1] = '\0';
        send_netlink_msg(msg);
	}

	return 0;
}

// For init_module: arg0 contains the module image pointer
static int init_module_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    char msg[1024];
    unsigned long module_ptr;

#ifdef ARCH_X86_64
    struct pt_regs *user_regs = task_pt_regs(current);
    module_ptr = GET_REG_ARG0(user_regs);
#else
    module_ptr = GET_REG_ARG0(regs);
#endif

    printk(KERN_INFO "[SPACECOP]\tINIT_MODULE called\n");
    snprintf(msg, sizeof(msg), "INIT_MODULE called (module addr: 0x%lx)\n", module_ptr);

    msg[sizeof(msg)-1] = '\0';
    send_netlink_msg(msg);

    return 0;
}

// For execve: arg0 contains the program path
static int execve_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	char kfile[256];
	char msg[1024];
	unsigned long filename_ptr;

#ifdef ARCH_X86_64
	struct pt_regs *user_regs = task_pt_regs(current);
	filename_ptr = GET_REG_ARG0(user_regs);
#else
	filename_ptr = GET_REG_ARG0(regs);
#endif

	if(filename_ptr)
	{
		if (strncpy_from_user(kfile, (char __user *)filename_ptr, sizeof(kfile)) > 0) {
            kfile[sizeof(kfile) - 1] = '\0';  
            printk(KERN_INFO "[SPACECOP]\tSyscall %s called with program: %s \n", p->symbol_name, kfile);	
            snprintf(msg, sizeof(msg), "Syscall %s called with program: %s \n", p->symbol_name, kfile);
        } 
        else
        {
        	printk(KERN_INFO "[SPACECOP]\tSyscall %s called \n", p->symbol_name);
        	snprintf(msg, sizeof(msg), "Syscall %s called\n", p->symbol_name);
        }
        msg[sizeof(msg)-1] = '\0';
        send_netlink_msg(msg);
	}

	return 0;
}

// For openat: arg0=dirfd, arg1=filename, arg2=flags, arg3=mode
static int open_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	char kfile[256];
	char msg[1024];
	int should_log = 0;
	unsigned long filename_ptr;

#ifdef ARCH_X86_64
	struct pt_regs *user_regs = task_pt_regs(current);
	filename_ptr = GET_REG_ARG1(user_regs);
#else
	filename_ptr = GET_REG_ARG1(regs);
#endif

	if(filename_ptr)
	{
		if (strncpy_from_user(kfile, (char __user *)filename_ptr, sizeof(kfile)) > 0) {
            kfile[sizeof(kfile) - 1] = '\0';  
            
            // Check if it's a device we care about
            if(strncmp(kfile, "/dev/mtdblock", 13) == 0 ||
               strncmp(kfile, "/dev/mtd", 8) == 0 ||
               strcmp(kfile, "/dev/zero") == 0 ||
               strcmp(kfile, "/dev/null") == 0 ||
               strcmp(kfile, "/null") == 0)
	        {
	        	should_log = 1;
	        	printk(KERN_INFO "[SPACECOP]\topenat called with filename: %s \n",  kfile);
            	snprintf(msg, sizeof(msg), "openat called with filename: %s \n", kfile);
	        }
        } 

        if(should_log)
        {
        	msg[sizeof(msg)-1] = '\0';
        	send_netlink_msg(msg);
        }
	}

	return 0;
}

// Define kprobes with NULL symbol_name initially (will be set during init)
static struct kprobe execve_kp = {
	.pre_handler = execve_pre_handler,
};

static struct kprobe read_kp = {
	.pre_handler = syscall_pre_handler,
};

static struct kprobe open_kp = {
	.pre_handler = open_pre_handler,
};

static struct kprobe chmod_kp = {
	.pre_handler = chmod_pre_handler,
};

static struct kprobe init_module_kp = {
    .pre_handler = init_module_pre_handler,
};

// Helper function to try registering with multiple symbol names
static int try_register_kprobe(struct kprobe *kp, const char *names[], int count, const char *desc)
{
	int i, ret;
	
	for(i = 0; i < count; i++)
	{
		kp->symbol_name = names[i];
		ret = register_kprobe(kp);
		if(ret == 0)
		{
			printk(KERN_INFO "[SPACECOP] Kprobe for %s registered with symbol: %s\n", desc, names[i]);
			return 0;
		}
		printk(KERN_DEBUG "[SPACECOP] Failed to register %s with symbol %s: %d\n", desc, names[i], ret);
	}
	
	printk(KERN_ERR "[SPACECOP] Failed to register %s kprobe with any known symbol\n", desc);
	return ret;
}

static int __init monitor_init(void)
{
	int ret;
	
	// Architecture-specific syscall symbol names
#ifdef ARCH_X86_64
	const char *open_symbols[] = {
		"__x64_sys_openat",
		"sys_openat",
		"__se_sys_openat"
	};
	const char *execve_symbols[] = {
		"__x64_sys_execve",
		"sys_execve",
		"__se_sys_execve"
	};
	const char *chmod_symbols[] = {
		"__x64_sys_fchmodat",
		"sys_fchmodat",
		"__se_sys_fchmodat"
	};
	const char *init_symbols[] = {
		"__x64_sys_init_module",
		"sys_init_module",
		"__se_sys_init_module"
	};
#elif defined(ARCH_ARM32)
	const char *open_symbols[] = {
		"sys_openat",
		"__arm_sys_openat",
		"__se_sys_openat",
		"ksys_openat",
		"do_sys_openat2",
		"do_sys_open"
	};
	const char *execve_symbols[] = {
		"sys_execve",
		"__arm_sys_execve",
		"__se_sys_execve"
	};
	const char *chmod_symbols[] = {
		"sys_fchmodat",
		"__arm_sys_fchmodat",
		"__se_sys_fchmodat"
	};
	const char *init_symbols[] = {
		"sys_init_module",
		"__arm_sys_init_module",
		"__se_sys_init_module"
	};
#elif defined(ARCH_ARM64)
	const char *open_symbols[] = {
		"__arm64_sys_openat",
		"sys_openat",
		"__se_sys_openat"
	};
	const char *execve_symbols[] = {
		"__arm64_sys_execve",
		"sys_execve",
		"__se_sys_execve"
	};
	const char *chmod_symbols[] = {
		"__arm64_sys_fchmodat",
		"sys_fchmodat",
		"__se_sys_fchmodat"
	};
	const char *init_symbols[] = {
		"__arm64_sys_init_module",
		"sys_init_module",
		"__se_sys_init_module"
	};
#else
	#error "Unsupported architecture"
#endif

	struct netlink_kernel_cfg cfg = { 
		.input = netlink_recv_msg,
	};

	printk(KERN_INFO "[SPACECOP] Initializing module for %s...\n", ARCH_NAME);

	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
	if(!nl_sk)
	{
		printk(KERN_ERR "[SPACECOP] netlink error: Failed to create netlink socket\n");
		return -ENOMEM;
	}
	printk(KERN_INFO "[SPACECOP] Netlink socket created\n");

	ret = try_register_kprobe(&open_kp, open_symbols, 
	                          sizeof(open_symbols)/sizeof(open_symbols[0]), "openat");
	if(ret < 0)
	{
		printk(KERN_ERR "[SPACECOP] Could not find openat syscall. Available symbols:\n");
		printk(KERN_ERR "[SPACECOP] Check: cat /proc/kallsyms | grep openat\n");
		netlink_kernel_release(nl_sk);
		return ret;
	}

    ret = try_register_kprobe(&init_module_kp, init_symbols,
                              sizeof(init_symbols)/sizeof(init_symbols[0]), "init_module");
    if(ret < 0)
    {
        printk(KERN_WARNING "[SPACECOP] Failed to register init_module (non-critical)\n");
        // Don't fail - this is optional
    }

	ret = try_register_kprobe(&execve_kp, execve_symbols,
	                          sizeof(execve_symbols)/sizeof(execve_symbols[0]), "execve");
	if(ret < 0)
	{
		printk(KERN_ERR "[SPACECOP] Failed to register execve\n");
		unregister_kprobe(&open_kp);
		if(init_module_kp.symbol_name)
			unregister_kprobe(&init_module_kp);
		netlink_kernel_release(nl_sk);
		return ret;
	}

	ret = try_register_kprobe(&chmod_kp, chmod_symbols,
	                          sizeof(chmod_symbols)/sizeof(chmod_symbols[0]), "fchmodat");
	if(ret < 0)
	{
		printk(KERN_WARNING "[SPACECOP] Failed to register chmod (non-critical)\n");
		// Don't fail - this is optional
	}

	printk(KERN_INFO "[SPACECOP] *** Module loaded successfully for %s ***\n", ARCH_NAME);
	printk(KERN_INFO "[SPACECOP] Monitoring: execve, openat, fchmodat, init_module\n");
	return 0;
}

static void __exit monitor_exit(void)
{
	if(execve_kp.symbol_name)
		unregister_kprobe(&execve_kp);
	if(open_kp.symbol_name)
		unregister_kprobe(&open_kp);
	if(chmod_kp.symbol_name)
		unregister_kprobe(&chmod_kp);
	if(init_module_kp.symbol_name)
		unregister_kprobe(&init_module_kp);

	if(nl_sk)
		netlink_kernel_release(nl_sk);

	printk(KERN_INFO "[SPACECOP] Kernel module unloaded\n");
}

module_init(monitor_init);
module_exit(monitor_exit);
