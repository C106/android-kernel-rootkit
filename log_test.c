#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/smp.h>

static void log_test_emit(const char *phase)
{
    console_verbose();
    printk_deferred(KERN_EMERG "[lk1337-log-test] %s cpu=%u module=%p\n",
                    phase, raw_smp_processor_id(), THIS_MODULE);
}

static int __init lk1337_log_test_init(void)
{
    log_test_emit("init");
    printk(KERN_ALERT "[lk1337-log-test] ALERT init\n");
    printk(KERN_ERR "[lk1337-log-test] ERR init\n");
    printk(KERN_WARNING "[lk1337-log-test] WARNING init\n");
    printk(KERN_INFO "[lk1337-log-test] INFO init\n");
    pr_notice("[lk1337-log-test] NOTICE init\n");
    return 0;
}

static void __exit lk1337_log_test_exit(void)
{
    log_test_emit("exit");
    printk(KERN_INFO "[lk1337-log-test] INFO exit\n");
}

module_init(lk1337_log_test_init);
module_exit(lk1337_log_test_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Minimal Android GKI printk diagnostic module");
MODULE_AUTHOR("LK1337");
