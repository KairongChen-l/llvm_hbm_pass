#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>  // copy_from_user
#include "my_probe_ioctl.h"

#define MYDEV_NAME "my_probe_dev"

static dev_t dev_num;
static struct cdev my_cdev;

// ioctl 函数
static long my_probe_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
    case MY_PROBE_IOCTL_CMD: {
        // 从用户态复制结构体
        struct my_probe_args kargs;
        if (copy_from_user(&kargs, (struct my_probe_args __user *)arg, sizeof(kargs))) {
            pr_err("copy_from_user failed.\n");
            return -EFAULT;
        }

        // 这里拿到传进来的“起始地址 + 大小”
        pr_info("[my_probe] start_addr=%p, size=%zu\n", kargs.start_addr, kargs.size);

        //TODO 需要做的处理
        


        break;
    }
    default:
        return -EINVAL;
    }
    return 0;
}

// 文件操作集
static const struct file_operations my_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = my_probe_ioctl, // 对应用户态的 ioctl 调用
};

// 模块加载
static int __init my_probe_init(void)
{
    int ret;

    // 分配主从设备号
    ret = alloc_chrdev_region(&dev_num, 0, 1, MYDEV_NAME);
    if (ret < 0) {
        pr_err("alloc_chrdev_region failed\n");
        return ret;
    }

    // 初始化 cdev
    cdev_init(&my_cdev, &my_fops);
    ret = cdev_add(&my_cdev, dev_num, 1);
    if (ret < 0) {
        pr_err("cdev_add failed\n");
        unregister_chrdev_region(dev_num, 1);
        return ret;
    }

    pr_info("my_probe driver loaded\n");
    return 0;
}

// 模块卸载
static void __exit my_probe_exit(void)
{
    cdev_del(&my_cdev);
    unregister_chrdev_region(dev_num, 1);
    pr_info("my_probe driver unloaded\n");
}

module_init(my_probe_init);
module_exit(my_probe_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("YourName");
MODULE_DESCRIPTION("A simple kernel module for capturing memory probe info from user space.");
