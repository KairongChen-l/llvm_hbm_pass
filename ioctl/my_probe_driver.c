#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>   // device_create, class_create 等
#include <linux/uaccess.h>
#include "my_probe_ioctl.h"

#define MYDEV_NAME "my_probe_dev"

static dev_t dev_num;
static struct cdev my_cdev;
static struct class *my_class;  // 用于自动创建设备节点

/**
 * @brief ioctl 处理函数
 */
static long my_probe_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
    case MY_PROBE_IOCTL_CMD: {
        struct my_probe_args kargs;
        // 从用户空间复制结构体
        if (copy_from_user(&kargs, (struct my_probe_args __user *)arg, sizeof(kargs))) {
            pr_err("my_probe: copy_from_user failed.\n");
            return -EFAULT;
        }
        // 在这里打印或处理传递来的地址与大小
        pr_info("[my_probe] start_addr=%p, size=%zu\n", kargs.start_addr, kargs.size);

        // TODO: 这里可以进行进一步的处理或记录
        break;
    }
    default:
        pr_err("my_probe: Invalid ioctl cmd=%u\n", cmd);
        return -EINVAL;
    }
    return 0;
}

static const struct file_operations my_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = my_probe_ioctl,
};

/**
 * @brief 模块加载函数
 */
static int __init my_probe_init(void)
{
    int ret;

    // 1. 分配主从设备号
    ret = alloc_chrdev_region(&dev_num, 0, 1, MYDEV_NAME);
    if (ret < 0) {
        pr_err("my_probe: alloc_chrdev_region failed, ret=%d\n", ret);
        return ret;
    }
    pr_info("my_probe: alloc_chrdev_region success. major=%d, minor=%d\n",
            MAJOR(dev_num), MINOR(dev_num));

    // 2. 初始化 cdev
    cdev_init(&my_cdev, &my_fops);
    ret = cdev_add(&my_cdev, dev_num, 1);
    if (ret < 0) {
        pr_err("my_probe: cdev_add failed, ret=%d\n", ret);
        unregister_chrdev_region(dev_num, 1);
        return ret;
    }
    pr_info("my_probe: cdev_add success.\n");

    // 3. 创建 class (供后续 device_create 使用)
    my_class = class_create(THIS_MODULE, "my_probe_class");
    if (IS_ERR(my_class)) {
        pr_err("my_probe: class_create failed, ret=%ld\n", PTR_ERR(my_class));
        cdev_del(&my_cdev);
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(my_class);
    }
    pr_info("my_probe: class_create success.\n");

    // 4. 创建设备节点 /dev/my_probe_dev
    if (!device_create(my_class, NULL, dev_num, NULL, MYDEV_NAME)) {
        pr_err("my_probe: device_create failed.\n");
        class_destroy(my_class);
        cdev_del(&my_cdev);
        unregister_chrdev_region(dev_num, 1);
        return -ENOMEM;
    }
    pr_info("my_probe: device_create success. /dev/%s is ready.\n", MYDEV_NAME);

    pr_info("my_probe driver loaded successfully.\n");
    return 0;
}

/**
 * @brief 模块卸载函数
 */
static void __exit my_probe_exit(void)
{
    pr_info("my_probe: unloading driver...\n");

    // 先销毁设备节点，再销毁类
    device_destroy(my_class, dev_num);
    class_destroy(my_class);

    // 删除 cdev，释放设备号
    cdev_del(&my_cdev);
    unregister_chrdev_region(dev_num, 1);

    pr_info("my_probe driver unloaded\n");
}

// 指定模块的初始化和卸载函数
module_init(my_probe_init);
module_exit(my_probe_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("YourName");
MODULE_DESCRIPTION("A simple kernel module for capturing memory probe info from user space.");
