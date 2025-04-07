#ifndef _MY_PROBE_IOCTL_H
#define _MY_PROBE_IOCTL_H

#include <linux/ioctl.h>

#define MY_PROBE_IOCTL_CMD  0xABCD

struct my_probe_args {
    void *start_addr;   // 用户态指针（虚拟地址）
    size_t size;        // 访问大小
};

#endif // _MY_PROBE_IOCTL_H
