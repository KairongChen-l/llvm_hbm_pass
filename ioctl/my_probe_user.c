#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "my_probe_ioctl.h"  // 与内核共用的头文件, 定义了结构体和CMD宏

//首地址和大小传给内核
// 这里是用户态的函数，调用时传入要探测的内存地址和大小
void my_probe(void *start_addr, size_t size)
{
    int fd = open("/dev/my_probe_driver", O_RDWR);
    if (fd < 0) {
        perror("[my_probe] open failed");
        return;
    }

    struct my_probe_args args;
    args.start_addr = start_addr;
    args.size = size;

    if (ioctl(fd, MY_PROBE_IOCTL_CMD, &args) < 0) {
        perror("[my_probe] ioctl failed");
    }

    close(fd);
}
// 这里是一个简单的测试函数，实际使用时可以根据需要修改
void test_my_probe() {
    int *arr = (int *)malloc(100 * sizeof(int));
    if (!arr) {
        perror("malloc failed");
        return;
    }

    // 填充数组
    for (int i = 0; i < 100; i++) {
        arr[i] = i;
    }

    // 调用探测函数
    my_probe(arr, 100 * sizeof(int));

    free(arr);
}
int main(){
    test_my_probe();
    return 0;
}
