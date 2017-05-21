#ifndef _TERMINAL_CONTROL_STRUCTS_H_
#define _TERMINAL_CONTROL_STRUCTS_H_

#include "types.h"

struct __attribute__((aligned(4))) ControlPacket {
    u32 id;
    u32 type;
};

struct __attribute__((aligned(4))) GPIOReadRequest {
    u32 pin;
};

struct __attribute__((aligned(4))) CodeExecRequest {
    u32 len;
};

struct __attribute__((aligned(4))) DataPacket {
    u32 id;
    u32 type;
};

struct __attribute__((aligned(4))) GPIOReadResponse {
    u32 val;
};

struct __attribute__((aligned(4))) CodeExecResponse {
    u16 regs[16];
};

struct Context {
    int state;
    char *key;

    malloc_fn malloc;
    free_fn free;

    gpio_read_fn gpio_read;
    gpio_write_fn gpio_write;

    net_write_fn net_write;
    void *net_write_param;
};

#endif