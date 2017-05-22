#ifndef _TERMINAL_CONTROL_STRUCTS_H_
#define _TERMINAL_CONTROL_STRUCTS_H_

#include "types.h"
#include "constants.h"

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

    u32 alive_count;

    struct VM *vms[MAX_VMS];

    malloc_fn malloc;
    free_fn free;

    gpio_read_fn gpio_read;
    gpio_write_fn gpio_write;
    gpio_set_pin_mode_fn gpio_set_pin_mode;

    net_write_fn net_write;
    void *net_write_param;
};

struct VM {
    struct Context *ctx;
    u32 task_id;
    
    size_t mem_size;
    u16 regs[16];
    u8 *mem;
    u8 *ip;
};

#endif