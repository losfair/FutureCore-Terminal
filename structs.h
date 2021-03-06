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
    u32 max_cycles;
};

struct __attribute__((aligned(4))) DataPacket {
    u32 id;
    u32 type;
};

struct __attribute__((aligned(4))) GPIOReadResponse {
    u32 val;
};

struct __attribute__((aligned(4))) CodeExecResponse {
    u32 regs[16];
};

struct __attribute__((aligned(4))) GetDeviceStatusResponse {
    u16 running_vms;
    u16 active_vms;
    u16 max_vms;
};

struct __attribute__((aligned(4))) ResetVMsResponse {
    u16 affected_vms;
};

struct Context {
    int state;
    char *key;

    const char *terminal_id;
    const char *signing_key;
    const char *encryption_key;
    u8 current_key[16];
    u8 server_key[16];

    u32 alive_count;

    hypercall_tick_fn hypercalls[256];

    struct VM *vms[MAX_VMS];

    malloc_fn malloc;
    free_fn free;
    secure_random_fn secure_random;

    gpio_read_fn gpio_read;
    gpio_write_fn gpio_write;
    gpio_set_pin_mode_fn gpio_set_pin_mode;

    net_write_fn net_write;
    void *net_write_param;
};

struct VM {
    struct Context *ctx;
    u32 task_id;
    u8 mode;
    u8 error;

    u32 code_begin;
    u32 code_end;
    u32 stack_begin;
    u32 stack_end;

    u32 current_cycles;
    u32 max_cycles;

    size_t code_size;
    size_t stack_size;
    u32 regs[16];

    u8 *code;
    u8 *stack;
    //u8 *mem;
    u32 ip;
    u32 sp;

    u8 runnable;

    hypercall_tick_fn hypercall_tick;
    char *hypercall_state;
};

#endif