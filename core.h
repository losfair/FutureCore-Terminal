#ifndef _TERMINAL_CONTROL_CORE_H_
#define _TERMINAL_CONTROL_CORE_H_

#ifdef DEBUG
#include <stdio.h>
#endif

#include <stdlib.h>
#include <string.h>
#include "types.h"
#include "structs.h"
#include "constants.h"
#include "md5.h"
#include "vm.h"

/*static void memcpy(char *dest, char *src, size_t len) {
    int i;

    for(i = 0; i < len; i++) {
        dest[i] = src[i];
    }
}*/

static int send_data_packet(struct Context *ctx, u32 id, u32 type, char *data, size_t len) {

#ifdef TC_NO_DYNAMIC_MEMORY
    static char buf[sizeof(struct DataPacket) + 1024];
    if(len > 1024) {
        return -1;
    }
#else
    char *buf = ctx -> malloc(sizeof(struct DataPacket) + len);
#endif

    struct DataPacket header;
    header.id = id;
    header.type = type;

    memcpy(buf, (char *)&header, sizeof(struct DataPacket));
    memcpy(buf + sizeof(struct DataPacket), data, len);

    int ret = ctx -> net_write(ctx -> net_write_param, buf, sizeof(struct DataPacket) + len);

#ifndef TC_NO_DYNAMIC_MEMORY
    ctx -> free(buf);
#endif

    return ret;
}

static int control_gpio_read(struct Context *ctx, u32 id, char **raw_packet_ptr, size_t *len_ptr) {
    size_t len = *len_ptr;

    if(len < sizeof(struct GPIOReadRequest)) {
        return -1;
    }

    struct GPIOReadRequest *req = (struct GPIOReadRequest *) *raw_packet_ptr;

    *len_ptr -= sizeof(struct GPIOReadRequest);
    *raw_packet_ptr += sizeof(struct GPIOReadRequest);

    struct GPIOReadResponse resp;
    resp.val = ctx -> gpio_read(req -> pin);

    send_data_packet(ctx, id, DATA_GPIO_READ, (char *) &resp, sizeof(struct GPIOReadResponse));

    return 0;
}

static int control_code_exec(struct Context *ctx, u32 id, char **raw_packet_ptr, size_t *len_ptr) {
    int i;
    size_t len = *len_ptr;

    if(len < sizeof(struct CodeExecRequest)) {
        return -1;
    }

    struct CodeExecRequest *req = (struct CodeExecRequest *) *raw_packet_ptr;

    *len_ptr -= sizeof(struct CodeExecRequest);
    *raw_packet_ptr += sizeof(struct CodeExecRequest);
    len = *len_ptr;

    size_t code_len = req -> len;
    if(len < code_len) {
        return -1;
    }

    const u8 *code = (const u8 *) *raw_packet_ptr;

    *len_ptr -= code_len;
    *raw_packet_ptr += code_len;
    len = *len_ptr;

    struct VM vm;
    tc_vm_init(ctx, &vm, code_len);
    memcpy(vm.mem, code, code_len);

#ifdef DEBUG
    printf("Executing VM\n");
    printf("Code length: %u\n", code_len);
    printf("Bytecode: ");
    for(i = 0; i < code_len; i++) {
        printf("%.2x ", code[i]);
    }
    printf("\n");
#endif

    tc_vm_execute(&vm);

#ifdef DEBUG
    printf("VM execution done\n");
    printf("Registers:\n");
    for(i = 0; i < 16; i++) {
        printf("Register %d: %d\n", i, vm.regs[i]);
    }
#endif

    struct CodeExecResponse resp;
    memcpy(resp.regs, vm.regs, sizeof(u16) * 16);

    tc_vm_destroy(&vm);

#ifdef DEBUG
    printf("VM destroyed\n");
#endif

    send_data_packet(ctx, id, DATA_CODE_EXEC, (char *) &resp, sizeof(struct CodeExecResponse));

    return 0;
}

void tc_init(struct Context *ctx) {
    ctx -> state = 0;
    ctx -> key = NULL;
    ctx -> malloc = (malloc_fn) malloc;
    ctx -> free = (free_fn) free;
    ctx -> gpio_read = NULL;
    ctx -> gpio_write = NULL;
    ctx -> net_write = NULL;
    ctx -> net_write_param = NULL;
}

int tc_start(struct Context *ctx) {
    if(ctx -> state != 0) {
        return -1;
    }
    ctx -> net_write(ctx -> net_write_param, "AUTH", 4);
    ctx -> state = 1;
    return 0;
}

int tc_input(struct Context *ctx, char *raw_packet, size_t len) {
    if(ctx -> state == 1) {
        if(len != 32) {
            return -1;
        }
        MD5_CTX md5;
        md5_init(&md5);
        md5_update(&md5, (unsigned char *) raw_packet, len);
        char output[16];
        md5_final(&md5, (unsigned char *) output);

        ctx -> net_write(ctx -> net_write_param, output, 16);
        ctx -> state = 2;
        return 0;
    } else if(ctx -> state == 2) {
        if(len != 2 || strncmp(raw_packet, "OK", 2) != 0) {
            return -1;
        }
        ctx -> state = 3;
        return 0;
    }

    if(len == 5) {
        if(strncmp(raw_packet, "ALIVE", 5) == 0) {
            ctx -> net_write(ctx -> net_write_param, "OK", 2);
            return 0;
        }
    }

    if(len < sizeof(struct ControlPacket)) {
        return -1;
    }

    struct ControlPacket *pkt = (struct ControlPacket *)raw_packet;
    raw_packet += sizeof(struct ControlPacket);
    len -= sizeof(struct ControlPacket);

    switch(pkt -> type) {
        case CONTROL_GPIO_READ: {
            return control_gpio_read(ctx, pkt -> id, &raw_packet, &len);
        }

        case CONTROL_CODE_EXEC: {
            return control_code_exec(ctx, pkt -> id, &raw_packet, &len);
        }

        default:
            return -100;
    }

    return 0;
}

#endif
