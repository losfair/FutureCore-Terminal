#ifndef _TERMINAL_CONTROL_CORE_H_
#define _TERMINAL_CONTROL_CORE_H_

#ifdef DEBUG
#include <stdio.h>
#endif

#include <stdlib.h>
#include <string.h>
#include "credentials.h"
#include "types.h"
#include "structs.h"
#include "constants.h"
#include "md5.h"
#include "vm.h"
#include "security.h"

/*static void memcpy(char *dest, char *src, size_t len) {
    int i;

    for(i = 0; i < len; i++) {
        dest[i] = src[i];
    }
}*/

static int send_data_packet(struct Context *ctx, u32 id, u32 type, const u8 *data, size_t len) {
    if(type == 0) {
        size_t enc_buf_len = len + 8;
        u8 *enc_buf = (u8 *) ctx -> malloc(enc_buf_len);

        tc_encrypt_and_sign(ctx, enc_buf, enc_buf_len, data, len);
        int ret = ctx -> net_write(ctx -> net_write_param, (const char *) enc_buf, enc_buf_len);

        ctx -> free((char *) enc_buf);

        return ret;
    }

    u8 *buf = (u8 *) ctx -> malloc(sizeof(struct DataPacket) + len);

    struct DataPacket header;
    header.id = id;
    header.type = type;

    memcpy(buf, (char *)&header, sizeof(struct DataPacket));
    memcpy(buf + sizeof(struct DataPacket), data, len);

    size_t enc_buf_len = sizeof(struct DataPacket) + len + 8;
    u8 *enc_buf = (u8 *) ctx -> malloc(enc_buf_len);
    tc_encrypt_and_sign(ctx, enc_buf, enc_buf_len, buf, sizeof(struct DataPacket) + len);

    ctx -> free((char *) buf);

    int ret = ctx -> net_write(ctx -> net_write_param, (const char *) enc_buf, enc_buf_len);

    ctx -> free((char *) enc_buf);

    return ret;
}

static struct VM * get_vm(struct Context *ctx, size_t code_len, size_t max_cycles) {
    int i;

    for(i = 0; i < MAX_VMS; i++) {
        if(ctx -> vms[i] == NULL) {
            ctx -> vms[i] = (struct VM *) ctx -> malloc(sizeof(struct VM));
            tc_vm_init(ctx, ctx -> vms[i], code_len, max_cycles);
            return ctx -> vms[i];
        }
    }

    return NULL;
}

static int control_gpio_read(struct Context *ctx, u32 id, u8 **raw_packet_ptr, size_t *len_ptr) {
    size_t len = *len_ptr;

    if(len < sizeof(struct GPIOReadRequest)) {
        return -1;
    }

    struct GPIOReadRequest *req = (struct GPIOReadRequest *) *raw_packet_ptr;

    *len_ptr -= sizeof(struct GPIOReadRequest);
    *raw_packet_ptr += sizeof(struct GPIOReadRequest);

    struct GPIOReadResponse resp;
    resp.val = ctx -> gpio_read(req -> pin);

    send_data_packet(ctx, id, DATA_GPIO_READ, (u8 *) &resp, sizeof(struct GPIOReadResponse));

    return 0;
}

static int control_code_exec(struct Context *ctx, u32 id, u8 **raw_packet_ptr, size_t *len_ptr) {
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

    struct VM *vm = get_vm(ctx, code_len, req -> max_cycles);
    if(!vm) {
        return -1;
    }

    memcpy(vm -> code, code, code_len);

#ifdef DEBUG
    printf("Executing VM\n");
    printf("Code length: %lu\n", code_len);
    printf("Bytecode: ");
    for(i = 0; i < code_len; i++) {
        printf("%.2x ", code[i]);
    }
    printf("\n");
#endif

    vm -> task_id = id;

    return 0;
}

static int control_get_device_status(struct Context *ctx, u32 id, u8 **raw_packet_ptr, size_t *len_ptr) {
    int i;

    struct GetDeviceStatusResponse resp;
    resp.max_vms = MAX_VMS;
    resp.running_vms = 0;
    resp.active_vms = 0;

    for(i = 0; i < MAX_VMS; i++) {
        if(ctx -> vms[i]) {
            resp.running_vms++;
            if(ctx -> vms[i] -> runnable) {
                resp.active_vms++;
            }
        }
    }

    send_data_packet(ctx, id, DATA_GET_DEVICE_STATUS, (u8 *)&resp, sizeof(struct GetDeviceStatusResponse));

    return 0;
}

void tc_init(struct Context *ctx) {
    int i;

    ctx -> state = 0;
    ctx -> key = NULL;

    ctx -> terminal_id = TC_CRED_TERMINAL_ID;
    ctx -> signing_key = TC_CRED_SIGNING_KEY;
    ctx -> encryption_key = TC_CRED_ENCRYPTION_KEY;

    ctx -> alive_count = 0;
    ctx -> malloc = (malloc_fn) malloc;
    ctx -> free = (free_fn) free;
    ctx -> secure_random = NULL;
    ctx -> gpio_read = NULL;
    ctx -> gpio_write = NULL;
    ctx -> gpio_set_pin_mode = NULL;
    ctx -> net_write = NULL;
    ctx -> net_write_param = NULL;

    for(i = 0; i < MAX_VMS; i++) {
        ctx -> vms[i] = NULL;
    }

    for(i = 0; i < 256; i++) {
        ctx -> hypercalls[i] = NULL;
    }

    tc_init_keys(ctx);
}

void tc_reset_vms(struct Context *ctx) {
    int i;

    for(i = 0; i < MAX_VMS; i++) {
        if(ctx -> vms[i] != NULL) {
            tc_vm_destroy(ctx -> vms[i]);
            ctx -> free((char *) ctx -> vms[i]);
            ctx -> vms[i] = NULL;
        }
    }
}

void tc_reset(struct Context *ctx) {
    tc_reset_vms(ctx);
    tc_init(ctx);
}

int tc_start(struct Context *ctx) {
    if(ctx -> state != 0) {
        return -1;
    }

    char auth_req[40]; // "AUTH"(4) + terminal_id(36)
    memcpy(auth_req, "AUTH", 4);
    memcpy(auth_req + 4, TC_CRED_TERMINAL_ID, 36);

    ctx -> net_write(ctx -> net_write_param, auth_req, 40);
    ctx -> state = 1;
    return 0;
}

int tc_can_sleep(struct Context *ctx) {
    int i;

    for(i = 0; i < MAX_VMS; i++) {
        if(ctx -> vms[i] && ctx -> vms[i] -> runnable) {
            return 0;
        }
    }

    return 1;
}

static int control_reset_vms(struct Context *ctx, u32 id, u8 **raw_packet_ptr, size_t *len_ptr) {
    int i;
    struct ResetVMsResponse resp;
    resp.affected_vms = 0;

    for(i = 0; i < MAX_VMS; i++) {
        if(ctx -> vms[i]) {
            resp.affected_vms++;
        }
    }

    tc_reset_vms(ctx);

    send_data_packet(ctx, id, DATA_RESET_VMS, (u8 *)&resp, sizeof(struct ResetVMsResponse));
    return 0;
}

void tc_tick(struct Context *ctx) {
    int i, j, k;

    for(i = 0; i < MAX_VMS; i++) {
        struct VM *vm = ctx -> vms[i];

        if(vm && vm -> runnable) {
            for(j = 0; j < CYCLES_PER_TICK; j++) {
                if(tc_vm_execute_once(vm) != 0) { // VM halted
#ifdef DEBUG
                    printf("VM execution done\n");
                    printf("Registers:\n");
                    for(k = 0; k < 16; k++) {
                        printf("Register %d: %u\n", k, vm -> regs[k]);
                    }
                    printf("Error code: %d\n", vm -> error);
#endif
                    struct CodeExecResponse resp;
                    memcpy(resp.regs, vm -> regs, sizeof(u16) * 16);
                    u32 task_id = vm -> task_id;

                    tc_vm_destroy(vm);
                    ctx -> free((char *) vm);
                    vm = NULL;
                    ctx -> vms[i] = NULL;

                    send_data_packet(ctx, task_id, DATA_CODE_EXEC, (u8 *) &resp, sizeof(struct CodeExecResponse));
                    break;
                }
                if(!vm -> runnable) {
                    break;
                }
            }
        }
    }
}

int tc_input(struct Context *ctx, u8 *enc_raw_packet, size_t _len) {
    u8 _raw_packet[2200];
    u8 *raw_packet = _raw_packet;
    int ilen = tc_verify_and_decrypt(ctx, raw_packet, 2200, enc_raw_packet, _len);
    if(ilen < 0) {
#ifdef DEBUG
        printf("tc_input: tc_verify_and_decrypt failed: %d\n", ilen);
#endif
        return -1;
    }
    size_t len = ilen;

    if(ctx -> state == 1) {
        if(len != 32) {
            return -1;
        }

        MD5_CTX md5;
        md5_init(&md5);
        md5_update(&md5, (unsigned char *) raw_packet, 32);
        u8 output[16];
        md5_final(&md5, (unsigned char *) output);

        send_data_packet(ctx, 0, 0, output, 16);

        ctx -> state = 2;
        return 0;
    } else if(ctx -> state == 2) {
        if(len != 2 || strncmp((char *) raw_packet, "OK", 2) != 0) {
            return -1;
        }
        ctx -> state = 3;
        ctx -> alive_count++;
        return 0;
    }

    if(len == 5) {
        if(strncmp((char *) raw_packet, "ALIVE", 5) == 0) {
            send_data_packet(ctx, 0, 0, (u8 *) "OK", 2);
            ctx -> alive_count++;
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

        case CONTROL_GET_DEVICE_STATUS: {
            return control_get_device_status(ctx, pkt -> id, &raw_packet, &len);
        }

        case CONTROL_RESET_VMS: {
            return control_reset_vms(ctx, pkt -> id, &raw_packet, &len);
        }

        default:
            return -100;
    }

    return 0;
}

#endif
