#ifndef _TERMINAL_CONTROL_RAND_H_
#define _TERMINAL_CONTROL_RAND_H_

#ifdef DEBUG
#include <stdio.h>
#endif

#include <stdlib.h>
#include "rand_r.h"
#include "types.h"
#include "credentials.h"
#include "structs.h"
#include "md5.h"

void tc_secure_random_bytes(struct Context *ctx, u8 *buf, size_t len) {
    int i;

    for(i = 0; i < len; i++) {
        buf[i] = ctx -> secure_random() & 0xff;
    }
}

void tc_update_key(u8 *key) {
    int i;
    unsigned int seed = (*(unsigned int *) key)
        ^ (*(unsigned int *) (key + 4) )
        ^ (*(unsigned int *) (key + 8) )
        ^ (*(unsigned int *) (key + 12) );
    
    for(i = 0; i < 16; i++) {
        key[i] ^= tc_rand_r(&seed) & 0xff;
    }
}

void tc_init_keys(struct Context *ctx) {
    int i;
    const char *enc_key = TC_CRED_ENCRYPTION_KEY;

    for(i = 0; i < 16; i++) {
        ctx -> current_key[i] = enc_key[i];
    }

    for(i = 0; i < 16; i++) {
        ctx -> server_key[i] = enc_key[i];
    }

    tc_update_key(ctx -> current_key);
    tc_update_key(ctx -> server_key);
}

int tc_encrypt_and_sign(struct Context *ctx, u8 *output, size_t output_len, const u8 *data, size_t data_len) {
    int i;
    u8 sign_buf[2200];

    if(!data_len || output_len < data_len + 8 || data_len > 2048) {
        return -1;
    }

    for(i = 0; i < data_len; i++) {
        output[i + 8] = data[i] ^ ctx -> current_key[i & 0xf];
    }
    
    memcpy(sign_buf, TC_CRED_SIGNING_KEY, 16);
    memcpy(sign_buf + 16, &output[8], data_len);

#ifdef DEBUG
    printf("tc_encrypt_and_sign: sign_buf: ");
    for(i = 0; i < 16 + data_len; i++) {
        printf("%.2x ", sign_buf[i]);
    }
    printf("\n");
#endif

    u8 md5_buf[16];

    MD5_CTX md5;
    md5_init(&md5);
    md5_update(&md5, (unsigned char *) sign_buf, 16 + data_len);
    md5_final(&md5, (unsigned char *) md5_buf);

    for(i = 0; i < 8; i++) {
        output[i] = md5_buf[i];
    }

    tc_update_key(ctx -> current_key);

    return data_len + 8;
}

int tc_verify_and_decrypt(struct Context *ctx, u8 *output, size_t output_len, const u8 *data, size_t data_len) {
    int i;
    u8 sign_buf[2200];

    if(output_len + 8 < data_len || data_len <= 8 || data_len > 2048) {
        return -1;
    }

    memcpy(sign_buf, TC_CRED_SIGNING_KEY, 16);
    memcpy(sign_buf + 16, &data[8], data_len - 8);

#ifdef DEBUG
    printf("tc_verify_and_decrypt: sign_buf: ");
    for(i = 0; i < 16 + data_len - 8; i++) {
        printf("%d ", sign_buf[i]);
    }
    printf("\n");
#endif

    u8 md5_buf[16];

    MD5_CTX md5;
    md5_init(&md5);
    md5_update(&md5, (unsigned char *) sign_buf, 16 + data_len - 8);
    md5_final(&md5, (unsigned char *) md5_buf);

#ifdef DEBUG
    printf("Expecting signature: ");
    for(i = 0; i < 8; i++) {
        printf("%d ", md5_buf[i]);
    }
    printf("\n");
    printf("Got signature: ");
    for(i = 0; i < 8; i++) {
        printf("%d ", data[i]);
    }
    printf("\n");
#endif

    for(i = 0; i < 8; i++) {
        if(md5_buf[i] != data[i]) {
            return -2;
        }
    }

    for(i = 0; i < data_len - 8; i++) {
        output[i] = data[i + 8] ^ ctx -> server_key[i & 0xf];
    }

    tc_update_key(ctx -> server_key);

    return data_len - 8;
}

#endif
