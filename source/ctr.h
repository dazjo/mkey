#ifndef _CTR_H
#define _CTR_H

#include "utils.h"

#include "polarssl/aes.h"

typedef struct
{
    u8 ctr[16];
    u8 iv[16];
    aes_context aes;
} ctr_aes_context;

void        ctr_set_iv( ctr_aes_context* ctx,
                         u8 iv[16] );

void        ctr_add_counter( ctr_aes_context* ctx,
                             u32 carry );

void        ctr_set_counter( ctr_aes_context* ctx,
                         u8 ctr[16] );


void        ctr_init_counter( ctr_aes_context* ctx,
                          u8 key[16],
                          u8 ctr[16] );


void        ctr_crypt_counter_block( ctr_aes_context* ctx,
                                     u8 input[16],
                                     u8 output[16] );


void        ctr_crypt_counter( ctr_aes_context* ctx,
                               u8* input,
                               u8* output,
                               u32 size );


void        ctr_init_cbc_encrypt( ctr_aes_context* ctx,
                               u8 key[16],
                               u8 iv[16] );

void        ctr_init_cbc_decrypt( ctr_aes_context* ctx,
                               u8 key[16],
                               u8 iv[16] );

void        ctr_encrypt_cbc( ctr_aes_context* ctx,
                              u8* input,
                              u8* output,
                              u32 size );

void        ctr_decrypt_cbc( ctr_aes_context* ctx,
                              u8* input,
                              u8* output,
                              u32 size );

#endif
