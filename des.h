#ifndef _DES_H_
#define _DES_H_

#include <stdint.h>

typedef struct des_key {
    uint64_t key;
    uint64_t schedule[16];
} DES_Key;


void DES_InitKey(DES_Key *key, uint64_t value);
uint64_t DES_Encrypt(const DES_Key *key, uint64_t plain);
uint64_t DES_Decrypt(const DES_Key *key, uint64_t cipher);

#endif
