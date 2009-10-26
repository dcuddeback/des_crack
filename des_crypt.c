/* vim: foldmethod=marker */

#include "des.h"


typedef struct des_block {
    union {
        uint64_t block;
        struct {
            uint32_t right;
            uint32_t left;
        };
    };
} DES_Block;

static uint64_t base_des_crypt(const DES_Key *key, uint64_t blockIn, int keyStart, int keyStep);
static uint64_t IP(uint64_t block);
static uint64_t FP(uint64_t block);
static uint32_t ES(uint32_t x, uint64_t key);
static uint32_t P(uint64_t x);
static uint32_t F(uint32_t subblock, uint64_t subkey);


/* {{{ Lookup tables */

static const int ip_table[] = {
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7,
};

static const int fp_table[] = {
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25,
};

static const int e_table[] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1,
};

static const int p_table[] = {
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25,
};

static const int sbox[][64] = {
        /* S1 */
    { 14,  0,  4, 15, 13,  7,  1,  4,  2, 14, 15,  2, 11, 13,  8,  1,
       3, 10, 10,  6,  6, 12, 12, 11,  5,  9,  9,  5,  0,  3,  7,  8,
       4, 15,  1, 12, 14,  8,  8,  2, 13,  4,  6,  9,  2,  1, 11,  7,
      15,  5, 12, 11,  9,  3,  7, 14,  3, 10, 10,  0,  5,  6,  0, 13, },
        /* S2 */
    { 15,  3,  1, 13,  8,  4, 14,  7,  6, 15, 11,  2,  3,  8,  4, 14,
       9, 12,  7,  0,  2,  1, 13, 10, 12,  6,  0,  9,  5, 11, 10,  5,
       0, 13, 14,  8,  7, 10, 11,  1, 10,  3,  4, 15, 13,  4,  1,  2,
       5, 11,  8,  6, 12,  7,  6, 12,  9,  0,  3,  5,  2, 14, 15,  9, },
        /* S3 */
    { 10, 13,  0,  7,  9,  0, 14,  9,  6,  3,  3,  4, 15,  6,  5, 10,
       1,  2, 13,  8, 12,  5,  7, 14, 11, 12,  4, 11,  2, 15,  8,  1,
      13,  1,  6, 10,  4, 13,  9,  0,  8,  6, 15,  9,  3,  8,  0,  7,
      11,  4,  1, 15,  2, 14, 12,  3,  5, 11, 10,  5, 14,  2,  7, 12, },
        /* S4 */
    {  7, 13, 13,  8, 14, 11,  3,  5,  0,  6,  6, 15,  9,  0, 10,  3,
       1,  4,  2,  7,  8,  2,  5, 12, 11,  1, 12, 10,  4, 14, 15,  9,
      10,  3,  6, 15,  9,  0,  0,  6, 12, 10, 11,  1,  7, 13, 13,  8,
      15,  9,  1,  4,  3,  5, 14, 11,  5, 12,  2,  7,  8,  2,  4, 14, },
        /* S5 */
    {  2, 14, 12, 11,  4,  2,  1, 12,  7,  4, 10,  7, 11, 13,  6,  1,
       8,  5,  5,  0,  3, 15, 15, 10, 13,  3,  0,  9, 14,  8,  9,  6,
       4, 11,  2,  8,  1, 12, 11,  7, 10,  1, 13, 14,  7,  2,  8, 13,
      15,  6,  9, 15, 12,  0,  5,  9,  6, 10,  3,  4,  0,  5, 14,  3, },
        /* S6 */
    { 12, 10,  1, 15, 10,  4, 15,  2,  9,  7,  2, 12,  6,  9,  8,  5,
       0,  6, 13,  1,  3, 13,  4, 14, 14,  0,  7, 11,  5,  3, 11,  8,
       9,  4, 14,  3, 15,  2,  5, 12,  2,  9,  8,  5, 12, 15,  3, 10,
       7, 11,  0, 14,  4,  1, 10,  7,  1,  6, 13,  0, 11,  8,  6, 13, },
        /* S7 */
    {  4, 13, 11,  0,  2, 11, 14,  7, 15,  4,  0,  9,  8,  1, 13, 10,
       3, 14, 12,  3,  9,  5,  7, 12,  5,  2, 10, 15,  6,  8,  1,  6,
       1,  6,  4, 11, 11, 13, 13,  8, 12,  1,  3,  4,  7, 10, 14,  7,
      10,  9, 15,  5,  6,  0,  8, 15,  0, 14,  5,  2,  9,  3,  2, 12, },
        /* S8 */
    { 13,  1,  2, 15,  8, 13,  4,  8,  6, 10, 15,  3, 11,  7,  1,  4,
      10, 12,  9,  5,  3,  6, 14, 11,  5,  0,  0, 14, 12,  9,  7,  2,
       7,  2, 11,  1,  4, 14,  1,  7,  9,  4, 12, 10, 14,  8,  2, 13,
       0, 15,  6, 12, 10,  9, 13,  0, 15,  3,  3,  5,  5,  6,  8, 11, },
};

/* }}} */

/* {{{ DES_Encrypt */

uint64_t DES_Encrypt(const DES_Key *key, uint64_t plain)
{
    return FP(base_des_crypt(key, IP(plain), 0, +1));
}

/* }}} */
/* {{{ DES_Decrypt */

uint64_t DES_Decrypt(const DES_Key *key, uint64_t cipher)
{
    return FP(base_des_crypt(key, IP(cipher), 15, -1));
}

/* }}} */
/* {{{ base_des_crypt */

static uint64_t base_des_crypt(const DES_Key *key, uint64_t blockIn, int keyStart, int keyStep)
{
    DES_Block block;
    int keyIndex = keyStart;
    int i;

    block.block = blockIn;

    for (i = 0; i < 16; i++) {
        block.left = F(block.right, key->schedule[keyIndex]) ^ block.left;

        if (i != 15) {
            /* swap subblocks */
            block.left ^= block.right;
            block.right ^= block.left;
            block.left ^= block.right;
        }

        keyIndex += keyStep;
    }

    return block.block;
}

/* }}} */
/* {{{ IP */

static uint64_t IP(uint64_t block)
{
    uint64_t ip = 0LL;
    int i;

    for (i = 0; i < 64; i++) {
        ip <<= 1;
        ip |= block >> (64 - ip_table[i]) & 0x1;
    }

    return ip;
}

/* }}} */
/* {{{ FP */

static uint64_t FP(uint64_t block)
{
    uint64_t fp = 0LL;
    int i;

    for (i = 0; i < 64; i++) {
        fp <<= 1;
        fp |= block >> (64 - fp_table[i]) & 0x1;
    }

    return fp;
}

/* }}} */
/* {{{ ES */

/* combined E and S function */
static uint32_t ES(uint32_t x, uint64_t key)
{
    uint64_t exp = (uint64_t)x << 47 | (uint64_t)x << 15 | x >> 17;
    uint64_t mask = 0x3FLL << 42;
    uint32_t ret = 0;
    int i;

    for (i = 0; i < 8; i++) {
        ret <<= 4;
        ret |= sbox[i][((exp ^ key) & mask) >> 42];
        exp <<= 4;
        key <<= 6;
    }

    return ret;
}

/* }}} */
/* {{{ P */

static uint32_t P(uint64_t x)
{
    uint32_t ret = 0L;
    int i;

    for (i = 0; i < 32; i++) {
        ret <<= 1;
        ret |= x >> (32 - p_table[i]) & 0x1;
    }

    return ret;
}

/* }}} */
/* {{{ F */

/* The Feistel cipher function */
static uint32_t F(uint32_t subblock, uint64_t subkey)
{
    return P(ES(subblock, subkey));
}

/* }}} */
