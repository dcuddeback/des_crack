/* vim: foldmethod=marker */

#include "des.h"

typedef struct des_subkey {
    uint32_t left;
    uint32_t right;
} DES_SubKey;


static void DES_InitSubKey(DES_SubKey* subkey, const DES_Key *key);
static uint64_t DES_PC2(DES_SubKey *subkey, int shift);

/* {{{ Constants and lookup tables */

static const int SUBKEY_MASK = 0xFFFFFFF; /* 28 bits */

/* shift amounts for each round */
static const int key_schedule[] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

static const int pc1_left[] = {
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
};

static const int pc1_right[] = {
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4,
};

static const int pc2_table[] = {
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
};

/* }}} */

/* {{{ DES_InitKey */

void DES_InitKey(DES_Key *key, uint64_t value)
{
    DES_SubKey subkey;
    int i;

    key->key = value;
    DES_InitSubKey(&subkey, key);

    for (i = 0; i < 16; i++) {
        key->schedule[i] = DES_PC2(&subkey, key_schedule[i]);
    }
}

/* }}} */
/* {{{ DES_InitSubKey */

static void DES_InitSubKey(DES_SubKey* subkey, const DES_Key *key)
{
    int i;

    subkey->left = 0;
    subkey->right = 0;

    for (i = 0; i < 28; i++) {
        subkey->left <<= 1;
        subkey->left |= key->key >> (64 - pc1_left[i]) & 0x1;

        subkey->right <<= 1;
        subkey->right |= key->key >> (64 - pc1_right[i]) & 0x1;
    }
}

/* }}} */
/* {{{ DES_PC2 */

static uint64_t DES_PC2(DES_SubKey *subkey, int shift)
{
    uint64_t value;
    uint64_t ret;
    int i;

    subkey->left = (subkey->left << shift | subkey->left >> (28 - shift)) & SUBKEY_MASK;
    subkey->right = (subkey->right << shift | subkey->right >> (28 - shift)) & SUBKEY_MASK;

    value = subkey->left;
    value <<= 28;
    value |= subkey->right;

    ret = 0;
    for (i = 0; i < 48; i++) {
        ret <<= 1;
        ret |= value >> (56 - pc2_table[i]) & 0x1;
    }

    return ret;
}

/* }}} */
