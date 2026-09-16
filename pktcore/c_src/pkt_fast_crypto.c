#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "twofish.h"

#define BLOCK_SIZE 16

static void xor_16(uint8_t* dst, const uint8_t* a, const uint8_t* b) {
    for (int i = 0; i < 16; ++i) dst[i] = a[i] ^ b[i];
}

static void left_shift_one_16(const uint8_t* in, uint8_t* out) {
    uint8_t carry = 0;
    for (int i = 15; i >= 0; --i) {
        uint8_t new_byte = (uint8_t)((in[i] << 1) & 0xFF);
        out[i] = new_byte | carry;
        carry = (uint8_t)((in[i] & 0x80) >> 7);
    }
}

static void generate_subkeys(Twofish_key* key, uint8_t K1[16], uint8_t K2[16]) {
    uint8_t zero[16] = {0};
    uint8_t L[16];
    Twofish_encrypt_block(key, zero, L);

    left_shift_one_16(L, K1);
    if (L[0] & 0x80) {
        K1[15] ^= 0x87;
    }

    left_shift_one_16(K1, K2);
    if (K1[0] & 0x80) {
        K2[15] ^= 0x87;
    }
}

static void cmac_digest(Twofish_key* key, const uint8_t K1[16], const uint8_t K2[16], const uint8_t* data, size_t len, uint8_t out[16]) {
    uint8_t last_block[16];
    size_t num_blocks = (len + BLOCK_SIZE - 1) / BLOCK_SIZE;
    if (len == 0) num_blocks = 1;

    size_t full_blocks = (len % BLOCK_SIZE == 0 && len > 0) ? num_blocks - 1 : (len / BLOCK_SIZE);
    size_t remainder = len - full_blocks * BLOCK_SIZE;

    if (len > 0 && remainder == BLOCK_SIZE) {
        xor_16(last_block, data + full_blocks * BLOCK_SIZE, K1);
    } else {
        memset(last_block, 0, 16);
        if (remainder > 0) {
            memcpy(last_block, data + full_blocks * BLOCK_SIZE, remainder);
        }
        last_block[remainder] = 0x80;
        xor_16(last_block, last_block, K2);
    }

    uint8_t X[16] = {0};
    for (size_t i = 0; i < full_blocks; ++i) {
        xor_16(X, X, data + i * BLOCK_SIZE);
        uint8_t tmp[16];
        Twofish_encrypt_block(key, X, tmp);
        memcpy(X, tmp, 16);
    }

    xor_16(X, X, last_block);
    Twofish_encrypt_block(key, X, out);
}

static void omac_with_prefix(Twofish_key* key, const uint8_t K1[16], const uint8_t K2[16], uint8_t prefix, const uint8_t* data, size_t len, uint8_t out[16]) {
    uint8_t* buf = (uint8_t*)malloc(16 + len);
    if (!buf) return;
    memset(buf, 0, 15);
    buf[15] = prefix;
    if (len > 0 && data) {
        memcpy(buf + 16, data, len);
    }
    cmac_digest(key, K1, K2, buf, 16 + len, out);
    free(buf);
}

static void inc_counter_be(uint8_t counter[16]) {
    for (int i = 15; i >= 0; --i) {
        counter[i] = (uint8_t)(counter[i] + 1);
        if (counter[i] != 0) break;
    }
}

static void ctr_process(Twofish_key* key, const uint8_t initial_counter[16], const uint8_t* in, uint8_t* out, size_t len) {
    uint8_t ctr[16];
    memcpy(ctr, initial_counter, 16);
    size_t offset = 0;
    while (offset < len) {
        uint8_t ks[16];
        Twofish_encrypt_block(key, ctr, ks);
        inc_counter_be(ctr);

        size_t chunk = len - offset;
        if (chunk > 16) chunk = 16;
        for (size_t i = 0; i < chunk; ++i) {
            out[offset + i] = in[offset + i] ^ ks[i];
        }
        offset += chunk;
    }
}

__declspec(dllexport) void deobf_stage1_c(const uint8_t* in, uint8_t* out, size_t L) {
    for (size_t i = 0; i < L; ++i) {
        uint8_t key = (uint8_t)(L - i * L);
        out[i] = in[L - 1 - i] ^ key;
    }
}

__declspec(dllexport) void obf_stage1_c(const uint8_t* in, uint8_t* out, size_t L) {
    for (size_t i = 0; i < L; ++i) {
        uint8_t key = (uint8_t)(L - i * L);
        out[L - 1 - i] = in[i] ^ key;
    }
}

__declspec(dllexport) void deobf_stage2_c(const uint8_t* in, uint8_t* out, size_t L) {
    for (size_t i = 0; i < L; ++i) {
        uint8_t key = (uint8_t)(L - i);
        out[i] = in[i] ^ key;
    }
}

__declspec(dllexport) void obf_stage2_c(const uint8_t* in, uint8_t* out, size_t L) {
    for (size_t i = 0; i < L; ++i) {
        uint8_t key = (uint8_t)(L - i);
        out[i] = in[i] ^ key;
    }
}

__declspec(dllexport) int fast_decrypt_pkt(
    const uint8_t* in_pkt, size_t in_len,
    const uint8_t* key_bytes, const uint8_t* iv_bytes,
    uint8_t* out_stage2, size_t* out_len
) {
    if (in_len < 16) return -1;
    size_t L = in_len;
    uint8_t* stage1 = (uint8_t*)malloc(L);
    if (!stage1) return -2;

    deobf_stage1_c(in_pkt, stage1, L);

    Twofish_initialise();
    Twofish_key tf_key;
    Twofish_prepare_key((Twofish_Byte*)key_bytes, 16, &tf_key);

    uint8_t K1[16], K2[16];
    generate_subkeys(&tf_key, K1, K2);

    size_t cipher_len = L - 16;
    const uint8_t* ciphertext = stage1;
    const uint8_t* tag = stage1 + cipher_len;

    uint8_t n_tag[16];
    omac_with_prefix(&tf_key, K1, K2, 0x00, iv_bytes, 16, n_tag);

    uint8_t* decrypted = (uint8_t*)malloc(cipher_len);
    if (!decrypted) { free(stage1); return -2; }

    ctr_process(&tf_key, n_tag, ciphertext, decrypted, cipher_len);

    uint8_t h_tag[16];
    omac_with_prefix(&tf_key, K1, K2, 0x01, NULL, 0, h_tag);

    uint8_t c_tag[16];
    omac_with_prefix(&tf_key, K1, K2, 0x02, ciphertext, cipher_len, c_tag);

    uint8_t expected_tag[16];
    for (int i = 0; i < 16; ++i) {
        expected_tag[i] = n_tag[i] ^ h_tag[i] ^ c_tag[i];
    }

    if (memcmp(expected_tag, tag, 16) != 0) {
        free(stage1);
        free(decrypted);
        return -3; // Auth failed
    }

    deobf_stage2_c(decrypted, out_stage2, cipher_len);
    *out_len = cipher_len;

    free(stage1);
    free(decrypted);
    return 0;
}

__declspec(dllexport) int fast_encrypt_pkt(
    const uint8_t* in_stage2, size_t in_len,
    const uint8_t* key_bytes, const uint8_t* iv_bytes,
    uint8_t* out_pkt, size_t* out_len
) {
    size_t L = in_len;
    uint8_t* dec_blob = (uint8_t*)malloc(L);
    if (!dec_blob) return -2;
    obf_stage2_c(in_stage2, dec_blob, L);

    Twofish_initialise();
    Twofish_key tf_key;
    Twofish_prepare_key((Twofish_Byte*)key_bytes, 16, &tf_key);

    uint8_t K1[16], K2[16];
    generate_subkeys(&tf_key, K1, K2);

    uint8_t n_tag[16];
    omac_with_prefix(&tf_key, K1, K2, 0x00, iv_bytes, 16, n_tag);

    uint8_t* ciphertext = (uint8_t*)malloc(L);
    if (!ciphertext) { free(dec_blob); return -2; }

    ctr_process(&tf_key, n_tag, dec_blob, ciphertext, L);

    uint8_t h_tag[16];
    omac_with_prefix(&tf_key, K1, K2, 0x01, NULL, 0, h_tag);

    uint8_t c_tag[16];
    omac_with_prefix(&tf_key, K1, K2, 0x02, ciphertext, L, c_tag);

    uint8_t tag[16];
    for (int i = 0; i < 16; ++i) {
        tag[i] = n_tag[i] ^ h_tag[i] ^ c_tag[i];
    }

    uint8_t* stage1 = (uint8_t*)malloc(L + 16);
    if (!stage1) { free(dec_blob); free(ciphertext); return -2; }

    memcpy(stage1, ciphertext, L);
    memcpy(stage1 + L, tag, 16);

    obf_stage1_c(stage1, out_pkt, L + 16);
    *out_len = L + 16;

    free(dec_blob);
    free(ciphertext);
    free(stage1);
    return 0;
}
