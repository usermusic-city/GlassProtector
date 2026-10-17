//
// Created by luoyesiqiu on 2025/11/26.
//

#include "dpt_crypto.h"
#include <cstring>

std::vector<uint8_t> hmac_sha256(const uint8_t *key,
                                 size_t key_len,
                                 const uint8_t *input,
                                 size_t input_len) {
    if (key == nullptr || key_len == 0 || input == nullptr || input_len == 0) {
        DLOGE("invalid hmac input");
        return {};
    }

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == nullptr) {
        DLOGE("mbedtls sha256 unavailable");
        return {};
    }

    std::vector<uint8_t> out(32);
    int ret = mbedtls_md_hmac(md_info, key, key_len, input, input_len, out.data());
    if (ret != 0) {
        DLOGE("hmac-sha256 failed: %d", ret);
        return {};
    }
    return out;
}

std::vector<uint8_t> aes_cbc_decrypt(const uint8_t *key,
                                     size_t key_bits,
                                     const uint8_t *iv,
                                     const uint8_t *in,
                                     size_t inlen) {
    if (key == nullptr || iv == nullptr || in == nullptr || inlen == 0 || (inlen % 16) != 0) {
        DLOGE("invalid aes cbc input");
        return {};
    }
    if (key_bits != 128 && key_bits != 192 && key_bits != 256) {
        DLOGE("unsupported aes key bits: %zu", key_bits);
        return {};
    }

    std::vector<uint8_t> out_vec(inlen);

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    int setkey_ret = mbedtls_aes_setkey_dec(&ctx, key, static_cast<unsigned int>(key_bits));

    if(setkey_ret == 0) {
        DLOGD("set key success");
    }
    else {
        DLOGE("set key fail");
        mbedtls_aes_free(&ctx);
        return {};
    }

    uint8_t new_iv[16] = {0};
    memcpy(new_iv, iv, 16);

    int ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, inlen, new_iv, in, out_vec.data());

    if(ret == 0) {
        DLOGD("decrypt ret: %d", ret);
    }
    else {
        DLOGE("decrypt fail");
        mbedtls_aes_free(&ctx);
        return {};
    }

    if (!out_vec.empty()) {
        uint8_t pad = out_vec.back();
        DLOGD("padding: %d", pad);
        if (pad > 0 && pad <= 16 && pad <= out_vec.size()) {
            out_vec.resize(out_vec.size() - pad);
        } else {
            DLOGE("invalid padding");
            mbedtls_aes_free(&ctx);
            return {};
        }
    }

    mbedtls_aes_free(&ctx);

    return out_vec;
}
