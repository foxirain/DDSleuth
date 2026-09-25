#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <stdexcept>
#include <string>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace ddsleuth {

class RunLocalFingerprinter
{
public:

    static constexpr const char* ENVIRONMENT = "DDSLEUTH_FINGERPRINT_SECRET";
    static constexpr const char* SCHEME = "hmac-sha256-run-local-v1";

    static RunLocalFingerprinter from_environment()
    {
        const char* encoded = std::getenv(ENVIRONMENT);
        if (encoded == nullptr)
        {
            throw std::runtime_error(std::string("missing ") + ENVIRONMENT);
        }
        return RunLocalFingerprinter(decode_secret(encoded));
    }

    explicit RunLocalFingerprinter(
            std::array<unsigned char, 32> secret)
        : secret_(secret)
    {
    }

    RunLocalFingerprinter(const RunLocalFingerprinter&) = delete;
    RunLocalFingerprinter& operator=(const RunLocalFingerprinter&) = delete;

    RunLocalFingerprinter(
            RunLocalFingerprinter&& other) noexcept
        : secret_(other.secret_)
    {
        OPENSSL_cleanse(other.secret_.data(), other.secret_.size());
    }

    ~RunLocalFingerprinter()
    {
        OPENSSL_cleanse(secret_.data(), secret_.size());
    }

    std::string fingerprint(
            const unsigned char* material,
            size_t size) const
    {
        static constexpr unsigned char DOMAIN[] =
                "ddsleuth:key-fingerprint:v1\0";
        HMAC_CTX* context = HMAC_CTX_new();
        if (context == nullptr)
        {
            throw std::runtime_error("HMAC context allocation failed");
        }

        std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
        unsigned int digest_size = 0;
        const bool ok = HMAC_Init_ex(
            context,
            secret_.data(),
            static_cast<int>(secret_.size()),
            EVP_sha256(),
            nullptr) == 1 &&
                HMAC_Update(context, DOMAIN, sizeof(DOMAIN) - 1) == 1 &&
                HMAC_Update(context, material, size) == 1 &&
                HMAC_Final(context, digest.data(), &digest_size) == 1;
        HMAC_CTX_free(context);
        if (!ok)
        {
            throw std::runtime_error("HMAC-SHA256 fingerprint failed");
        }
        return std::string(SCHEME) + ":" + hex(digest.data(), digest_size);
    }

private:

    static unsigned char nibble(
            char value)
    {
        if (value >= '0' && value <= '9')
        {
            return static_cast<unsigned char>(value - '0');
        }
        if (value >= 'a' && value <= 'f')
        {
            return static_cast<unsigned char>(value - 'a' + 10);
        }
        if (value >= 'A' && value <= 'F')
        {
            return static_cast<unsigned char>(value - 'A' + 10);
        }
        throw std::runtime_error("fingerprint secret is not hexadecimal");
    }

    static std::array<unsigned char, 32> decode_secret(
            const std::string& encoded)
    {
        if (encoded.size() != 64)
        {
            throw std::runtime_error("fingerprint secret must encode exactly 32 bytes");
        }
        std::array<unsigned char, 32> secret{};
        for (size_t index = 0; index < secret.size(); ++index)
        {
            secret[index] = static_cast<unsigned char>(
                (nibble(encoded[index * 2]) << 4) |
                nibble(encoded[index * 2 + 1]));
        }
        return secret;
    }

    static std::string hex(
            const unsigned char* bytes,
            size_t size)
    {
        static constexpr char HEX[] = "0123456789abcdef";
        std::string encoded(size * 2, '0');
        for (size_t index = 0; index < size; ++index)
        {
            encoded[index * 2] = HEX[(bytes[index] >> 4) & 0x0f];
            encoded[index * 2 + 1] = HEX[bytes[index] & 0x0f];
        }
        return encoded;
    }

    std::array<unsigned char, 32> secret_;
};

} // namespace ddsleuth
