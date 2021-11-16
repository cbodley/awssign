#pragma once

#include <stdexcept>
#include <openssl/err.h>
#include <openssl/evp.h>

namespace awssign::detail {

class digest_error : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

auto make_digest_error(unsigned long code) {
  char message[256];
  ::ERR_error_string_n(code, message, sizeof(message));
  return digest_error{message};
}

class digest {
  ::EVP_MD_CTX* ctx;
  const EVP_MD* md;
 public:
  static constexpr std::size_t max_size = EVP_MAX_MD_SIZE;

  explicit digest(const char* digest_name)
      : digest(::EVP_get_digestbyname(digest_name))
  {}
  explicit digest(const EVP_MD* md)
      : ctx(::EVP_MD_CTX_new()), md(md) {
    if (!ctx || !md) {
      throw make_digest_error(::ERR_get_error());
    }
    if (!::EVP_DigestInit_ex(ctx, md, nullptr)) {
      throw make_digest_error(::ERR_get_error());
    }
  }
  ~digest() {
    ::EVP_MD_CTX_free(ctx);
  }
  void init() {
    if (!::EVP_DigestInit_ex(ctx, md, nullptr)) {
      throw make_digest_error(::ERR_get_error());
    }
  }
  void update(const void* data, std::size_t len) {
    if (!::EVP_DigestUpdate(ctx, data, len)) {
      throw make_digest_error(::ERR_get_error());
    }
  }
  std::size_t finish(unsigned char* digest) {
    unsigned int bytes = 0;
    if (!::EVP_DigestFinal(ctx, digest, &bytes)) {
      throw make_digest_error(::ERR_get_error());
    }
    return bytes;
  }
};

class hmac {
  ::EVP_MD_CTX* ctx;
  const EVP_MD* md;
  ::EVP_PKEY* pkey;
 public:
  static constexpr std::size_t max_size = EVP_MAX_MD_SIZE;

  explicit hmac(const char* digest_name, const unsigned char* key, int len)
      : hmac(::EVP_get_digestbyname(digest_name), key, len)
  {}

  hmac(const EVP_MD* md, const unsigned char* key, int len)
      : ctx(::EVP_MD_CTX_new()),
        md(md),
        pkey(::EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, nullptr, key, len)) {
    if (!ctx || !md || !pkey) {
      throw make_digest_error(::ERR_get_error());
    }
    init();
  }
  ~hmac() {
    ::EVP_PKEY_free(pkey);
    ::EVP_MD_CTX_free(ctx);
  }
  void init() {
    if (!::EVP_DigestSignInit(ctx, nullptr, md, nullptr, pkey)) {
      throw make_digest_error(::ERR_get_error());
    }
  }
  // reinitialize with a new key
  void init(const unsigned char* key, int len) {
    auto new_pkey = ::EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, nullptr,
                                                   key, len);
    if (!new_pkey) {
      throw make_digest_error(::ERR_get_error());
    }
    ::EVP_PKEY_free(pkey);
    pkey = new_pkey;
    init();
  }
  void update(const void* data, std::size_t len) {
    if (!::EVP_DigestSignUpdate(ctx, data, len)) {
      throw make_digest_error(::ERR_get_error());
    }
  }
  std::size_t finish(unsigned char* digest) {
    size_t len = max_size;
    if (!::EVP_DigestSignFinal(ctx, digest, &len)) {
      throw make_digest_error(::ERR_get_error());
    }
    return len;
  }
};

} // namespace awssign::detail
