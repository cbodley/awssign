#pragma once

#include <stdexcept>
#include <utility>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

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
  const ::EVP_MD* md;
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
  digest(const digest&) = delete;
  digest& operator=(const digest&) = delete;

  digest(digest&& o) noexcept
      : ctx(std::exchange(o.ctx, nullptr)),
        md(std::exchange(o.md, nullptr))
  {}
  digest& operator=(digest&& o) {
    using std::swap;
    swap(ctx, o.ctx);
    swap(md, o.md);
    return *this;
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
  ::HMAC_CTX* ctx;
  const ::EVP_MD* md;
 public:
  static constexpr std::size_t max_size = EVP_MAX_MD_SIZE;

  // construct without a key; a key must be provided to init() before use
  explicit hmac(const char* digest_name)
      : hmac(::EVP_get_digestbyname(digest_name))
  {}
  explicit hmac(const EVP_MD* md)
      : ctx(::HMAC_CTX_new()), md(md) {
    if (!ctx || !md) {
      throw make_digest_error(::ERR_get_error());
    }
    init();
  }

  hmac(const char* digest_name, const unsigned char* key, int len)
      : hmac(::EVP_get_digestbyname(digest_name), key, len)
  {}
  hmac(const EVP_MD* md, const unsigned char* key, int len)
      : ctx(::HMAC_CTX_new()), md(md) {
    if (!ctx || !md) {
      throw make_digest_error(::ERR_get_error());
    }
    init(key, len);
  }
  ~hmac() {
    ::HMAC_CTX_free(ctx);
  }
  hmac(const hmac&) = delete;
  hmac& operator=(const hmac&) = delete;

  hmac(hmac&& o) noexcept
      : ctx(std::exchange(o.ctx, nullptr)),
        md(std::exchange(o.md, nullptr))
  {}
  hmac& operator=(hmac&& o) noexcept {
    using std::swap;
    swap(ctx, o.ctx);
    swap(md, o.md);
    return *this;
  }

  void init() {
    if (!::HMAC_Init_ex(ctx, nullptr, 0, md, nullptr)) {
      throw make_digest_error(::ERR_get_error());
    }
  }
  // reinitialize with a new key
  void init(const unsigned char* key, int len) {
    if (!::HMAC_Init_ex(ctx, key, len, md, nullptr)) {
      throw make_digest_error(::ERR_get_error());
    }
  }
  void update(const void* data, std::size_t len) {
    auto buf = reinterpret_cast<const unsigned char*>(data);
    if (!::HMAC_Update(ctx, buf, len)) {
      throw make_digest_error(::ERR_get_error());
    }
  }
  std::size_t finish(unsigned char* digest) {
    unsigned int len = max_size;
    if (!::HMAC_Final(ctx, digest, &len)) {
      throw make_digest_error(::ERR_get_error());
    }
    return len;
  }
};

} // namespace awssign::detail
