#include <sodium.h>

#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha3.h>
#include <mbedtls/ssl.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

using Bytes = std::vector<uint8_t>;

namespace {

constexpr size_t kCellBodyLen = 509;
constexpr size_t kRelayHeaderLen = 11;
constexpr size_t kRelayPayloadLen = kCellBodyLen - kRelayHeaderLen;

constexpr uint8_t CMD_RELAY = 3;
constexpr uint8_t CMD_DESTROY = 4;
constexpr uint8_t CMD_CREATE_FAST = 5;
constexpr uint8_t CMD_CREATED_FAST = 6;
constexpr uint8_t CMD_VERSIONS = 7;
constexpr uint8_t CMD_NETINFO = 8;
constexpr uint8_t CMD_RELAY_EARLY = 9;
constexpr uint8_t CMD_CREATE2 = 10;
constexpr uint8_t CMD_CREATED2 = 11;
constexpr uint8_t CMD_CERTS = 129;
constexpr uint8_t CMD_AUTH_CHALLENGE = 130;

constexpr uint8_t RELAY_BEGIN = 1;
constexpr uint8_t RELAY_DATA = 2;
constexpr uint8_t RELAY_END = 3;
constexpr uint8_t RELAY_CONNECTED = 4;
constexpr uint8_t RELAY_SENDME = 5;
constexpr uint8_t RELAY_BEGIN_DIR = 13;
constexpr uint8_t RELAY_EXTEND2 = 14;
constexpr uint8_t RELAY_EXTENDED2 = 15;
constexpr uint8_t RELAY_ESTABLISH_RENDEZVOUS = 33;
constexpr uint8_t RELAY_INTRODUCE1 = 34;
constexpr uint8_t RELAY_RENDEZVOUS2 = 37;
constexpr uint8_t RELAY_RENDEZVOUS_ESTABLISHED = 39;
constexpr uint8_t RELAY_INTRODUCE_ACK = 40;

constexpr const char *kHsProto = "tor-hs-ntor-curve25519-sha3-256-1";
constexpr const char *kBlindString = "Derive temporary signing key";
constexpr const char *kBlindBasePoint =
    "(1511222134953540077250115140958853151145401269304185720604611328394984776"
    "2202, "
    "46316835694926478169428394003475163141307993866256225615783033603165251855"
    "960)";

[[noreturn]] void fail(const std::string &msg) {
  throw std::runtime_error(msg);
}

void require(bool ok, const std::string &msg) {
  if (!ok) {
    fail(msg);
  }
}

[[maybe_unused]] std::string trim(std::string_view s) {
  size_t b = 0;
  while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b]))) {
    ++b;
  }
  size_t e = s.size();
  while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) {
    --e;
  }
  return std::string(s.substr(b, e - b));
}

std::vector<std::string> split_ws(std::string_view s) {
  std::vector<std::string> out;
  size_t i = 0;
  while (i < s.size()) {
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) {
      ++i;
    }
    size_t j = i;
    while (j < s.size() && !std::isspace(static_cast<unsigned char>(s[j]))) {
      ++j;
    }
    if (j > i) {
      out.emplace_back(s.substr(i, j - i));
    }
    i = j;
  }
  return out;
}

bool starts_with(std::string_view s, std::string_view p) {
  return s.size() >= p.size() && s.substr(0, p.size()) == p;
}

std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return s;
}

void put_u16(Bytes &b, uint16_t v) {
  b.push_back(static_cast<uint8_t>(v >> 8));
  b.push_back(static_cast<uint8_t>(v));
}

void put_u32(Bytes &b, uint32_t v) {
  b.push_back(static_cast<uint8_t>(v >> 24));
  b.push_back(static_cast<uint8_t>(v >> 16));
  b.push_back(static_cast<uint8_t>(v >> 8));
  b.push_back(static_cast<uint8_t>(v));
}

void put_u64(Bytes &b, uint64_t v) {
  for (int i = 7; i >= 0; --i) {
    b.push_back(static_cast<uint8_t>(v >> (i * 8)));
  }
}

uint16_t read_u16(const Bytes &b, size_t off) {
  require(off + 2 <= b.size(), "short u16");
  return static_cast<uint16_t>((b[off] << 8) | b[off + 1]);
}

uint32_t read_u32(const Bytes &b, size_t off) {
  require(off + 4 <= b.size(), "short u32");
  return (static_cast<uint32_t>(b[off]) << 24) |
         (static_cast<uint32_t>(b[off + 1]) << 16) |
         (static_cast<uint32_t>(b[off + 2]) << 8) |
         static_cast<uint32_t>(b[off + 3]);
}

Bytes from_string(std::string_view s) { return Bytes(s.begin(), s.end()); }

std::string to_string_lossy(const Bytes &b) {
  return std::string(reinterpret_cast<const char *>(b.data()), b.size());
}

std::string hex(const Bytes &b) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string out;
  out.reserve(b.size() * 2);
  for (uint8_t c : b) {
    out.push_back(kHex[c >> 4]);
    out.push_back(kHex[c & 0x0f]);
  }
  return out;
}

Bytes random_bytes(size_t n) {
  Bytes b(n);
  randombytes_buf(b.data(), b.size());
  return b;
}

bool ct_equal(const Bytes &a, const Bytes &b) {
  if (a.size() != b.size()) {
    return false;
  }
  return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

Bytes sha1(const Bytes &in) {
  Bytes out(20);
  require(mbedtls_sha1(in.data(), in.size(), out.data()) == 0, "sha1 failed");
  return out;
}

[[maybe_unused]] Bytes sha256(const Bytes &in) {
  Bytes out(32);
  require(mbedtls_sha256(in.data(), in.size(), out.data(), 0) == 0,
          "sha256 failed");
  return out;
}

Bytes sha3_256(const Bytes &in) {
  Bytes out(32);
  require(mbedtls_sha3(MBEDTLS_SHA3_256, in.data(), in.size(), out.data(),
                       out.size()) == 0,
          "sha3 failed");
  return out;
}

[[maybe_unused]] Bytes hmac_sha256(const Bytes &key, const Bytes &msg) {
  Bytes out(32);
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  require(info != nullptr, "missing sha256 md");
  require(mbedtls_md_hmac(info, key.data(), key.size(), msg.data(), msg.size(),
                          out.data()) == 0,
          "hmac failed");
  return out;
}

Bytes shake256(const Bytes &in, size_t out_len) {
  Bytes out(out_len);
  require(crypto_xof_shake256(out.data(), out.size(), in.data(), in.size()) ==
              0,
          "shake256 failed");
  return out;
}

Bytes tor_mac(const Bytes &key, const Bytes &msg) {
  Bytes in;
  put_u64(in, key.size());
  in.insert(in.end(), key.begin(), key.end());
  in.insert(in.end(), msg.begin(), msg.end());
  return sha3_256(in);
}

Bytes aes_ctr_crypt(const Bytes &key, const Bytes &input,
                    const Bytes &iv = Bytes(16, 0)) {
  require(iv.size() == 16, "bad aes ctr iv");
  Bytes out(input.size());
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  int rc = mbedtls_aes_setkey_enc(&ctx, key.data(),
                                  static_cast<unsigned int>(key.size() * 8));
  require(rc == 0, "aes setkey failed");
  std::array<uint8_t, 16> nonce{};
  std::array<uint8_t, 16> stream{};
  std::copy(iv.begin(), iv.end(), nonce.begin());
  size_t nc_off = 0;
  rc = mbedtls_aes_crypt_ctr(&ctx, input.size(), &nc_off, nonce.data(),
                             stream.data(), input.data(), out.data());
  mbedtls_aes_free(&ctx);
  require(rc == 0, "aes ctr failed");
  return out;
}

class AesCtrStream {
public:
  AesCtrStream() { mbedtls_aes_init(&ctx_); }
  explicit AesCtrStream(const Bytes &key) { init(key); }
  AesCtrStream(const AesCtrStream &) = delete;
  AesCtrStream &operator=(const AesCtrStream &) = delete;
  AesCtrStream(AesCtrStream &&other) noexcept { move_from(other); }
  AesCtrStream &operator=(AesCtrStream &&other) noexcept {
    if (this != &other) {
      mbedtls_aes_free(&ctx_);
      move_from(other);
    }
    return *this;
  }
  ~AesCtrStream() { mbedtls_aes_free(&ctx_); }

  void init(const Bytes &key) {
    key_ = key;
    initialized_ = true;
    require(mbedtls_aes_setkey_enc(&ctx_, key.data(),
                                   static_cast<unsigned int>(key.size() * 8)) ==
                0,
            "aes stream setkey failed");
    nonce_.fill(0);
    stream_.fill(0);
    nc_off_ = 0;
  }

  Bytes apply(const Bytes &input) {
    Bytes out(input.size());
    require(mbedtls_aes_crypt_ctr(&ctx_, input.size(), &nc_off_, nonce_.data(),
                                  stream_.data(), input.data(),
                                  out.data()) == 0,
            "aes stream failed");
    return out;
  }

private:
  void move_from(AesCtrStream &other) noexcept {
    mbedtls_aes_init(&ctx_);
    initialized_ = false;
    key_ = std::move(other.key_);
    if (!key_.empty()) {
      initialized_ = true;
      (void)mbedtls_aes_setkey_enc(&ctx_, key_.data(),
                                   static_cast<unsigned int>(key_.size() * 8));
    }
    nonce_ = other.nonce_;
    stream_ = other.stream_;
    nc_off_ = other.nc_off_;
    other.initialized_ = false;
    mbedtls_aes_free(&other.ctx_);
    mbedtls_aes_init(&other.ctx_);
    other.key_.clear();
    other.nonce_.fill(0);
    other.stream_.fill(0);
    other.nc_off_ = 0;
  }

  mbedtls_aes_context ctx_{};
  std::array<uint8_t, 16> nonce_{};
  std::array<uint8_t, 16> stream_{};
  size_t nc_off_ = 0;
  Bytes key_;
  bool initialized_ = false;
};

class Sha1Digest {
public:
  Sha1Digest() {
    mbedtls_sha1_init(&ctx_);
    require(mbedtls_sha1_starts(&ctx_) == 0, "sha1 starts failed");
  }
  Sha1Digest(const Sha1Digest &other) {
    mbedtls_sha1_init(&ctx_);
    mbedtls_sha1_clone(&ctx_, &other.ctx_);
  }
  Sha1Digest &operator=(const Sha1Digest &other) {
    if (this != &other) {
      mbedtls_sha1_clone(&ctx_, &other.ctx_);
    }
    return *this;
  }
  Sha1Digest(Sha1Digest &&other) noexcept {
    mbedtls_sha1_init(&ctx_);
    mbedtls_sha1_clone(&ctx_, &other.ctx_);
  }
  ~Sha1Digest() { mbedtls_sha1_free(&ctx_); }
  void update(const Bytes &b) {
    require(mbedtls_sha1_update(&ctx_, b.data(), b.size()) == 0,
            "sha1 update failed");
  }
  Bytes current() const {
    mbedtls_sha1_context tmp;
    mbedtls_sha1_init(&tmp);
    mbedtls_sha1_clone(&tmp, &ctx_);
    Bytes out(20);
    require(mbedtls_sha1_finish(&tmp, out.data()) == 0, "sha1 finish failed");
    mbedtls_sha1_free(&tmp);
    return out;
  }

private:
  mbedtls_sha1_context ctx_{};
};

class Sha3Digest {
public:
  Sha3Digest() {
    mbedtls_sha3_init(&ctx_);
    require(mbedtls_sha3_starts(&ctx_, MBEDTLS_SHA3_256) == 0,
            "sha3 starts failed");
  }
  Sha3Digest(const Sha3Digest &other) {
    mbedtls_sha3_init(&ctx_);
    mbedtls_sha3_clone(&ctx_, &other.ctx_);
  }
  Sha3Digest &operator=(const Sha3Digest &other) {
    if (this != &other) {
      mbedtls_sha3_clone(&ctx_, &other.ctx_);
    }
    return *this;
  }
  Sha3Digest(Sha3Digest &&other) noexcept {
    mbedtls_sha3_init(&ctx_);
    mbedtls_sha3_clone(&ctx_, &other.ctx_);
  }
  ~Sha3Digest() { mbedtls_sha3_free(&ctx_); }
  void update(const Bytes &b) {
    require(mbedtls_sha3_update(&ctx_, b.data(), b.size()) == 0,
            "sha3 update failed");
  }
  Bytes current() const {
    mbedtls_sha3_context tmp;
    mbedtls_sha3_init(&tmp);
    mbedtls_sha3_clone(&tmp, &ctx_);
    Bytes out(32);
    require(mbedtls_sha3_finish(&tmp, out.data(), out.size()) == 0,
            "sha3 finish failed");
    mbedtls_sha3_free(&tmp);
    return out;
  }

private:
  mbedtls_sha3_context ctx_{};
};

class RelayCrypto {
public:
  enum class DigestKind { Sha1, Sha3 };

  RelayCrypto() = default;
  RelayCrypto(const Bytes &df, const Bytes &db, const Bytes &kf,
              const Bytes &kb, DigestKind kind)
      : f_(kf), b_(kb), kind_(kind) {
    if (kind == DigestKind::Sha1) {
      sf_.emplace();
      sb_.emplace();
      sf_->update(df);
      sb_->update(db);
    } else {
      s3f_.emplace();
      s3b_.emplace();
      s3f_->update(df);
      s3b_->update(db);
    }
  }

  Bytes encrypt_relay(uint8_t relay_cmd, uint16_t stream_id,
                      const Bytes &data) {
    require(data.size() <= kRelayPayloadLen, "relay payload too large");
    Bytes body(kCellBodyLen, 0);
    body[0] = relay_cmd;
    body[3] = static_cast<uint8_t>(stream_id >> 8);
    body[4] = static_cast<uint8_t>(stream_id);
    body[9] = static_cast<uint8_t>(data.size() >> 8);
    body[10] = static_cast<uint8_t>(data.size());
    std::copy(data.begin(), data.end(), body.begin() + kRelayHeaderLen);
    update_forward(body);
    Bytes d = forward_digest();
    std::copy(d.begin(), d.begin() + 4, body.begin() + 5);
    return encrypt_body_only(body);
  }

  std::optional<Bytes> decrypt_recognized(const Bytes &encrypted) {
    Bytes body = decrypt_body_only(encrypted);
    if (recognize_decrypted(body)) {
      return body;
    }
    return std::nullopt;
  }

  bool recognize_decrypted(const Bytes &body) {
    if (body.size() != kCellBodyLen || body[1] != 0 || body[2] != 0) {
      return false;
    }
    Bytes tmp = body;
    std::fill(tmp.begin() + 5, tmp.begin() + 9, 0);
    auto checkpoint = clone_backward();
    update_backward(tmp);
    Bytes d = backward_digest();
    if (std::equal(d.begin(), d.begin() + 4, body.begin() + 5)) {
      return true;
    }
    restore_backward(std::move(checkpoint));
    return false;
  }

  Bytes encrypt_body_only(const Bytes &body) { return f_.apply(body); }

  Bytes decrypt_body_only(const Bytes &body) { return b_.apply(body); }

private:
  struct DigestCheckpoint {
    std::optional<Sha1Digest> s1;
    std::optional<Sha3Digest> s3;
  };

  DigestCheckpoint clone_backward() const {
    DigestCheckpoint cp;
    if (kind_ == DigestKind::Sha1) {
      cp.s1.emplace(*sb_);
    } else {
      cp.s3.emplace(*s3b_);
    }
    return cp;
  }

  void restore_backward(DigestCheckpoint &&cp) {
    if (kind_ == DigestKind::Sha1) {
      sb_ = std::move(cp.s1);
    } else {
      s3b_ = std::move(cp.s3);
    }
  }

  void update_forward(const Bytes &b) {
    if (kind_ == DigestKind::Sha1) {
      sf_->update(b);
    } else {
      s3f_->update(b);
    }
  }

  void update_backward(const Bytes &b) {
    if (kind_ == DigestKind::Sha1) {
      sb_->update(b);
    } else {
      s3b_->update(b);
    }
  }

  Bytes forward_digest() const {
    return kind_ == DigestKind::Sha1 ? sf_->current() : s3f_->current();
  }

  Bytes backward_digest() const {
    return kind_ == DigestKind::Sha1 ? sb_->current() : s3b_->current();
  }

  AesCtrStream f_;
  AesCtrStream b_;
  DigestKind kind_ = DigestKind::Sha1;
  std::optional<Sha1Digest> sf_;
  std::optional<Sha1Digest> sb_;
  std::optional<Sha3Digest> s3f_;
  std::optional<Sha3Digest> s3b_;
};

struct HostPort {
  std::string host;
  uint16_t port = 0;
};

HostPort parse_hostport(const std::string &s, uint16_t default_port = 0) {
  if (s.empty()) {
    fail("empty host");
  }
  HostPort hp;
  if (s[0] == '[') {
    auto close = s.find(']');
    require(close != std::string::npos, "bad IPv6 host:port");
    hp.host = s.substr(1, close - 1);
    if (close + 1 < s.size()) {
      require(s[close + 1] == ':', "bad IPv6 port separator");
      hp.port = static_cast<uint16_t>(std::stoul(s.substr(close + 2)));
    } else {
      hp.port = default_port;
    }
  } else {
    auto colon = s.rfind(':');
    if (colon != std::string::npos && s.find(':') == colon) {
      hp.host = s.substr(0, colon);
      hp.port = static_cast<uint16_t>(std::stoul(s.substr(colon + 1)));
    } else {
      hp.host = s;
      hp.port = default_port;
    }
  }
  require(!hp.host.empty(), "missing host");
  require(hp.port != 0, "missing port");
  return hp;
}

Bytes base64_decode(std::string s) {
  s.erase(std::remove_if(s.begin(), s.end(),
                         [](unsigned char c) { return std::isspace(c); }),
          s.end());
  while (s.size() % 4 != 0) {
    s.push_back('=');
  }
  Bytes out(s.size() / 4 * 3 + 4);
  size_t bin_len = 0;
  int rc =
      sodium_base642bin(out.data(), out.size(), s.c_str(), s.size(), nullptr,
                        &bin_len, nullptr, sodium_base64_VARIANT_ORIGINAL);
  require(rc == 0, "base64 decode failed");
  out.resize(bin_len);
  return out;
}

std::string base64_encode_unpadded(const Bytes &b) {
  size_t max_len =
      sodium_base64_encoded_len(b.size(), sodium_base64_VARIANT_ORIGINAL);
  std::string out(max_len, '\0');
  sodium_bin2base64(out.data(), out.size(), b.data(), b.size(),
                    sodium_base64_VARIANT_ORIGINAL);
  out.resize(std::strlen(out.c_str()));
  while (!out.empty() && out.back() == '=') {
    out.pop_back();
  }
  return out;
}

Bytes base32_decode_onion(std::string s) {
  s = lower(s);
  if (s.size() > 6 && s.substr(s.size() - 6) == ".onion") {
    s.resize(s.size() - 6);
  }
  require(s.size() == 56, "v3 onion address must have 56 base32 characters");
  int bits = 0;
  uint32_t acc = 0;
  Bytes out;
  for (char ch : s) {
    int v = -1;
    if (ch >= 'a' && ch <= 'z') {
      v = ch - 'a';
    } else if (ch >= '2' && ch <= '7') {
      v = ch - '2' + 26;
    }
    require(v >= 0, "invalid base32 character in onion address");
    acc = (acc << 5) | static_cast<uint32_t>(v);
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<uint8_t>((acc >> bits) & 0xff));
    }
  }
  require(out.size() == 35, "invalid v3 onion address length");
  return out;
}

struct OnionAddress {
  Bytes pubkey;
};

OnionAddress parse_onion_address(const std::string &addr) {
  Bytes raw = base32_decode_onion(addr);
  Bytes pub(raw.begin(), raw.begin() + 32);
  Bytes checksum(raw.begin() + 32, raw.begin() + 34);
  uint8_t version = raw[34];
  require(version == 3, "only v3 onion addresses are supported");
  Bytes check_input = from_string(".onion checksum");
  check_input.insert(check_input.end(), pub.begin(), pub.end());
  check_input.push_back(version);
  Bytes expected = sha3_256(check_input);
  require(checksum[0] == expected[0] && checksum[1] == expected[1],
          "bad onion checksum");
  require(crypto_core_ed25519_is_valid_point(pub.data()) == 1,
          "onion ed25519 key is invalid");
  return OnionAddress{pub};
}

int connect_tcp(const std::string &host, uint16_t port, int timeout_ms) {
  require(timeout_ms >= 0, "timeout must be non-negative");
  addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  addrinfo *res = nullptr;
  std::string port_s = std::to_string(port);
  int gai = getaddrinfo(host.c_str(), port_s.c_str(), &hints, &res);
  require(gai == 0, std::string("getaddrinfo failed for ") + host + ": " +
                        gai_strerror(gai));
  int fd = -1;
  std::string last_error = "no address found";
  for (addrinfo *ai = res; ai; ai = ai->ai_next) {
    fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) {
      last_error = std::strerror(errno);
      continue;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
      last_error = std::strerror(errno);
      close(fd);
      fd = -1;
      continue;
    }

    int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
    if (rc != 0 && errno == EINPROGRESS) {
      pollfd pfd{};
      pfd.fd = fd;
      pfd.events = POLLOUT;
      do {
        rc = poll(&pfd, 1, timeout_ms);
      } while (rc < 0 && errno == EINTR);
      if (rc == 0) {
        last_error = "connect timeout";
        close(fd);
        fd = -1;
        continue;
      }
      if (rc < 0) {
        last_error = std::strerror(errno);
        close(fd);
        fd = -1;
        continue;
      }
      int so_error = 0;
      socklen_t so_error_len = sizeof(so_error);
      if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len) != 0) {
        last_error = std::strerror(errno);
        close(fd);
        fd = -1;
        continue;
      }
      if (so_error != 0) {
        last_error = std::strerror(so_error);
        close(fd);
        fd = -1;
        continue;
      }
    } else if (rc != 0) {
      last_error = std::strerror(errno);
      close(fd);
      fd = -1;
      continue;
    }

    if (fcntl(fd, F_SETFL, flags) < 0) {
      last_error = std::strerror(errno);
      close(fd);
      fd = -1;
      continue;
    }

    if (fd >= 0) {
      break;
    }
  }
  freeaddrinfo(res);
  require(fd >= 0,
          "tcp connect failed to " + host + ":" + std::to_string(port) +
              ": " + last_error);
  timeval tv{};
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  return fd;
}

void write_all_fd(int fd, const Bytes &data) {
  size_t off = 0;
  while (off < data.size()) {
    ssize_t n = send(fd, data.data() + off, data.size() - off, 0);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    require(n > 0, "socket write failed");
    off += static_cast<size_t>(n);
  }
}

Bytes read_all_fd(int fd, size_t limit = 8 * 1024 * 1024) {
  Bytes out;
  std::array<uint8_t, 8192> buf{};
  while (out.size() < limit) {
    ssize_t n = recv(fd, buf.data(), buf.size(), 0);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      break;
    }
    out.insert(out.end(), buf.begin(), buf.begin() + n);
  }
  return out;
}

Bytes decode_http_body(const Bytes &response) {
  std::string s = to_string_lossy(response);
  auto pos = s.find("\r\n\r\n");
  require(pos != std::string::npos, "malformed HTTP response");
  std::string head = s.substr(0, pos);
  Bytes body(response.begin() + static_cast<long>(pos + 4), response.end());
  require(head.find(" 200 ") != std::string::npos,
          "HTTP request failed: " + head.substr(0, head.find("\r\n")));
  std::string lhead = lower(head);
  if (lhead.find("transfer-encoding: chunked") != std::string::npos) {
    Bytes decoded;
    size_t p = 0;
    while (p < body.size()) {
      size_t line_end = p;
      while (line_end + 1 < body.size() &&
             !(body[line_end] == '\r' && body[line_end + 1] == '\n')) {
        ++line_end;
      }
      require(line_end + 1 < body.size(), "bad chunked response");
      std::string len_s(reinterpret_cast<const char *>(body.data() + p),
                        line_end - p);
      size_t semi = len_s.find(';');
      if (semi != std::string::npos) {
        len_s.resize(semi);
      }
      size_t chunk_len = std::stoul(len_s, nullptr, 16);
      p = line_end + 2;
      if (chunk_len == 0) {
        break;
      }
      require(p + chunk_len <= body.size(), "truncated chunk");
      decoded.insert(decoded.end(), body.begin() + static_cast<long>(p),
                     body.begin() + static_cast<long>(p + chunk_len));
      p += chunk_len + 2;
    }
    return decoded;
  }
  return body;
}

Bytes http_get_direct(const HostPort &hp, const std::string &path,
                      int timeout_ms) {
  int fd = connect_tcp(hp.host, hp.port, timeout_ms);
  try {
    std::ostringstream req;
    req << "GET " << path << " HTTP/1.0\r\n"
        << "Host: " << hp.host << "\r\n"
        << "User-Agent: onionlink/0\r\n"
        << "Accept-Encoding: identity\r\n"
        << "Connection: close\r\n\r\n";
    Bytes rb = from_string(req.str());
    write_all_fd(fd, rb);
    Bytes resp = read_all_fd(fd);
    close(fd);
    fd = -1;
    return decode_http_body(resp);
  } catch (...) {
    if (fd >= 0) {
      close(fd);
    }
    throw;
  }
}

std::time_t parse_time_utc(const std::string &date, const std::string &time) {
  std::tm tm{};
  std::string both = date + " " + time;
  char *end = strptime(both.c_str(), "%Y-%m-%d %H:%M:%S", &tm);
  require(end != nullptr && *end == '\0', "bad consensus time: " + both);
  return timegm(&tm);
}

struct Relay {
  std::string nickname;
  std::string ip;
  uint16_t or_port = 0;
  uint16_t dir_port = 0;
  Bytes rsa_id;
  Bytes ed_id;
  std::set<std::string> flags;
  std::string proto;
  std::string md_digest;
  Bytes ntor_key;

  bool has_flag(const std::string &f) const {
    return flags.find(f) != flags.end();
  }
};

struct Consensus {
  std::time_t valid_after = 0;
  std::time_t fresh_until = 0;
  std::map<std::string, int> params;
  Bytes shared_rand_current;
  Bytes shared_rand_previous;
  std::vector<Relay> relays;

  int param(const std::string &name, int def) const {
    auto it = params.find(name);
    return it == params.end() ? def : it->second;
  }
};

[[maybe_unused]] std::string after_prefix(const std::string &line,
                                          const std::string &prefix) {
  require(starts_with(line, prefix), "line prefix mismatch");
  return line.substr(prefix.size());
}

Consensus parse_consensus(const std::string &doc) {
  Consensus c;
  Relay *cur = nullptr;
  std::istringstream in(doc);
  std::string line;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    if (line.empty()) {
      continue;
    }
    auto parts = split_ws(line);
    if (parts.empty()) {
      continue;
    }
    if (parts[0] == "valid-after" && parts.size() >= 3) {
      c.valid_after = parse_time_utc(parts[1], parts[2]);
    } else if (parts[0] == "fresh-until" && parts.size() >= 3) {
      c.fresh_until = parse_time_utc(parts[1], parts[2]);
    } else if (parts[0] == "params") {
      for (size_t i = 1; i < parts.size(); ++i) {
        auto eq = parts[i].find('=');
        if (eq != std::string::npos) {
          c.params[parts[i].substr(0, eq)] = std::stoi(parts[i].substr(eq + 1));
        }
      }
    } else if (parts[0] == "shared-rand-current-value" && parts.size() >= 3) {
      c.shared_rand_current = base64_decode(parts[2]);
    } else if (parts[0] == "shared-rand-previous-value" && parts.size() >= 3) {
      c.shared_rand_previous = base64_decode(parts[2]);
    } else if (parts[0] == "r" && parts.size() >= 8) {
      c.relays.push_back(Relay{});
      cur = &c.relays.back();
      cur->nickname = parts[1];
      cur->rsa_id = base64_decode(parts[2]);
      if (parts.size() >= 9) {
        cur->ip = parts[6];
        cur->or_port = static_cast<uint16_t>(std::stoul(parts[7]));
        cur->dir_port = static_cast<uint16_t>(std::stoul(parts[8]));
      } else {
        cur->ip = parts[5];
        cur->or_port = static_cast<uint16_t>(std::stoul(parts[6]));
        cur->dir_port = static_cast<uint16_t>(std::stoul(parts[7]));
      }
    } else if (parts[0] == "s" && cur) {
      for (size_t i = 1; i < parts.size(); ++i) {
        cur->flags.insert(parts[i]);
      }
    } else if (parts[0] == "pr" && cur) {
      cur->proto = line.size() > 3 ? line.substr(3) : "";
    } else if (parts[0] == "id" && cur && parts.size() >= 3 &&
               parts[1] == "ed25519" && parts[2] != "none") {
      cur->ed_id = base64_decode(parts[2]);
    } else if (parts[0] == "m" && cur && parts.size() >= 2) {
      std::string digest = parts[1];
      for (size_t i = 1; i < parts.size(); ++i) {
        auto eq = parts[i].find("sha256=");
        if (eq != std::string::npos) {
          digest = parts[i].substr(eq + 7);
        }
      }
      cur->md_digest = digest;
    }
  }
  require(c.valid_after != 0, "consensus missing valid-after");
  require(!c.relays.empty(), "consensus has no relays");
  return c;
}

Bytes read_file_bytes(const std::string &path) {
  std::ifstream f(path, std::ios::binary);
  require(static_cast<bool>(f), "failed to open " + path);
  return Bytes(std::istreambuf_iterator<char>(f),
               std::istreambuf_iterator<char>());
}

std::string read_file_string(const std::string &path) {
  Bytes b = read_file_bytes(path);
  return to_string_lossy(b);
}

Relay parse_microdescriptor_into(Relay relay, const std::string &doc) {
  std::istringstream in(doc);
  std::string line;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    auto parts = split_ws(line);
    if (parts.empty()) {
      continue;
    }
    if (parts[0] == "ntor-onion-key" && parts.size() >= 2) {
      relay.ntor_key = base64_decode(parts[1]);
    } else if (parts[0] == "id" && parts.size() >= 3 && parts[1] == "ed25519" &&
               relay.ed_id.empty()) {
      relay.ed_id = base64_decode(parts[2]);
    }
  }
  require(relay.ntor_key.size() == 32,
          "microdescriptor missing ntor-onion-key for " + relay.nickname);
  return relay;
}

std::vector<std::string> split_microdescriptors(const std::string &raw) {
  std::vector<std::string> out;
  size_t start = raw.find("onion-key\n");
  if (start == std::string::npos) {
    return out;
  }
  while (start < raw.size()) {
    size_t next = raw.find("\nonion-key\n", start + 1);
    if (next == std::string::npos) {
      out.push_back(raw.substr(start));
      break;
    }
    out.push_back(raw.substr(start, next + 1 - start));
    start = next + 1;
  }
  return out;
}

struct MicrodescriptorFields {
  Bytes ed_id;
  Bytes ntor_key;
};

MicrodescriptorFields parse_microdescriptor_fields(const std::string &doc) {
  MicrodescriptorFields f;
  std::istringstream in(doc);
  std::string line;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    auto parts = split_ws(line);
    if (parts.empty()) {
      continue;
    }
    if (parts[0] == "ntor-onion-key" && parts.size() >= 2) {
      f.ntor_key = base64_decode(parts[1]);
    } else if (parts[0] == "id" && parts.size() >= 3 && parts[1] == "ed25519") {
      f.ed_id = base64_decode(parts[2]);
    }
  }
  return f;
}

std::map<std::string, MicrodescriptorFields>
index_microdescriptors(const std::string &raw) {
  std::map<std::string, MicrodescriptorFields> out;
  for (const std::string &doc : split_microdescriptors(raw)) {
    Bytes bytes = from_string(doc);
    out[base64_encode_unpadded(sha256(bytes))] =
        parse_microdescriptor_fields(doc);
  }
  return out;
}

bool relay_usable_dir(const Relay &r) {
  return r.or_port != 0 && r.has_flag("Running") && r.has_flag("Valid");
}

bool relay_usable_hsdir(const Relay &r) {
  return relay_usable_dir(r) && r.has_flag("HSDir") &&
         !r.has_flag("NoEdConsensus") && r.ed_id.size() == 32;
}

bool relay_usable_rendezvous(const Relay &r) {
  return relay_usable_dir(r) && !r.has_flag("MiddleOnly") &&
         !r.has_flag("NoEdConsensus") && r.rsa_id.size() == 20 &&
         r.ed_id.size() == 32 && r.ntor_key.size() == 32;
}

std::vector<Relay> candidate_rendezvous_relays(const Consensus &c) {
  std::vector<Relay> out;
  for (const auto &r : c.relays) {
    if (relay_usable_rendezvous(r)) {
      out.push_back(r);
    }
  }
  require(!out.empty(), "no usable rendezvous relays in consensus");
  std::shuffle(out.begin(), out.end(), std::mt19937{std::random_device{}()});
  return out;
}

uint64_t current_period_num(const Consensus &c, int period_len_min) {
  int voting_interval = 60;
  if (c.fresh_until > c.valid_after) {
    voting_interval = static_cast<int>((c.fresh_until - c.valid_after) / 60);
    if (voting_interval <= 0) {
      voting_interval = 60;
    }
  }
  uint64_t minutes = static_cast<uint64_t>(c.valid_after / 60);
  uint64_t offset = static_cast<uint64_t>(12 * voting_interval);
  if (minutes < offset) {
    return 0;
  }
  return (minutes - offset) / static_cast<uint64_t>(period_len_min);
}

Bytes blind_onion_key(const Bytes &pubkey, uint64_t period_num,
                      uint64_t period_len) {
  require(pubkey.size() == 32, "bad onion pubkey");
  Bytes nonce = from_string("key-blind");
  put_u64(nonce, period_num);
  put_u64(nonce, period_len);
  Bytes input = from_string(kBlindString);
  input.push_back(0);
  input.insert(input.end(), pubkey.begin(), pubkey.end());
  Bytes b = from_string(kBlindBasePoint);
  input.insert(input.end(), b.begin(), b.end());
  input.insert(input.end(), nonce.begin(), nonce.end());
  Bytes h = sha3_256(input);
  h[0] &= 248;
  h[31] &= 63;
  h[31] |= 64;
  Bytes blinded(32);
  int rc = crypto_scalarmult_ed25519_noclamp(blinded.data(), h.data(),
                                             pubkey.data());
  require(rc == 0, "ed25519 key blinding failed");
  return blinded;
}

Bytes onion_subcredential(const Bytes &pubkey, const Bytes &blinded) {
  Bytes cred_in = from_string("credential");
  cred_in.insert(cred_in.end(), pubkey.begin(), pubkey.end());
  Bytes cred = sha3_256(cred_in);
  Bytes sub_in = from_string("subcredential");
  sub_in.insert(sub_in.end(), cred.begin(), cred.end());
  sub_in.insert(sub_in.end(), blinded.begin(), blinded.end());
  return sha3_256(sub_in);
}

struct HsPeriodKeys {
  uint64_t period_num = 0;
  int period_len = 1440;
  Bytes blinded;
  Bytes subcredential;
};

HsPeriodKeys derive_hs_period_keys(const Consensus &c,
                                   const OnionAddress &addr) {
  HsPeriodKeys k;
  k.period_len = c.param("hsdir-interval", 1440);
  k.period_num = current_period_num(c, k.period_len);
  k.blinded = blind_onion_key(addr.pubkey, k.period_num,
                              static_cast<uint64_t>(k.period_len));
  k.subcredential = onion_subcredential(addr.pubkey, k.blinded);
  return k;
}

std::vector<Relay> select_hsdirs(const Consensus &c, const Bytes &blinded,
                                 const Bytes &srv, uint64_t period_num,
                                 int period_len) {
  require(srv.size() == 32, "shared random value missing from consensus");
  struct Indexed {
    Bytes idx;
    Relay relay;
  };
  std::vector<Indexed> ring;
  for (const Relay &r : c.relays) {
    if (!relay_usable_hsdir(r)) {
      continue;
    }
    Bytes in = from_string("node-idx");
    in.insert(in.end(), r.ed_id.begin(), r.ed_id.end());
    in.insert(in.end(), srv.begin(), srv.end());
    put_u64(in, period_num);
    put_u64(in, static_cast<uint64_t>(period_len));
    ring.push_back({sha3_256(in), r});
  }
  require(!ring.empty(), "no usable HSDir relays in consensus");
  std::sort(ring.begin(), ring.end(),
            [](const Indexed &a, const Indexed &b) { return a.idx < b.idx; });

  int replicas = std::clamp(c.param("hsdir_n_replicas", 2), 1, 16);
  int spread = std::clamp(c.param("hsdir_spread_fetch", 3), 1, 128);
  std::vector<Relay> out;
  std::set<std::string> used;
  for (int rep = 1; rep <= replicas; ++rep) {
    Bytes sin = from_string("store-at-idx");
    sin.insert(sin.end(), blinded.begin(), blinded.end());
    put_u64(sin, static_cast<uint64_t>(rep));
    put_u64(sin, static_cast<uint64_t>(period_len));
    put_u64(sin, period_num);
    Bytes service_idx = sha3_256(sin);
    auto it = std::lower_bound(
        ring.begin(), ring.end(), service_idx,
        [](const Indexed &a, const Bytes &idx) { return a.idx < idx; });
    size_t start = static_cast<size_t>(it - ring.begin());
    for (size_t n = 0, seen = 0;
         seen < ring.size() && n < static_cast<size_t>(spread); ++seen) {
      const Relay &r = ring[(start + seen) % ring.size()].relay;
      std::string key = hex(r.ed_id);
      if (used.insert(key).second) {
        out.push_back(r);
        ++n;
      }
    }
  }
  return out;
}

struct LinkSpecifier {
  uint8_t type = 0;
  Bytes data;
};

std::vector<LinkSpecifier> parse_link_specifiers(const Bytes &encoded) {
  require(!encoded.empty(), "empty link specifier block");
  size_t pos = 0;
  uint8_t n = encoded[pos++];
  std::vector<LinkSpecifier> specs;
  for (uint8_t i = 0; i < n; ++i) {
    require(pos + 2 <= encoded.size(), "truncated link specifier");
    uint8_t type = encoded[pos++];
    uint8_t len = encoded[pos++];
    require(pos + len <= encoded.size(), "truncated link specifier body");
    specs.push_back(
        {type, Bytes(encoded.begin() + static_cast<long>(pos),
                     encoded.begin() + static_cast<long>(pos + len))});
    pos += len;
  }
  return specs;
}

Bytes serialize_link_specifiers(const std::vector<LinkSpecifier> &specs) {
  require(specs.size() <= 255, "too many link specifiers");
  Bytes out;
  out.push_back(static_cast<uint8_t>(specs.size()));
  for (const auto &s : specs) {
    require(s.data.size() <= 255, "link specifier too large");
    out.push_back(s.type);
    out.push_back(static_cast<uint8_t>(s.data.size()));
    out.insert(out.end(), s.data.begin(), s.data.end());
  }
  return out;
}

std::optional<HostPort>
link_spec_ipv4(const std::vector<LinkSpecifier> &specs) {
  for (const auto &s : specs) {
    if (s.type == 0 && s.data.size() == 6) {
      char buf[INET_ADDRSTRLEN]{};
      inet_ntop(AF_INET, s.data.data(), buf, sizeof(buf));
      uint16_t port = static_cast<uint16_t>((s.data[4] << 8) | s.data[5]);
      return HostPort{buf, port};
    }
  }
  return std::nullopt;
}

std::vector<LinkSpecifier> relay_link_specifiers(const Relay &r) {
  std::vector<LinkSpecifier> specs;
  in_addr a{};
  require(inet_pton(AF_INET, r.ip.c_str(), &a) == 1,
          "relay has non-IPv4 address");
  Bytes ipv4(reinterpret_cast<uint8_t *>(&a),
             reinterpret_cast<uint8_t *>(&a) + 4);
  ipv4.push_back(static_cast<uint8_t>(r.or_port >> 8));
  ipv4.push_back(static_cast<uint8_t>(r.or_port));
  specs.push_back({0, ipv4});
  specs.push_back({2, r.rsa_id});
  specs.push_back({3, r.ed_id});
  return specs;
}

bool same_relay(const Relay &a, const Relay &b) {
  if (!a.ed_id.empty() && !b.ed_id.empty() && a.ed_id == b.ed_id) {
    return true;
  }
  if (!a.rsa_id.empty() && !b.rsa_id.empty() && a.rsa_id == b.rsa_id) {
    return true;
  }
  return !a.ip.empty() && a.or_port != 0 && a.ip == b.ip &&
         a.or_port == b.or_port;
}

struct Cell {
  uint32_t circ_id = 0;
  uint8_t cmd = 0;
  Bytes body;
};

class TorChannel {
public:
  TorChannel(std::string host, uint16_t port, int timeout_ms)
      : host_(std::move(host)), port_(port), timeout_ms_(timeout_ms) {
    try {
      init_tls();
      negotiate();
    } catch (...) {
      cleanup();
      throw;
    }
  }

  TorChannel(const TorChannel &) = delete;
  TorChannel &operator=(const TorChannel &) = delete;

  ~TorChannel() {
    cleanup();
  }

  void cleanup() noexcept {
    mbedtls_ssl_close_notify(&ssl_);
    mbedtls_net_free(&net_);
    mbedtls_ssl_free(&ssl_);
    mbedtls_ssl_config_free(&conf_);
    mbedtls_ctr_drbg_free(&ctr_drbg_);
    mbedtls_entropy_free(&entropy_);
  }

  void write_cell(uint32_t circ_id, uint8_t cmd, const Bytes &body) {
    Bytes out;
    if (cmd == CMD_VERSIONS) {
      put_u16(out, 0);
      out.push_back(cmd);
      put_u16(out, static_cast<uint16_t>(body.size()));
      out.insert(out.end(), body.begin(), body.end());
    } else if (cmd >= 128) {
      put_u32(out, circ_id);
      out.push_back(cmd);
      put_u16(out, static_cast<uint16_t>(body.size()));
      out.insert(out.end(), body.begin(), body.end());
    } else {
      require(body.size() <= kCellBodyLen, "fixed cell body too large");
      put_u32(out, circ_id);
      out.push_back(cmd);
      out.insert(out.end(), body.begin(), body.end());
      out.resize(4 + 1 + kCellBodyLen, 0);
    }
    tls_write_all(out);
  }

  Cell read_cell() { return read_cell_with_circ_len(4); }

  uint32_t new_circ_id() {
    uint32_t id = 0;
    randombytes_buf(&id, sizeof(id));
    id = ntohl(id);
    id |= 0x80000000u;
    if (id == 0) {
      id = 0x80000001u;
    }
    return id;
  }

private:
  void init_tls() {
    mbedtls_net_init(&net_);
    mbedtls_ssl_init(&ssl_);
    mbedtls_ssl_config_init(&conf_);
    mbedtls_ctr_drbg_init(&ctr_drbg_);
    mbedtls_entropy_init(&entropy_);
    const char *pers = "onionlink";
    require(mbedtls_ctr_drbg_seed(&ctr_drbg_, mbedtls_entropy_func, &entropy_,
                                  reinterpret_cast<const unsigned char *>(pers),
                                  std::strlen(pers)) == 0,
            "ctr_drbg seed failed");
    int fd = connect_tcp(host_, port_, timeout_ms_);
    net_.fd = fd;
    require(mbedtls_ssl_config_defaults(&conf_, MBEDTLS_SSL_IS_CLIENT,
                                        MBEDTLS_SSL_TRANSPORT_STREAM,
                                        MBEDTLS_SSL_PRESET_DEFAULT) == 0,
            "ssl config defaults failed");
    mbedtls_ssl_conf_authmode(&conf_, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&conf_, mbedtls_ctr_drbg_random, &ctr_drbg_);
    mbedtls_ssl_conf_read_timeout(&conf_, static_cast<uint32_t>(timeout_ms_));
    require(mbedtls_ssl_setup(&ssl_, &conf_) == 0, "ssl setup failed");
    mbedtls_ssl_set_bio(&ssl_, &net_, mbedtls_net_send, mbedtls_net_recv,
                        mbedtls_net_recv_timeout);
    int rc = 0;
    while ((rc = mbedtls_ssl_handshake(&ssl_)) != 0) {
      if (rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE) {
        fail("TLS handshake failed with " + std::to_string(rc));
      }
    }
  }

  void negotiate() {
    Bytes versions;
    put_u16(versions, 4);
    put_u16(versions, 5);
    Bytes out;
    put_u16(out, 0);
    out.push_back(CMD_VERSIONS);
    put_u16(out, static_cast<uint16_t>(versions.size()));
    out.insert(out.end(), versions.begin(), versions.end());
    tls_write_all(out);

    Cell v = read_cell_with_circ_len(2);
    require(v.cmd == CMD_VERSIONS, "first Tor cell was not VERSIONS");
    int best = 0;
    for (size_t i = 0; i + 1 < v.body.size(); i += 2) {
      int peer = (v.body[i] << 8) | v.body[i + 1];
      if ((peer == 4 || peer == 5) && peer > best) {
        best = peer;
      }
    }
    require(best >= 4, "relay does not support link protocol 4+");
    link_version_ = best;
    bool got_netinfo = false;
    for (int i = 0; i < 16 && !got_netinfo; ++i) {
      Cell c = read_cell();
      if (c.cmd == CMD_NETINFO) {
        got_netinfo = true;
      }
    }
    require(got_netinfo, "relay did not send NETINFO");
    send_netinfo();
  }

  void send_netinfo() {
    Bytes body(kCellBodyLen, 0);
    uint32_t now = static_cast<uint32_t>(std::time(nullptr));
    body[0] = static_cast<uint8_t>(now >> 24);
    body[1] = static_cast<uint8_t>(now >> 16);
    body[2] = static_cast<uint8_t>(now >> 8);
    body[3] = static_cast<uint8_t>(now);
    body[4] = 4;
    body[5] = 4;
    body[10] = 0;
    write_cell(0, CMD_NETINFO, body);
  }

  Cell read_cell_with_circ_len(size_t circ_len) {
    Bytes header = tls_read_exact(circ_len + 1);
    Cell c;
    if (circ_len == 2) {
      c.circ_id = read_u16(header, 0);
    } else {
      c.circ_id = read_u32(header, 0);
    }
    c.cmd = header[circ_len];
    bool variable = (c.cmd == CMD_VERSIONS || c.cmd >= 128);
    if (variable) {
      Bytes lenb = tls_read_exact(2);
      uint16_t len = read_u16(lenb, 0);
      c.body = tls_read_exact(len);
    } else {
      c.body = tls_read_exact(kCellBodyLen);
    }
    return c;
  }

  Bytes tls_read_exact(size_t n) {
    Bytes out(n);
    size_t off = 0;
    while (off < n) {
      int rc = mbedtls_ssl_read(&ssl_, out.data() + off, n - off);
      if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
        continue;
      }
      require(rc > 0, "TLS read failed");
      off += static_cast<size_t>(rc);
    }
    return out;
  }

  void tls_write_all(const Bytes &data) {
    size_t off = 0;
    while (off < data.size()) {
      int rc = mbedtls_ssl_write(&ssl_, data.data() + off, data.size() - off);
      if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
        continue;
      }
      require(rc > 0, "TLS write failed");
      off += static_cast<size_t>(rc);
    }
  }

  std::string host_;
  uint16_t port_ = 0;
  int timeout_ms_ = 30000;
  int link_version_ = 4;
  mbedtls_net_context net_{};
  mbedtls_ssl_context ssl_{};
  mbedtls_ssl_config conf_{};
  mbedtls_ctr_drbg_context ctr_drbg_{};
  mbedtls_entropy_context entropy_{};
};

Bytes kdf_tor(const Bytes &k0, size_t len) {
  Bytes out;
  for (uint8_t i = 0; out.size() < len; ++i) {
    Bytes in = k0;
    in.push_back(i);
    Bytes h = sha1(in);
    out.insert(out.end(), h.begin(), h.end());
  }
  out.resize(len);
  return out;
}

Bytes hkdf_sha256_expand(const Bytes &key_seed, const Bytes &info, size_t len) {
  Bytes out;
  Bytes prev;
  for (uint8_t i = 1; out.size() < len; ++i) {
    Bytes msg = prev;
    msg.insert(msg.end(), info.begin(), info.end());
    msg.push_back(i);
    prev = hmac_sha256(key_seed, msg);
    out.insert(out.end(), prev.begin(), prev.end());
  }
  out.resize(len);
  return out;
}

struct NtorState {
  Bytes x;
  Bytes X;
  Bytes B;
  Bytes id;
  Bytes bx;
};

Bytes x25519_public_from_private(const Bytes &priv);
Bytes x25519_shared(const Bytes &priv, const Bytes &pub);

Bytes build_ntor_onionskin(const Relay &relay, NtorState &st) {
  require(relay.rsa_id.size() == 20, "relay missing RSA identity for ntor");
  require(relay.ntor_key.size() == 32, "relay missing ntor key");
  st.x = random_bytes(32);
  st.X = x25519_public_from_private(st.x);
  st.B = relay.ntor_key;
  st.id = relay.rsa_id;
  st.bx = x25519_shared(st.x, st.B);
  Bytes hdata = st.id;
  hdata.insert(hdata.end(), st.B.begin(), st.B.end());
  hdata.insert(hdata.end(), st.X.begin(), st.X.end());
  return hdata;
}

RelayCrypto finish_ntor(const NtorState &st, const Bytes &hdata) {
  require(hdata.size() >= 64, "short ntor CREATED2 data");
  Bytes Y(hdata.begin(), hdata.begin() + 32);
  Bytes auth(hdata.begin() + 32, hdata.begin() + 64);
  Bytes yx = x25519_shared(st.x, Y);
  Bytes proto = from_string("ntor-curve25519-sha256-1");
  Bytes secret = yx;
  secret.insert(secret.end(), st.bx.begin(), st.bx.end());
  secret.insert(secret.end(), st.id.begin(), st.id.end());
  secret.insert(secret.end(), st.B.begin(), st.B.end());
  secret.insert(secret.end(), st.X.begin(), st.X.end());
  secret.insert(secret.end(), Y.begin(), Y.end());
  secret.insert(secret.end(), proto.begin(), proto.end());
  Bytes t_key = from_string("ntor-curve25519-sha256-1:key_extract");
  Bytes t_verify = from_string("ntor-curve25519-sha256-1:verify");
  Bytes t_mac = from_string("ntor-curve25519-sha256-1:mac");
  Bytes key_seed = hmac_sha256(t_key, secret);
  Bytes verify = hmac_sha256(t_verify, secret);
  Bytes auth_input = verify;
  auth_input.insert(auth_input.end(), st.id.begin(), st.id.end());
  auth_input.insert(auth_input.end(), st.B.begin(), st.B.end());
  auth_input.insert(auth_input.end(), Y.begin(), Y.end());
  auth_input.insert(auth_input.end(), st.X.begin(), st.X.end());
  auth_input.insert(auth_input.end(), proto.begin(), proto.end());
  Bytes server = from_string("Server");
  auth_input.insert(auth_input.end(), server.begin(), server.end());
  Bytes expected = hmac_sha256(t_mac, auth_input);
  require(ct_equal(auth, expected), "ntor auth mismatch");
  Bytes k = hkdf_sha256_expand(
      key_seed, from_string("ntor-curve25519-sha256-1:key_expand"), 92);
  Bytes df(k.begin(), k.begin() + 20);
  Bytes db(k.begin() + 20, k.begin() + 40);
  Bytes kf(k.begin() + 40, k.begin() + 56);
  Bytes kb(k.begin() + 56, k.begin() + 72);
  return RelayCrypto(df, db, kf, kb, RelayCrypto::DigestKind::Sha1);
}

struct RelayMessage {
  uint8_t cmd = 0;
  uint16_t stream_id = 0;
  Bytes data;
};

class Circuit {
public:
  Circuit(std::shared_ptr<TorChannel> ch, uint32_t id, RelayCrypto crypto)
      : ch_(std::move(ch)), id_(id) {
    hops_.push_back(std::move(crypto));
  }

  static Circuit create_fast(std::shared_ptr<TorChannel> ch) {
    uint32_t id = ch->new_circ_id();
    Bytes x = random_bytes(20);
    Bytes body = x;
    body.resize(kCellBodyLen, 0);
    ch->write_cell(id, CMD_CREATE_FAST, body);
    for (;;) {
      Cell c = ch->read_cell();
      if (c.circ_id != id) {
        continue;
      }
      if (c.cmd == CMD_DESTROY) {
        fail("CREATE_FAST was destroyed");
      }
      require(c.cmd == CMD_CREATED_FAST,
              "unexpected cell while waiting for CREATED_FAST");
      Bytes y(c.body.begin(), c.body.begin() + 20);
      Bytes kh(c.body.begin() + 20, c.body.begin() + 40);
      Bytes k0 = x;
      k0.insert(k0.end(), y.begin(), y.end());
      Bytes k = kdf_tor(k0, 92);
      Bytes expected_kh(k.begin(), k.begin() + 20);
      require(ct_equal(kh, expected_kh), "CREATE_FAST key hash mismatch");
      Bytes df(k.begin() + 20, k.begin() + 40);
      Bytes db(k.begin() + 40, k.begin() + 60);
      Bytes kf(k.begin() + 60, k.begin() + 76);
      Bytes kb(k.begin() + 76, k.begin() + 92);
      RelayCrypto rc(df, db, kf, kb, RelayCrypto::DigestKind::Sha1);
      return Circuit(std::move(ch), id, std::move(rc));
    }
  }

  void send_relay(uint8_t cmd, uint16_t stream_id, const Bytes &data) {
    send_relay_cell(CMD_RELAY, hops_.size() - 1, cmd, stream_id, data);
  }

  RelayMessage recv_relay() {
    for (;;) {
      Cell c = ch_->read_cell();
      if (c.circ_id != id_) {
        continue;
      }
      if (c.cmd == CMD_DESTROY) {
        fail("circuit destroyed");
      }
      if (c.cmd != CMD_RELAY) {
        continue;
      }
      Bytes body = c.body;
      for (RelayCrypto &hop : hops_) {
        body = hop.decrypt_body_only(body);
        if (hop.recognize_decrypted(body)) {
          return parse_relay_body(body);
        }
      }
    }
  }

  void send_raw_body(const Bytes &body) {
    require(body.size() == kCellBodyLen,
            "raw relay body must be one cell body");
    Bytes encrypted = body;
    for (auto it = hops_.rbegin(); it != hops_.rend(); ++it) {
      encrypted = it->encrypt_body_only(encrypted);
    }
    ch_->write_cell(id_, CMD_RELAY, encrypted);
  }

  Bytes recv_raw_body() {
    for (;;) {
      Cell c = ch_->read_cell();
      if (c.circ_id != id_) {
        continue;
      }
      if (c.cmd == CMD_DESTROY) {
        fail("rendezvous circuit destroyed");
      }
      if (c.cmd == CMD_RELAY) {
        Bytes body = c.body;
        for (RelayCrypto &hop : hops_) {
          body = hop.decrypt_body_only(body);
        }
        return body;
      }
    }
  }

  void extend_ntor(const Relay &relay) {
    NtorState st;
    Bytes hdata = build_ntor_onionskin(relay, st);
    Bytes lspec = serialize_link_specifiers(relay_link_specifiers(relay));
    Bytes data = lspec;
    put_u16(data, 2);
    put_u16(data, static_cast<uint16_t>(hdata.size()));
    data.insert(data.end(), hdata.begin(), hdata.end());
    send_relay_cell(CMD_RELAY_EARLY, hops_.size() - 1, RELAY_EXTEND2, 0, data);
    for (;;) {
      RelayMessage m = recv_relay();
      if (m.cmd == RELAY_EXTENDED2) {
        require(m.data.size() >= 2, "short EXTENDED2 body");
        uint16_t hlen = read_u16(m.data, 0);
        require(m.data.size() >= 2u + static_cast<size_t>(hlen),
                "truncated EXTENDED2 handshake");
        Bytes created(m.data.begin() + 2, m.data.begin() + 2 + hlen);
        hops_.push_back(finish_ntor(st, created));
        return;
      }
    }
  }

private:
  void send_relay_cell(uint8_t cell_cmd, size_t hop_index, uint8_t relay_cmd,
                       uint16_t stream_id, const Bytes &data) {
    require(hop_index < hops_.size(), "bad hop index");
    Bytes body = hops_[hop_index].encrypt_relay(relay_cmd, stream_id, data);
    for (size_t i = hop_index; i > 0; --i) {
      body = hops_[i - 1].encrypt_body_only(body);
    }
    ch_->write_cell(id_, cell_cmd, body);
  }

  static RelayMessage parse_relay_body(const Bytes &body) {
    require(body.size() == kCellBodyLen, "bad relay body");
    uint16_t len = read_u16(body, 9);
    require(len <= kRelayPayloadLen, "relay length too large");
    RelayMessage m;
    m.cmd = body[0];
    m.stream_id = read_u16(body, 3);
    m.data.assign(body.begin() + kRelayHeaderLen,
                  body.begin() + kRelayHeaderLen + len);
    return m;
  }

  std::shared_ptr<TorChannel> ch_;
  uint32_t id_ = 0;
  std::vector<RelayCrypto> hops_;
};

[[maybe_unused]] Bytes begin_dir_get(const Relay &relay,
                                     const std::string &path, int timeout_ms) {
  auto ch = std::make_shared<TorChannel>(relay.ip, relay.or_port, timeout_ms);
  Circuit circ = Circuit::create_fast(ch);
  circ.send_relay(RELAY_BEGIN_DIR, 1, {});
  for (;;) {
    RelayMessage m = circ.recv_relay();
    if (m.cmd == RELAY_CONNECTED && m.stream_id == 1) {
      break;
    }
    if (m.cmd == RELAY_END && m.stream_id == 1) {
      fail("BEGIN_DIR rejected by " + relay.nickname);
    }
  }
  std::ostringstream req;
  req << "GET " << path << " HTTP/1.0\r\n"
      << "Host: " << relay.ip << "\r\n"
      << "User-Agent: onionlink/0\r\n"
      << "Accept-Encoding: identity\r\n"
      << "Connection: close\r\n\r\n";
  Bytes rb = from_string(req.str());
  for (size_t off = 0; off < rb.size(); off += kRelayPayloadLen) {
    size_t n = std::min(kRelayPayloadLen, rb.size() - off);
    circ.send_relay(RELAY_DATA, 1,
                    Bytes(rb.begin() + static_cast<long>(off),
                          rb.begin() + static_cast<long>(off + n)));
  }
  Bytes response;
  int circ_window = 1000;
  int stream_window = 500;
  for (;;) {
    RelayMessage m = circ.recv_relay();
    if (m.cmd == RELAY_DATA && m.stream_id == 1) {
      response.insert(response.end(), m.data.begin(), m.data.end());
      if (--circ_window <= 900) {
        circ.send_relay(RELAY_SENDME, 0, Bytes{0, 0, 0});
        circ_window += 100;
      }
      if (--stream_window <= 450) {
        circ.send_relay(RELAY_SENDME, 1, {});
        stream_window += 50;
      }
    } else if (m.cmd == RELAY_END && m.stream_id == 1) {
      break;
    }
    if (response.size() > 8 * 1024 * 1024) {
      fail("BEGIN_DIR response too large");
    }
  }
  return decode_http_body(response);
}

Bytes begin_dir_get_via(const Relay &guard, const Relay &target,
                        const std::string &path, int timeout_ms) {
  auto ch = std::make_shared<TorChannel>(guard.ip, guard.or_port, timeout_ms);
  Circuit circ = Circuit::create_fast(ch);
  circ.extend_ntor(target);
  circ.send_relay(RELAY_BEGIN_DIR, 1, {});
  for (;;) {
    RelayMessage m = circ.recv_relay();
    if (m.cmd == RELAY_CONNECTED && m.stream_id == 1) {
      break;
    }
    if (m.cmd == RELAY_END && m.stream_id == 1) {
      fail("BEGIN_DIR rejected by " + target.nickname);
    }
  }
  std::ostringstream req;
  req << "GET " << path << " HTTP/1.0\r\n"
      << "Host: " << target.ip << "\r\n"
      << "User-Agent: onionlink/0\r\n"
      << "Accept-Encoding: identity\r\n"
      << "Connection: close\r\n\r\n";
  Bytes rb = from_string(req.str());
  for (size_t off = 0; off < rb.size(); off += kRelayPayloadLen) {
    size_t n = std::min(kRelayPayloadLen, rb.size() - off);
    circ.send_relay(RELAY_DATA, 1,
                    Bytes(rb.begin() + static_cast<long>(off),
                          rb.begin() + static_cast<long>(off + n)));
  }
  Bytes response;
  int circ_window = 1000;
  int stream_window = 500;
  for (;;) {
    RelayMessage m = circ.recv_relay();
    if (m.cmd == RELAY_DATA && m.stream_id == 1) {
      response.insert(response.end(), m.data.begin(), m.data.end());
      if (--circ_window <= 900) {
        circ.send_relay(RELAY_SENDME, 0, Bytes{0, 0, 0});
        circ_window += 100;
      }
      if (--stream_window <= 450) {
        circ.send_relay(RELAY_SENDME, 1, {});
        stream_window += 50;
      }
    } else if (m.cmd == RELAY_END && m.stream_id == 1) {
      break;
    }
    if (response.size() > 8 * 1024 * 1024) {
      fail("BEGIN_DIR response too large");
    }
  }
  return decode_http_body(response);
}

std::string extract_pem_message(const std::string &text,
                                const std::string &begin_label,
                                const std::string &end_label) {
  auto b = text.find(begin_label);
  require(b != std::string::npos, "PEM begin marker not found");
  b = text.find('\n', b);
  require(b != std::string::npos, "bad PEM begin line");
  auto e = text.find(end_label, b);
  require(e != std::string::npos, "PEM end marker not found");
  return text.substr(b + 1, e - b - 1);
}

Bytes parse_ed25519_cert_subject(const std::string &pem) {
  Bytes cert = base64_decode(extract_pem_message(
      pem, "-----BEGIN ED25519 CERT-----", "-----END ED25519 CERT-----"));
  require(cert.size() >= 1 + 1 + 4 + 1 + 32 + 1 + 64, "short ed25519 cert");
  require(cert[0] == 1, "unsupported ed25519 cert version");
  return Bytes(cert.begin() + 7, cert.begin() + 39);
}

Bytes decrypt_descriptor_layer(const Bytes &ciphertext,
                               const Bytes &secret_data,
                               const Bytes &subcredential, uint64_t revision,
                               const std::string &constant) {
  require(ciphertext.size() >= 16 + 32, "descriptor ciphertext too short");
  Bytes salt(ciphertext.begin(), ciphertext.begin() + 16);
  Bytes enc(ciphertext.begin() + 16, ciphertext.end() - 32);
  Bytes mac(ciphertext.end() - 32, ciphertext.end());
  Bytes secret_input = secret_data;
  secret_input.insert(secret_input.end(), subcredential.begin(),
                      subcredential.end());
  put_u64(secret_input, revision);
  Bytes kdf_in = secret_input;
  kdf_in.insert(kdf_in.end(), salt.begin(), salt.end());
  Bytes c = from_string(constant);
  kdf_in.insert(kdf_in.end(), c.begin(), c.end());
  Bytes keys = shake256(kdf_in, 32 + 16 + 32);
  Bytes secret_key(keys.begin(), keys.begin() + 32);
  Bytes secret_iv(keys.begin() + 32, keys.begin() + 48);
  Bytes mac_key(keys.begin() + 48, keys.end());
  Bytes mac_in;
  put_u64(mac_in, mac_key.size());
  mac_in.insert(mac_in.end(), mac_key.begin(), mac_key.end());
  put_u64(mac_in, salt.size());
  mac_in.insert(mac_in.end(), salt.begin(), salt.end());
  mac_in.insert(mac_in.end(), enc.begin(), enc.end());
  require(ct_equal(mac, sha3_256(mac_in)), "descriptor layer MAC mismatch");
  Bytes plain = aes_ctr_crypt(secret_key, enc, secret_iv);
  while (!plain.empty() && plain.back() == 0) {
    plain.pop_back();
  }
  return plain;
}

struct IntroductionPoint {
  std::vector<LinkSpecifier> links;
  Bytes ntor_key;
  Bytes auth_key;
  Bytes enc_key;
};

struct HiddenServiceDescriptor {
  std::vector<IntroductionPoint> intros;
};

struct DescriptorFetchResult {
  HiddenServiceDescriptor descriptor;
  Relay guard;
};

Relay intro_relay_from_descriptor(const IntroductionPoint &intro) {
  Relay r;
  r.nickname = "intro";
  auto hp = link_spec_ipv4(intro.links);
  require(hp.has_value(), "intro point lacks IPv4 link specifier");
  r.ip = hp->host;
  r.or_port = hp->port;
  r.ntor_key = intro.ntor_key;
  for (const LinkSpecifier &ls : intro.links) {
    if (ls.type == 2 && ls.data.size() == 20) {
      r.rsa_id = ls.data;
    } else if (ls.type == 3 && ls.data.size() == 32) {
      r.ed_id = ls.data;
    }
  }
  require(r.rsa_id.size() == 20,
          "intro point lacks RSA identity link specifier");
  require(r.ed_id.size() == 32,
          "intro point lacks Ed25519 identity link specifier");
  require(r.ntor_key.size() == 32, "intro point lacks ntor onion key");
  return r;
}

HiddenServiceDescriptor parse_inner_descriptor(const std::string &plain) {
  HiddenServiceDescriptor desc;
  std::istringstream in(plain);
  std::string line;
  IntroductionPoint *cur = nullptr;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    auto parts = split_ws(line);
    if (parts.empty()) {
      continue;
    }
    if (parts[0] == "introduction-point" && parts.size() >= 2) {
      desc.intros.push_back(IntroductionPoint{});
      cur = &desc.intros.back();
      cur->links = parse_link_specifiers(base64_decode(parts[1]));
    } else if (parts[0] == "onion-key" && cur && parts.size() >= 3 &&
               parts[1] == "ntor") {
      cur->ntor_key = base64_decode(parts[2]);
    } else if (parts[0] == "enc-key" && cur && parts.size() >= 3 &&
               parts[1] == "ntor") {
      cur->enc_key = base64_decode(parts[2]);
    } else if (parts[0] == "auth-key" && cur) {
      std::string pem = line + "\n";
      std::string cert_line;
      bool in_cert = false;
      while (std::getline(in, cert_line)) {
        if (!cert_line.empty() && cert_line.back() == '\r') {
          cert_line.pop_back();
        }
        pem += cert_line + "\n";
        if (cert_line == "-----BEGIN ED25519 CERT-----") {
          in_cert = true;
        }
        if (cert_line == "-----END ED25519 CERT-----") {
          break;
        }
      }
      require(in_cert, "auth-key missing cert");
      cur->auth_key = parse_ed25519_cert_subject(pem);
    }
  }
  desc.intros.erase(
      std::remove_if(desc.intros.begin(), desc.intros.end(),
                     [](const IntroductionPoint &ip) {
                       return ip.auth_key.size() != 32 ||
                              ip.ntor_key.size() != 32 ||
                              ip.enc_key.size() != 32 ||
                              !link_spec_ipv4(ip.links).has_value();
                     }),
      desc.intros.end());
  require(!desc.intros.empty(), "descriptor has no usable introduction points");
  return desc;
}

HiddenServiceDescriptor decrypt_hs_descriptor(const std::string &outer,
                                              const HsPeriodKeys &keys) {
  uint64_t revision = 0;
  std::istringstream in(outer);
  std::string line;
  std::string super_pem;
  bool in_super = false;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    auto parts = split_ws(line);
    if (parts.size() >= 2 && parts[0] == "revision-counter") {
      revision = std::stoull(parts[1]);
    }
    if (line == "-----BEGIN MESSAGE-----") {
      in_super = true;
      super_pem += line + "\n";
      continue;
    }
    if (in_super) {
      super_pem += line + "\n";
      if (line == "-----END MESSAGE-----") {
        in_super = false;
      }
    }
  }
  require(revision != 0 ||
              outer.find("revision-counter 0") != std::string::npos,
          "descriptor missing revision-counter");
  require(!super_pem.empty(), "descriptor missing superencrypted blob");
  Bytes super_cipher = base64_decode(extract_pem_message(
      super_pem, "-----BEGIN MESSAGE-----", "-----END MESSAGE-----"));
  Bytes first_plain =
      decrypt_descriptor_layer(super_cipher, keys.blinded, keys.subcredential,
                               revision, "hsdir-superencrypted-data");
  std::string first = to_string_lossy(first_plain);
  std::string inner_pem = extract_pem_message(first, "-----BEGIN MESSAGE-----",
                                              "-----END MESSAGE-----");
  Bytes inner_cipher = base64_decode(inner_pem);
  Bytes second_secret = keys.blinded;
  Bytes second_plain =
      decrypt_descriptor_layer(inner_cipher, second_secret, keys.subcredential,
                               revision, "hsdir-encrypted-data");
  return parse_inner_descriptor(to_string_lossy(second_plain));
}

struct HsNtorState {
  Bytes x;
  Bytes X;
  Bytes B;
  Bytes auth_key;
  Bytes bx;
  Bytes ntor_key_seed;
};

struct HsIntroPayload {
  Bytes body;
  HsNtorState state;
};

Bytes x25519_public_from_private(const Bytes &priv) {
  require(priv.size() == 32, "bad x25519 private key");
  Bytes pub(32);
  require(crypto_scalarmult_base(pub.data(), priv.data()) == 0,
          "x25519 public failed");
  return pub;
}

Bytes x25519_shared(const Bytes &priv, const Bytes &pub) {
  require(priv.size() == 32 && pub.size() == 32, "bad x25519 inputs");
  Bytes out(32);
  require(crypto_scalarmult(out.data(), priv.data(), pub.data()) == 0,
          "x25519 shared secret failed");
  return out;
}

HsIntroPayload build_introduce1(const IntroductionPoint &intro, const Relay &rp,
                                const Bytes &rend_cookie,
                                const HsPeriodKeys &keys) {
  require(rend_cookie.size() == 20, "bad rendezvous cookie");
  require(rp.ntor_key.size() == 32, "rendezvous relay missing ntor key");
  Bytes header(20, 0);
  header.push_back(2);
  put_u16(header, 32);
  header.insert(header.end(), intro.auth_key.begin(), intro.auth_key.end());
  header.push_back(0);

  Bytes plain = rend_cookie;
  plain.push_back(0);
  plain.push_back(1);
  put_u16(plain, 32);
  plain.insert(plain.end(), rp.ntor_key.begin(), rp.ntor_key.end());
  Bytes rp_lspec = serialize_link_specifiers(relay_link_specifiers(rp));
  plain.insert(plain.end(), rp_lspec.begin(), rp_lspec.end());
  if (plain.size() < 246) {
    plain.resize(246, 0);
  }

  HsNtorState st;
  st.x = random_bytes(32);
  st.X = x25519_public_from_private(st.x);
  st.B = intro.enc_key;
  st.auth_key = intro.auth_key;
  st.bx = x25519_shared(st.x, st.B);

  Bytes proto = from_string(kHsProto);
  Bytes intro_secret = st.bx;
  intro_secret.insert(intro_secret.end(), intro.auth_key.begin(),
                      intro.auth_key.end());
  intro_secret.insert(intro_secret.end(), st.X.begin(), st.X.end());
  intro_secret.insert(intro_secret.end(), st.B.begin(), st.B.end());
  intro_secret.insert(intro_secret.end(), proto.begin(), proto.end());
  Bytes info = from_string(std::string(kHsProto) + ":hs_key_expand");
  info.insert(info.end(), keys.subcredential.begin(), keys.subcredential.end());
  Bytes kdf_in = intro_secret;
  Bytes t_hsenc = from_string(std::string(kHsProto) + ":hs_key_extract");
  kdf_in.insert(kdf_in.end(), t_hsenc.begin(), t_hsenc.end());
  kdf_in.insert(kdf_in.end(), info.begin(), info.end());
  Bytes hs_keys = shake256(kdf_in, 64);
  Bytes enc_key(hs_keys.begin(), hs_keys.begin() + 32);
  Bytes mac_key(hs_keys.begin() + 32, hs_keys.end());
  Bytes encrypted = aes_ctr_crypt(enc_key, plain);

  Bytes mac_msg = header;
  mac_msg.insert(mac_msg.end(), st.X.begin(), st.X.end());
  mac_msg.insert(mac_msg.end(), encrypted.begin(), encrypted.end());
  Bytes mac = tor_mac(mac_key, mac_msg);

  Bytes body = header;
  body.insert(body.end(), st.X.begin(), st.X.end());
  body.insert(body.end(), encrypted.begin(), encrypted.end());
  body.insert(body.end(), mac.begin(), mac.end());
  return HsIntroPayload{body, st};
}

RelayCrypto finish_hs_ntor(HsNtorState &st, const Bytes &handshake_info) {
  require(handshake_info.size() >= 64, "RENDEZVOUS2 handshake too short");
  Bytes Y(handshake_info.begin(), handshake_info.begin() + 32);
  Bytes auth(handshake_info.begin() + 32, handshake_info.begin() + 64);
  Bytes yx = x25519_shared(st.x, Y);
  Bytes proto = from_string(kHsProto);
  Bytes secret = yx;
  secret.insert(secret.end(), st.bx.begin(), st.bx.end());
  secret.insert(secret.end(), st.auth_key.begin(), st.auth_key.end());
  secret.insert(secret.end(), st.B.begin(), st.B.end());
  secret.insert(secret.end(), st.X.begin(), st.X.end());
  secret.insert(secret.end(), Y.begin(), Y.end());
  secret.insert(secret.end(), proto.begin(), proto.end());
  Bytes ntor_key_seed =
      tor_mac(secret, from_string(std::string(kHsProto) + ":hs_key_extract"));
  Bytes verify =
      tor_mac(secret, from_string(std::string(kHsProto) + ":hs_verify"));
  Bytes auth_input = verify;
  auth_input.insert(auth_input.end(), st.auth_key.begin(), st.auth_key.end());
  auth_input.insert(auth_input.end(), st.B.begin(), st.B.end());
  auth_input.insert(auth_input.end(), Y.begin(), Y.end());
  auth_input.insert(auth_input.end(), st.X.begin(), st.X.end());
  auth_input.insert(auth_input.end(), proto.begin(), proto.end());
  Bytes server = from_string("Server");
  auth_input.insert(auth_input.end(), server.begin(), server.end());
  Bytes expected =
      tor_mac(auth_input, from_string(std::string(kHsProto) + ":hs_mac"));
  require(ct_equal(auth, expected), "RENDEZVOUS2 hs-ntor auth mismatch");
  st.ntor_key_seed = ntor_key_seed;
  Bytes kdf_in = ntor_key_seed;
  Bytes expand = from_string(std::string(kHsProto) + ":hs_key_expand");
  kdf_in.insert(kdf_in.end(), expand.begin(), expand.end());
  Bytes k = shake256(kdf_in, 128);
  Bytes df(k.begin(), k.begin() + 32);
  Bytes db(k.begin() + 32, k.begin() + 64);
  Bytes kf(k.begin() + 64, k.begin() + 96);
  Bytes kb(k.begin() + 96, k.begin() + 128);
  return RelayCrypto(df, db, kf, kb, RelayCrypto::DigestKind::Sha3);
}

class RendezvousStream {
public:
  RendezvousStream(Circuit circ, RelayCrypto hs_crypto)
      : circ_(std::move(circ)), hs_(std::move(hs_crypto)) {}

  void begin(uint16_t stream_id, uint16_t port) {
    Bytes target = from_string(":" + std::to_string(port));
    target.push_back(0);
    send_hs(RELAY_BEGIN, stream_id, target);
    for (;;) {
      RelayMessage m = recv_hs();
      if (m.stream_id != stream_id) {
        continue;
      }
      if (m.cmd == RELAY_CONNECTED) {
        return;
      }
      if (m.cmd == RELAY_END) {
        fail("onion service stream ended before CONNECTED");
      }
    }
  }

  void send_data(uint16_t stream_id, const Bytes &data) {
    for (size_t off = 0; off < data.size(); off += kRelayPayloadLen) {
      size_t n = std::min(kRelayPayloadLen, data.size() - off);
      send_hs(RELAY_DATA, stream_id,
              Bytes(data.begin() + static_cast<long>(off),
                    data.begin() + static_cast<long>(off + n)));
    }
  }

  Bytes read_until_end(uint16_t stream_id, size_t limit = 4 * 1024 * 1024) {
    Bytes out;
    int circ_window = 1000;
    int stream_window = 500;
    for (;;) {
      RelayMessage m = recv_hs();
      if (m.stream_id != stream_id) {
        continue;
      }
      if (m.cmd == RELAY_DATA) {
        out.insert(out.end(), m.data.begin(), m.data.end());
        if (--circ_window <= 900) {
          send_hs(RELAY_SENDME, 0, Bytes{0, 0, 0});
          circ_window += 100;
        }
        if (--stream_window <= 450) {
          send_hs(RELAY_SENDME, stream_id, {});
          stream_window += 50;
        }
        if (out.size() > limit) {
          fail("stream response too large");
        }
      } else if (m.cmd == RELAY_END) {
        break;
      }
    }
    return out;
  }

  void end(uint16_t stream_id) { send_hs(RELAY_END, stream_id, Bytes{6}); }

private:
  void send_hs(uint8_t cmd, uint16_t stream_id, const Bytes &data) {
    circ_.send_raw_body(hs_.encrypt_relay(cmd, stream_id, data));
  }

  RelayMessage recv_hs() {
    for (;;) {
      Bytes rp_plain = circ_.recv_raw_body();
      auto body = hs_.decrypt_recognized(rp_plain);
      if (!body) {
        continue;
      }
      uint16_t len = read_u16(*body, 9);
      RelayMessage m;
      m.cmd = (*body)[0];
      m.stream_id = read_u16(*body, 3);
      m.data.assign(body->begin() + kRelayHeaderLen,
                    body->begin() + kRelayHeaderLen + len);
      return m;
    }
  }

  Circuit circ_;
  RelayCrypto hs_;
};

std::string fetch_microdescriptor_doc(const HostPort &bootstrap, const Relay &r,
                                      int timeout_ms) {
  require(!r.md_digest.empty(), "relay missing microdescriptor digest");
  Bytes body =
      http_get_direct(bootstrap, "/tor/micro/d/" + r.md_digest, timeout_ms);
  return to_string_lossy(body);
}

void hydrate_microdescriptors(Consensus &consensus, const HostPort &bootstrap,
                              int timeout_ms, bool verbose) {
  std::vector<std::string> digests;
  std::set<std::string> seen;
  for (const Relay &r : consensus.relays) {
    if (!relay_usable_dir(r) || r.md_digest.empty() ||
        r.has_flag("NoEdConsensus")) {
      continue;
    }
    if (r.has_flag("HSDir")) {
      if (seen.insert(r.md_digest).second) {
        digests.push_back(r.md_digest);
      }
    }
  }
  require(!digests.empty(),
          "consensus has no microdescriptor digests to fetch");

  std::vector<HostPort> sources;
  sources.push_back(bootstrap);
  for (const Relay &r : consensus.relays) {
    if (relay_usable_dir(r) && r.dir_port != 0 && r.has_flag("V2Dir")) {
      sources.push_back(HostPort{r.ip, r.dir_port});
    }
  }
  std::shuffle(sources.begin() + 1, sources.end(),
               std::mt19937{std::random_device{}()});

  constexpr size_t kBatch = 90;
  int microdesc_timeout_ms = std::min(timeout_ms, 3000);

  struct Batch {
    size_t first = 0;
    size_t last = 0;
    std::string path;
  };
  std::vector<Batch> batches;
  for (size_t i = 0; i < digests.size(); i += kBatch) {
    size_t end = std::min(digests.size(), i + kBatch);
    Batch batch;
    batch.first = i + 1;
    batch.last = end;
    batch.path = "/tor/micro/d/";
    for (size_t j = i; j < end; ++j) {
      if (j != i) {
        batch.path.push_back('-');
      }
      batch.path += digests[j];
    }
    batches.push_back(std::move(batch));
  }

  std::map<std::string, MicrodescriptorFields> fields;
  std::mutex fields_mu;
  std::mutex log_mu;
  std::atomic<size_t> next_batch{0};
  size_t worker_count =
      std::min<size_t>(8, std::max<size_t>(1, batches.size()));
  auto worker = [&](size_t worker_id) {
    for (;;) {
      size_t idx = next_batch.fetch_add(1);
      if (idx >= batches.size()) {
        return;
      }
      const Batch &batch = batches[idx];
      if (verbose) {
        std::lock_guard<std::mutex> lock(log_mu);
        std::cerr << "fetching HSDir microdescriptors " << batch.first << "-"
                  << batch.last << " of " << digests.size() << "\n";
      }
      bool ok = false;
      std::string last_error;
      size_t attempts = std::min<size_t>(5, sources.size());
      for (size_t attempt = 0; attempt < attempts; ++attempt) {
        size_t src_idx = (idx * 7 + worker_id * 13 + attempt) % sources.size();
        const HostPort &src = sources[src_idx];
        try {
          Bytes body = http_get_direct(src, batch.path, microdesc_timeout_ms);
          auto parsed = index_microdescriptors(to_string_lossy(body));
          {
            std::lock_guard<std::mutex> lock(fields_mu);
            fields.insert(parsed.begin(), parsed.end());
          }
          ok = true;
          break;
        } catch (const std::exception &e) {
          last_error = e.what();
        }
      }
      if (!ok && verbose) {
        std::lock_guard<std::mutex> lock(log_mu);
        std::cerr << "microdescriptor batch " << batch.first << "-"
                  << batch.last << " failed after " << attempts
                  << " sources: " << last_error << "\n";
      }
    }
  };
  std::vector<std::thread> workers;
  for (size_t i = 0; i < worker_count; ++i) {
    workers.emplace_back(worker, i);
  }
  for (auto &t : workers) {
    t.join();
  }

  size_t hydrated = 0;
  for (Relay &r : consensus.relays) {
    auto it = fields.find(r.md_digest);
    if (it == fields.end()) {
      continue;
    }
    if (r.ed_id.empty()) {
      r.ed_id = it->second.ed_id;
    }
    if (r.ntor_key.empty()) {
      r.ntor_key = it->second.ntor_key;
    }
    if (r.ed_id.size() == 32 || r.ntor_key.size() == 32) {
      ++hydrated;
    }
  }
  if (verbose) {
    std::cerr << "hydrated " << hydrated << " relays from microdescriptors\n";
  }
}

DescriptorFetchResult
fetch_hidden_service_descriptor(const Consensus &consensus,
                                const HsPeriodKeys &keys, int timeout_ms,
                                bool verbose) {
  std::vector<Bytes> srvs;
  if (!consensus.shared_rand_current.empty()) {
    srvs.push_back(consensus.shared_rand_current);
  }
  if (!consensus.shared_rand_previous.empty()) {
    srvs.push_back(consensus.shared_rand_previous);
  }
  require(!srvs.empty(), "consensus has no shared-rand values");
  std::string blinded_b64 = base64_encode_unpadded(keys.blinded);
  std::string path = "/tor/hs/3/" + blinded_b64;
  std::string last_error;
  std::vector<Relay> guards = candidate_rendezvous_relays(consensus);
  for (const Bytes &srv : srvs) {
    std::vector<Relay> hsdirs = select_hsdirs(consensus, keys.blinded, srv,
                                              keys.period_num, keys.period_len);
    std::shuffle(hsdirs.begin(), hsdirs.end(),
                 std::mt19937{std::random_device{}()});
    size_t guard_pos = 0;
    for (const Relay &hsdir : hsdirs) {
      try {
        if (verbose) {
          std::cerr << "fetching descriptor from HSDir " << hsdir.nickname
                    << "\n";
        }
        Relay guard;
        bool found_guard = false;
        for (size_t tries = 0; tries < guards.size(); ++tries) {
          const Relay &candidate = guards[(guard_pos + tries) % guards.size()];
          if (candidate.ed_id != hsdir.ed_id) {
            guard = candidate;
            guard_pos = (guard_pos + tries + 1) % guards.size();
            found_guard = true;
            break;
          }
        }
        require(found_guard, "no guard available for HSDir request");
        Bytes body = begin_dir_get_via(guard, hsdir, path, timeout_ms);
        return DescriptorFetchResult{
            decrypt_hs_descriptor(to_string_lossy(body), keys), guard};
      } catch (const std::exception &e) {
        last_error = e.what();
      }
    }
  }
  fail("failed to fetch/decrypt hidden service descriptor: " + last_error);
}

struct Options {
  std::string onion;
  uint16_t port = 0;
  HostPort bootstrap{"128.31.0.39", 9131};
  std::string consensus_file;
  bool verbose = false;
  bool stdin_mode = false;
  std::string send_text;
  std::string http_get;
  int timeout_ms = 30000;
};

void usage() {
  std::cerr
      << "usage: onionlink <service.onion> <port> [options]\n"
      << "options:\n"
      << "  --bootstrap host:port      HTTP directory cache (default "
         "128.31.0.39:9131)\n"
      << "  --consensus-file path      use a local consensus-microdesc file\n"
      << "  --timeout-ms n             network timeout (default 30000)\n"
      << "  --http-get [path]          send a simple HTTP/1.0 GET after "
         "connecting\n"
      << "  --send text                send raw text after connecting\n"
      << "  --stdin                    send standard input after connecting\n"
      << "  --verbose                  print progress\n";
}

Options parse_args(int argc, char **argv) {
  if (argc >= 2) {
    std::string first = argv[1];
    if (first == "--help" || first == "-h") {
      usage();
      std::exit(0);
    }
  }
  if (argc < 3) {
    usage();
    std::exit(2);
  }
  Options opt;
  opt.onion = argv[1];
  opt.port = static_cast<uint16_t>(std::stoul(argv[2]));
  for (int i = 3; i < argc; ++i) {
    std::string a = argv[i];
    auto need_value = [&](const std::string &name) -> std::string {
      require(i + 1 < argc, name + " requires a value");
      return argv[++i];
    };
    if (a == "--bootstrap") {
      opt.bootstrap = parse_hostport(need_value(a));
    } else if (a == "--consensus-file") {
      opt.consensus_file = need_value(a);
    } else if (a == "--timeout-ms") {
      opt.timeout_ms = std::stoi(need_value(a));
    } else if (a == "--http-get") {
      if (i + 1 < argc && std::string(argv[i + 1]).rfind("--", 0) != 0) {
        opt.http_get = argv[++i];
      } else {
        opt.http_get = "/";
      }
    } else if (a == "--send") {
      opt.send_text = need_value(a);
    } else if (a == "--stdin") {
      opt.stdin_mode = true;
    } else if (a == "--verbose") {
      opt.verbose = true;
    } else if (a == "--help" || a == "-h") {
      usage();
      std::exit(0);
    } else {
      fail("unknown option: " + a);
    }
  }
  if (opt.http_get.empty() && opt.send_text.empty() && !opt.stdin_mode) {
    opt.http_get = "/";
  }
  return opt;
}

Bytes read_stdin_all() {
  return Bytes(std::istreambuf_iterator<char>(std::cin),
               std::istreambuf_iterator<char>());
}

Consensus load_consensus(const Options &opt) {
  if (!opt.consensus_file.empty()) {
    return parse_consensus(read_file_string(opt.consensus_file));
  }
  if (opt.verbose) {
    std::cerr << "fetching microdescriptor consensus from "
              << opt.bootstrap.host << ":" << opt.bootstrap.port << "\n";
  }
  Bytes doc = http_get_direct(opt.bootstrap,
                              "/tor/status-vote/current/consensus-microdesc",
                              opt.timeout_ms);
  return parse_consensus(to_string_lossy(doc));
}

[[maybe_unused]] Relay choose_rendezvous_with_ntor(const Consensus &consensus,
                                                   const HostPort &bootstrap,
                                                   int timeout_ms,
                                                   bool verbose) {
  auto candidates = candidate_rendezvous_relays(consensus);
  std::string last_error;
  for (Relay r : candidates) {
    try {
      if (r.ntor_key.size() == 32 && r.ed_id.size() == 32) {
        return r;
      }
      if (verbose) {
        std::cerr << "fetching rendezvous microdescriptor for " << r.nickname
                  << "\n";
      }
      r = parse_microdescriptor_into(
          r, fetch_microdescriptor_doc(bootstrap, r, timeout_ms));
      return r;
    } catch (const std::exception &e) {
      last_error = e.what();
    }
  }
  fail("could not fetch any rendezvous ntor key: " + last_error);
}

RendezvousStream connect_onion_service(const Options &opt,
                                       const Consensus &consensus,
                                       const HiddenServiceDescriptor &desc,
                                       const HsPeriodKeys &keys,
                                       const Relay &rp, const Relay &guard) {
  Bytes rend_cookie = random_bytes(20);
  if (opt.verbose) {
    std::cerr << "connecting to rendezvous point " << rp.nickname << " at "
              << rp.ip << ":" << rp.or_port << " via guard " << guard.nickname
              << "\n";
  }
  auto rp_ch =
      std::make_shared<TorChannel>(guard.ip, guard.or_port, opt.timeout_ms);
  Circuit rp_circ = Circuit::create_fast(rp_ch);
  if (!same_relay(guard, rp)) {
    rp_circ.extend_ntor(rp);
  }
  rp_circ.send_relay(RELAY_ESTABLISH_RENDEZVOUS, 0, rend_cookie);
  for (;;) {
    RelayMessage m = rp_circ.recv_relay();
    if (m.cmd == RELAY_RENDEZVOUS_ESTABLISHED) {
      break;
    }
  }

  std::vector<IntroductionPoint> intros = desc.intros;
  std::shuffle(intros.begin(), intros.end(),
               std::mt19937{std::random_device{}()});
  std::string last_error;
  HsNtorState ntor_state;
  bool introduced = false;
  for (const auto &intro : intros) {
    try {
      Relay intro_relay = intro_relay_from_descriptor(intro);
      if (opt.verbose) {
        std::cerr << "sending INTRODUCE1 via intro point " << intro_relay.ip
                  << ":" << intro_relay.or_port << "\n";
      }
      HsIntroPayload payload = build_introduce1(intro, rp, rend_cookie, keys);
      auto ip_ch =
          std::make_shared<TorChannel>(guard.ip, guard.or_port, opt.timeout_ms);
      Circuit ip_circ = Circuit::create_fast(ip_ch);
      if (!same_relay(guard, intro_relay)) {
        ip_circ.extend_ntor(intro_relay);
      }
      ip_circ.send_relay(RELAY_INTRODUCE1, 0, payload.body);
      for (;;) {
        RelayMessage ack = ip_circ.recv_relay();
        if (ack.cmd == RELAY_INTRODUCE_ACK) {
          require(ack.data.size() >= 2, "short INTRODUCE_ACK");
          uint16_t status = read_u16(ack.data, 0);
          require(status == 0,
                  "INTRODUCE_ACK status " + std::to_string(status));
          ntor_state = std::move(payload.state);
          introduced = true;
          break;
        }
      }
      if (introduced) {
        break;
      }
    } catch (const std::exception &e) {
      last_error = e.what();
    }
  }
  require(introduced, "all introduction points failed: " + last_error);
  if (opt.verbose) {
    std::cerr << "waiting for RENDEZVOUS2\n";
  }
  RelayCrypto hs_crypto;
  for (;;) {
    RelayMessage m = rp_circ.recv_relay();
    if (m.cmd == RELAY_RENDEZVOUS2) {
      hs_crypto = finish_hs_ntor(ntor_state, m.data);
      break;
    }
  }
  (void)consensus;
  return RendezvousStream(std::move(rp_circ), std::move(hs_crypto));
}

RendezvousStream connect_onion_service_with_retries(
    const Options &opt, const Consensus &consensus,
    const HiddenServiceDescriptor &desc, const HsPeriodKeys &keys,
    const std::vector<Relay> &preferred_guards) {
  std::vector<Relay> candidates = candidate_rendezvous_relays(consensus);
  std::vector<Relay> guards;
  for (const Relay &g : preferred_guards) {
    if (relay_usable_rendezvous(g) &&
        std::none_of(guards.begin(), guards.end(), [&](const Relay &existing) {
          return same_relay(existing, g);
        })) {
      guards.push_back(g);
    }
  }
  for (const Relay &g : candidates) {
    if (std::none_of(guards.begin(), guards.end(), [&](const Relay &existing) {
          return same_relay(existing, g);
        })) {
      guards.push_back(g);
    }
  }
  require(!guards.empty(), "no usable guard relays for rendezvous");
  std::string last_error;
  size_t rp_attempts = std::min<size_t>(12, candidates.size());
  size_t guard_attempts = std::min<size_t>(3, guards.size());
  for (size_t i = 0; i < rp_attempts; ++i) {
    for (size_t j = 0; j < guard_attempts; ++j) {
      const Relay &rp = candidates[i];
      const Relay &guard = guards[(i + j) % guards.size()];
      if (same_relay(rp, guard) && guards.size() > 1) {
        continue;
      }
      try {
        return connect_onion_service(opt, consensus, desc, keys, rp, guard);
      } catch (const std::exception &e) {
        last_error = e.what();
        if (opt.verbose) {
          std::cerr << "rendezvous attempt failed: " << last_error << "\n";
        }
      }
    }
  }
  fail("all rendezvous attempts failed: " + last_error);
}

} // namespace

#ifndef ONIONLINK_NO_MAIN
int main(int argc, char **argv) {
  try {
    require(sodium_init() >= 0, "libsodium initialization failed");
    Options opt = parse_args(argc, argv);
    OnionAddress onion = parse_onion_address(opt.onion);
    Consensus consensus = load_consensus(opt);
    HsPeriodKeys keys = derive_hs_period_keys(consensus, onion);
    if (opt.verbose) {
      std::cerr << "derived blinded key "
                << base64_encode_unpadded(keys.blinded) << " for period "
                << keys.period_num << "\n";
    }
    hydrate_microdescriptors(consensus, opt.bootstrap, opt.timeout_ms,
                             opt.verbose);
    DescriptorFetchResult desc = fetch_hidden_service_descriptor(
        consensus, keys, opt.timeout_ms, opt.verbose);
    RendezvousStream stream = connect_onion_service_with_retries(
        opt, consensus, desc.descriptor, keys, {desc.guard});
    constexpr uint16_t stream_id = 1;
    if (opt.verbose) {
      std::cerr << "opening onion service stream to port " << opt.port << "\n";
    }
    stream.begin(stream_id, opt.port);
    Bytes outbound;
    if (!opt.http_get.empty()) {
      std::string path = opt.http_get;
      if (path.empty() || path[0] != '/') {
        path.insert(path.begin(), '/');
      }
      std::ostringstream req;
      req << "GET " << path << " HTTP/1.0\r\n"
          << "Host: " << lower(opt.onion) << "\r\n"
          << "Connection: close\r\n\r\n";
      outbound = from_string(req.str());
    }
    if (!opt.send_text.empty()) {
      Bytes s = from_string(opt.send_text);
      outbound.insert(outbound.end(), s.begin(), s.end());
    }
    if (opt.stdin_mode) {
      Bytes s = read_stdin_all();
      outbound.insert(outbound.end(), s.begin(), s.end());
    }
    if (!outbound.empty()) {
      stream.send_data(stream_id, outbound);
    }
    Bytes inbound = stream.read_until_end(stream_id);
    std::cout.write(reinterpret_cast<const char *>(inbound.data()),
                    static_cast<std::streamsize>(inbound.size()));
    return 0;
  } catch (const std::exception &e) {
    std::cerr << "error: " << e.what() << "\n";
    return 1;
  }
}
#endif
