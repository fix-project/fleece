#include <array>
#include <string_view>

using sha256_hash = std::array<uint8_t, 32>; // equal to SHA256_DIGEST_LENGTH, but don't want to bring
                                             // OpenSSL into the global namespace

sha256_hash sha256( const std::string_view input );

std::string_view make_view( const sha256_hash& hash );

sha256_hash hmac_sha256( const std::string_view secret_k, const std::string_view input );
