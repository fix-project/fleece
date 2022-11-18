#include <array>
#include <string_view>

using sha256_hash = std::array<uint8_t, 32>; // equal to SHA256_DIGEST_LENGTH, but don't want to bring
                                             // OpenSSL into the global namespace

void sha256( const std::string_view input, sha256_hash& hash );
