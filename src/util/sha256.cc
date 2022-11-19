#include <openssl/sha.h>

#include "sha256.hh"

using namespace std;

static_assert( tuple_size<sha256_hash>::value == SHA256_DIGEST_LENGTH );

void sha256( const string_view input, sha256_hash& hash )
{
  SHA256( reinterpret_cast<const uint8_t*>( input.data() ), input.length(), hash.data() );
}

string_view make_view( const sha256_hash& hash )
{
  return { reinterpret_cast<const char*>( hash.data() ), hash.size() };
}
