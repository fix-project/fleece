#include "sha256.hh"
#include "exception.hh"
#include <openssl/hmac.h>
#include <openssl/sha.h>

using namespace std;

static_assert( tuple_size<sha256_hash>::value == SHA256_DIGEST_LENGTH );

sha256_hash sha256( const string_view input )
{
  sha256_hash hash;
  notnull( "sha256", SHA256( reinterpret_cast<const uint8_t*>( input.data() ), input.length(), hash.data() ) );
  return hash;
}

string_view make_view( const sha256_hash& hash )
{
  return { reinterpret_cast<const char*>( hash.data() ), hash.size() };
}

sha256_hash hmac_sha256( const string_view secret_k, const string_view input )
{
  sha256_hash output;
  notnull( "hmac",
           HMAC( notnull( "EVP_sha256", EVP_sha256() ),
                 secret_k.data(),
                 secret_k.size(),
                 reinterpret_cast<const uint8_t*>( input.data() ),
                 input.size(),
                 output.data(),
                 nullptr ) );
  return output;
}
