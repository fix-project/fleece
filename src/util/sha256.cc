#include <openssl/sha.h>

#include "sha256.hh"
#include "timer.hh"

using namespace std;

std::string sha256buf_to_string_( const unsigned char* buf )
{
  char sbuf[2 * SHA256_DIGEST_LENGTH + 1];
  for ( unsigned i = 0; i < SHA256_DIGEST_LENGTH; i++ ) {
    snprintf( &( sbuf[2 * i] ), 3, "%2.2x", buf[i] );
  }
  return string( sbuf, 2 * SHA256_DIGEST_LENGTH );
}

std::string sha256::encode( string input )
{
  unsigned char output[SHA256_DIGEST_LENGTH];

  SHA256( (const unsigned char*)input.c_str(), input.length(), output );

  return sha256buf_to_string_( output );
}
