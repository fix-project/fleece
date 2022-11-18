#include <string>

namespace sha256 {
std::string encode( std::string input );
std::string sha256buf_to_string_( const unsigned char* buf );
}
