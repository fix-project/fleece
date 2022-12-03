#include "http_structures.hh"
#include <string>

using namespace std;

void calculate_sig( HTTPRequest& req, string string_to_sign );

string create_string_to_sign( HTTPRequest& req, string can_request );

string create_can_request( HTTPRequest& req );

string x_amz_date_( const time_t& t );
