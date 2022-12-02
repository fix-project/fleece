#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include "awsv4sig.hh"
#include "exception.hh"
#include "http_structures.hh"
#include "sha256.hh"

using namespace std;

string parse_date( string date )
{
  return date.substr( 0, 8 );
}

void calculate_sig( HTTPRequest& req, string string_to_sign )
{
  string date = parse_date( req.headers.date );
  string region = "us-east-1";
  string service = "lambda";
  string composed_key = "AWS4"s + notnull( "getting AWS_SECRET_ACCESS_KEY", getenv( "AWS_SECRET_ACCESS_KEY" ) );

  sha256_hash kDate = hmac_sha256( composed_key, date );
  sha256_hash kRegion = hmac_sha256( make_view( kDate ), region );
  sha256_hash kService = hmac_sha256( make_view( kRegion ), service );
  sha256_hash kSigning = hmac_sha256( make_view( kService ), "aws4_request" );

  sha256_hash final_sig = hmac_sha256( make_view( kSigning ), string_to_sign );
  stringstream ss;
  for ( int ch : final_sig ) {
    ss << hex << setw( 2 ) << setfill( '0' ) << ch;
  }

  cout << "SIGNATURE STRING:" << endl;
  cout << ss.str() << endl;
  cout << "====================" << endl;

  string key_id = notnull( "getting AWS_ACCESS_KEY_ID", getenv( "AWS_ACCESS_KEY_ID" ) );

  stringstream ss2;
  ss2 << "AWS4-HMAC-SHA256 Credential=" << key_id;
  ss2 << "/" << parse_date( req.headers.date ) << "/us-east-1/lambda/aws4_request, ";
  ss2 << "SignedHeaders=host;x-amz-date, ";
  ss2 << "Signature=" << ss.str();

  cout << "AUTHORIZATION HEADER CONTENTS:" << endl;
  cout << ss2.str() << endl;

  req.headers.authorization = ss2.str();
}

string x_amz_date_( const time_t& t )
{
  char sbuf[17];
  strftime( sbuf, 17, "%Y%m%dT%H%M%SZ", gmtime( &t ) );
  return string( sbuf, 16 );
}

string create_string_to_sign( HTTPRequest& req, string can_request )
{
  stringstream res;
  res << "AWS4-HMAC-SHA256\n";
  res << req.headers.date + "\n";
  res << parse_date( req.headers.date ) << "/us-east-1/lambda/aws4_request\n";
  sha256_hash hash_can_req = sha256( can_request );
  for ( int ch : hash_can_req ) {
    res << hex << setw( 2 ) << setfill( '0' ) << ch;
  }

  cout << "STRING TO SIGN:" << endl;
  cout << res.str() << endl;
  cout << "====================" << endl;

  return res.str();
}

string create_can_request( HTTPRequest& req )
{
  stringstream can_req;
  can_req << req.method + "\n";
  can_req << req.request_target + "\n";
  can_req << "\n"; // assuming no query string, so just blank line
  can_req << "host:" + req.headers.host + "\n" + "x-amz-date:" + req.headers.date + "\n"
               + "\n"; // need an extra newline at the end of the canonical headers
  can_req << "host;x-amz-date\n";

  sha256_hash hash = sha256( req.body );
  for ( int ch : hash ) {
    can_req << hex << setw( 2 ) << setfill( '0' ) << ch;
  }

  cout << "CANONICAL REQUEST:" << endl;
  cout << can_req.str() << endl;
  cout << "====================" << endl;

  return can_req.str();
}