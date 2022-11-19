#include <cstdlib>
#include <ctime>
#include <iostream>
#include <openssl/hmac.h>
#include <string>
#include <string_view>
#include <unistd.h>

#include "certificates.hh"
#include "eventloop.hh"
#include "http_client.hh"
#include "secure_socket.hh"
#include "sha256.hh"
#include "socket.hh"
#include "timer.hh"

using namespace std;

void calculate_sig( string string_to_sign )
{
  string date = "20221118";
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
    ss << hex << ch;
  }
}

string x_amz_date_( const time_t& t )
{
  char sbuf[17];
  strftime( sbuf, 17, "%Y%m%dT%H%M%SZ", gmtime( &t ) );
  return string( sbuf, 16 );
}

string create_string_to_sign( string can_request )
{
  stringstream res;
  res << "AWS4-HMAC-SHA256\n";
  res << x_amz_date_( time( 0 ) ) + "\n";
  res << "20221118/us-east-1/iam/aws4_request\n";
  sha256_hash hash_can_req = sha256( can_request );
  for ( int ch : hash_can_req ) {
    res << hex << ch;
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
  can_req << "\n";                                     // assuming no query string, so just blank line
  can_req << "host:" + req.headers.host + "\n" + "\n"; // need an extra newline at the end of the canonical headers
  can_req << "host\n";

  sha256_hash hash = sha256( req.body );
  for ( int ch : hash ) {
    can_req << hex << ch;
  }

  cout << "CANONICAL REQUEST:" << endl;
  cout << can_req.str() << endl;
  cout << "====================" << endl;

  return can_req.str();
}

int main()
{
  const string hostname { "lambda.us-east-1.amazonaws.com" };
  HTTPRequest req;
  req.method = "GET";
  req.request_target = "/2016-08-19/account-settings/";
  req.http_version = "HTTP/1.1";
  req.headers.host = hostname;
  req.headers.connection = "close";
  string can_request = create_can_request( req );
  string string_to_sign = create_string_to_sign( can_request );
  calculate_sig( string_to_sign );

  /*
  FileDescriptor output { CheckSystemCall( "dup", dup( STDOUT_FILENO ) ) };
  output.set_blocking( false );

  SSLClientContext context;
  context.trust_certificate( aws_root_ca_1 );
  const string hostname { "lambda.us-east-1.amazonaws.com" };
  SSLSession sess { context.make_SSL_handle(), {}, hostname };
  sess.socket().set_blocking( false );

  sess.socket().connect( { hostname, "https" } );

  HTTPClient client;
  {
    HTTPRequest req;
    req.method = "GET";
    req.request_target = "/2016-08-19/account-settings/";
    req.http_version = "HTTP/1.1";
    req.headers.host = hostname;
    req.headers.connection = "close";
    client.push_request( move( req ) );
  }

  EventLoop loop;
  HTTPResponse resp;

  loop.add_rule(
    "SSL read", sess.socket(), Direction::In, [&] { sess.do_read(); }, [&] { return sess.want_read(); } );

  loop.add_rule(
    "SSL write", sess.socket(), Direction::Out, [&] { sess.do_write(); }, [&] { return sess.want_write(); } );

  loop.add_rule(
    "Receive reply",
    [&] {
      bool is_done = client.read( sess.inbound_plaintext(), resp );
      if ( is_done ) {
        cout << "got reply with code: " << resp.status_code << " and reason phrase " << resp.reason_phrase << "\n";
      }
    },
    [&] { return not sess.inbound_plaintext().readable_region().empty(); } );

  loop.add_rule(
    "Send req",
    [&] { client.write( sess.outbound_plaintext() ); },
    [&] { return !client.requests_empty() && !sess.outbound_plaintext().writable_region().empty(); } );

  while ( loop.wait_next_event( -1 ) != EventLoop::Result::Exit ) {}

  cout << "\n";

  loop.summary( cout );

  cout << "\n";

  global_timer().summary( cout ); */
}
