#include <cstdlib>
#include <ctime>
#include <iostream>
#include <openssl/hmac.h>
#include <string>
#include <string_view>
#include <unistd.h>

#include "awsv4sig.hh"
#include "certificates.hh"
#include "eventloop.hh"
#include "http_client.hh"
#include "secure_socket.hh"
#include "sha256.hh"
#include "socket.hh"
#include "timer.hh"

using namespace std;

int main()
{
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
    req.headers.date = x_amz_date_( time( 0 ) );
    req.headers.connection = "close";

    string can_request = create_can_request( req );
    string string_to_sign = create_string_to_sign( req, can_request );
    calculate_sig( req, string_to_sign );

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
        cout << "got reply with code: " << resp.status_code << " and reason phrase: " << resp.reason_phrase << "\n";
        cout << "reply body: " << resp.body << endl;
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

  global_timer().summary( cout );
}
