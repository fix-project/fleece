#include <iostream>

#include "socket.hh"

using namespace std;

int main()
{
  TCPSocket sock;
  sock.connect({"www.cs.stanford.edu", "http"});
  sock.write("GET / HTTP/1.1\r\nhost: www.cs.stanford.edu\r\n\r\n");

  string buf;
  buf.resize(1024);
  string_span buf_span{string_span::from_view(buf)};

  while (not sock.eof()) {
    auto len = sock.read(buf_span);
    cout << buf_span.substr(0, len);
  }
  cout << "Hello World!\n";
}
