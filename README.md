# LibreSSL-Example
Cross-Platform LibreSSL Echo Server

On windows, open the Visual Studio project.<br/ >
On Unix-like systems, you need LibreSSL installed, and a Makefile is supplied in the "LibreSSLTesting" folder<br/ >
On all platforms, self-signed certificates are supplied.

Unix usage:

    $ ./LibreSSL-Example [port:1234]


To test from the command-line:

    $ openssl s_client -connect 127.0.0.1:1234
