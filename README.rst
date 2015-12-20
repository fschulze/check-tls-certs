check-tls-certs
===============

Check TLS certificates of domains for expiration dates and more.


Requirements
------------

You need an ``openssl`` executable in your path for fetching the certificate from the server.


Usage
-----

::

    Usage: check_tls_certs [OPTIONS] [DOMAIN]...

      Checks the TLS certificate for each DOMAIN.

      You can add checks for alternative names by separating them with a slash,
      like example.com/www.example.com.

      Exits with return code 3 when there are warnings and code 4 when there are
      errors.

    Options:
      -f, --file FILE  File to read domains from. One per line.
      --help           Show this message and exit.
