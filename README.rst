check-tls-certs
===============

Check TLS certificates of domains for expiration dates and more.


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
      -f, --file FILE              File to read domains from. One per line.
      -v, --verbose / -q, --quiet  Toggle printing of infos for domains with no
                                   errors or warnings.
      --help                       Show this message and exit.

When domains are read from a file, lines starting with a ``#`` are ignored.

If a domain starts with a ``!`` it is checked to be in the list of alternate names,
but the TLS certificate for it will not be fetched and checked.
This is useful for domains that aren't accessible for some reason.

The default port 443,
to which the connection is made to fetch the certificate,
can be changed by adding it to the domain separated by a colon like ``example.com:1234``.
