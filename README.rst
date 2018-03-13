check-tls-certs
===============

Check TLS certificates of domains for expiration dates and more.


Installation
------------

It's recommended to use Python 3.5 or newer on macOS,
because DNS lookups work in parallel and thus much faster when checking several domains.

Best installed via `pipsi`_::

    % pipsi install check-tls-certs

Or some other way to install a python package with included scripts.

.. _pipsi: https://pypi.python.org/pypi/pipsi


Usage
-----

::

    Usage: check_tls_certs [OPTIONS] [DOMAIN]...

      Checks the TLS certificate for each DOMAIN.

      You can add checks for alternative names by separating them with a slash,
      like example.com/www.example.com.

      Wildcard domains are supported.

      Exits with return code 3 when there are warnings, code 4 when there are
      errors, code 6 when more than half of the domains raised an exception
      during fetch and code 5 when the domain definition contains errors.

    Options:
      -f, --file FILE  File to read domains from. One per line.
      -v, --verbose    Increase verbosity. Can be used several times. Currently
                       max verbosity is 2.
      --help           Show this message and exit.


When domains are read from a file, lines starting with a ``#`` are ignored.
If a line in a file ends in a ``/``, it is joined with the next line.
This allows you to group many domains using the same certificate.

If a domain starts with a ``!`` it is checked to be in the list of alternate names,
but the TLS certificate for it will not be fetched and checked.
This is useful for domains that aren't accessible for some reason.

The default port 443,
to which the connection is made to fetch the certificate,
can be changed by adding it to the domain separated by a colon like ``example.com:1234``.

You can change the actually used host used for the connection by separating it with a ``|`` symbol,
for example ``example.com|192.168.0.1`` will use the IP ``192.168.0.1`` to connect.
