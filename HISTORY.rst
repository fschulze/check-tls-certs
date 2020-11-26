Changelog
=========

0.12.0 - 2020-11-26
-------------------

* Drop support for Python < 3.6.
  [fschulze]

* Fix setting hostname when using ``|``.
  [fschulze]

* Set timeout on socket before wrapping it in the SSL Connection.
  [fschulze]

* Allow overriding the threshold for expiration warnings with ``-e`` option.
  [fschulze]

* Refactor exception handling. If more than half of the domains throw an
  exception during fetch, an exit code of 6 is returned instead of 4.
  [fschulze]


0.11.0 - 2018-01-07
-------------------

* Support wildcard certificates.
  [fschulze]


0.10.0 - 2017-11-24
-------------------

* Validate the certificate chain.
  [fschulze]

* Allow specifying a host used for the actual connection using ``|``.
  [fschulze]

* Re-raise actual connection errors, so the exit code of the script indicates
  a failure.
  [fschulze]


0.9.1 - 2017-04-05
------------------

* Re-release because of premature upload.
  [fschulze]


0.9.0 - 2017-04-05
------------------

* Add 5 second timeout and print more detailed error messages.
  [fschulze]

* If a line ends in a ``/`` it is joined with the next line when reading
  domains from a file.
  [fschulze]

* Sort domain names in output.
  [fschulze]


0.8.0 - 2016-05-09
------------------

* Validate the certificate chain sent by the server.
  [fschulze]


0.7.0 - 2016-05-09
------------------

* Get current time once to avoid duplicate expiry messages.
  [fschulze]

* Mark certificates from staging server with error.
  [fschulze]


0.6.0 - 2016-02-20
------------------

* Fix comparison if there is no expiration time.
  [fschulze]

* Allow port in domain name, to which the ssl connection is made instead of the
  default 443, be specified.


0.5.0 - 2016-02-17
------------------

* Use UTC time to calculate expiration time.
  [fschulze]

* Add another verbosity level (and remove ``-q/--quite``). By default nothing
  is printed except when there are errors. The first level ``-v`` always
  prints the earliest expiration date. The second level ``-vv`` prints all the
  info.


0.4.0 - 2016-02-12
------------------

* When prefixing a domain with a ``!`` the certificate will not be fetched and
  checked, but it's name well be checked to be in the list of alternate names.
  [fschulze]

* Change handling of alternate names, so checking for just one domain when a
  certificate is valid for several works.
  [fschulze]

* By default only print messages for domains with errors. Use ``-v`` option
  to print infos for all domains.
  [fschulze]

* Allow comments starting with ``#`` in domain file.
  [fschulze]

* Get rid of ``openssl`` executable requirement.
  [fschulze]


0.3.0 - 2016-01-01
------------------

* Use asyncio to fetch certificates in parallel.
  [fschulze]


0.2.0 - 2015-12-22
------------------

* Actually support Python 3.4 as advertised.
  [fschulze]

* Fix packaging.
  [witsch]

* Round expiry time delta to minutes for nicer output.
  [fschulze]

* Skip duplicate messages for alternate names.
  [fschulze]

* Add certificate issuer to output.
  [fschulze]

* Mark sha1 certificate signature as error.
  [fschulze]


0.1.0 - 2015-12-20
------------------

* Initial release
  [fschulze]
