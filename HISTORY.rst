Changelog
=========

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
