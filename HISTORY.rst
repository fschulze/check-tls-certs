Changelog
=========

0.4.0 - Unreleased
------------------

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
