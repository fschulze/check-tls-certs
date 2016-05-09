import asyncio
import click
import datetime
import itertools
import ssl
import sys
import OpenSSL


class Domain(str):
    def __new__(cls, domain):
        if domain.startswith('!'):
            name = domain[1:]
        else:
            name = domain
        host = name
        port = 443
        if ':' in name:
            host, port = name.split(':')
            port = int(port)
        result = str.__new__(cls, name)
        if domain.startswith('!'):
            result.no_fetch = True
        else:
            result.no_fetch = False
        result.host = host
        result.port = port
        return result


def get_cert_from_domain(domain):
    if domain.no_fetch:
        return (domain, None)
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with ssl.create_connection((domain.host, domain.port)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as sslsock:
                dercert = sslsock.getpeercert(True)
        data = ssl.DER_cert_to_PEM_cert(dercert)
        data = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, data)
    except Exception as e:
        data = str(e)
    return (domain, data)


def close_event_loop(loop):
    # just a separate function, so this can be monkeypatched in tests
    loop.close()


def get_domain_certs(domains):
    loop = asyncio.get_event_loop()
    (done, pending) = loop.run_until_complete(asyncio.wait([
        loop.run_in_executor(None, get_cert_from_domain, x)
        for x in itertools.chain(*domains)]))
    close_event_loop(loop)
    return dict(x.result() for x in done)


def check(domainnames_certs, expiry_warn=14):
    msgs = []
    domainnames = set(dnc[0].host for dnc in domainnames_certs)
    earliest_expiration = None
    today = datetime.datetime.utcnow()
    for domain, cert in domainnames_certs:
        if cert is None:
            continue
        if not isinstance(cert, OpenSSL.crypto.X509):
            msgs.append(
                ('error', "Couldn't fetch certificate for %s:\n%s" % (
                    domain, cert)))
            continue
        expires = datetime.datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        if expires:
            if earliest_expiration is None or expires < earliest_expiration:
                earliest_expiration = expires
        issued_level = "info"
        if cert.get_issuer().commonName.lower() == "happy hacker fake ca":
            issued_level = "error"
        msgs.append(
            (issued_level, "Issued by: %s" % cert.get_issuer().commonName))
        sig_alg = cert.get_signature_algorithm()
        if sig_alg.startswith(b'sha1'):
            msgs.append(
                ('error', "Unsecure signature algorithm %s" % sig_alg))
        if expires < today:
            msgs.append(
                ('error', "The certificate has expired on %s." % expires))
        elif expires < (today + datetime.timedelta(days=expiry_warn)):
            msgs.append(
                ('warning', "The certificate expires on %s (%s)." % (
                    expires, expires - today)))
        else:
            # rounded delta
            delta = ((expires - today) // 60 // 10 ** 6) * 60 * 10 ** 6
            msgs.append(
                ('info', "Valid until %s (%s)." % (expires, delta)))
        alt_names = set()
        for index in range(cert.get_extension_count()):
            ext = cert.get_extension(index)
            if ext.get_short_name() != b'subjectAltName':
                continue
            alt_names.update(
                x.strip().replace('DNS:', '')
                for x in str(ext).split(','))
        alt_names.add(cert.get_subject().commonName)
        unmatched = domainnames.difference(alt_names)
        if unmatched:
            msgs.append(
                ('info', "Alternate names in certificate: %s" % ', '.join(
                    sorted(alt_names, key=lambda x: list(reversed(x.split('.')))))))
            if len(domainnames) == 1:
                name = cert.get_subject().commonName
                if name != domain.host:
                    msgs.append(
                        ('error', "The requested domain %s doesn't match the certificate domain %s." % (domain, name)))
            else:
                msgs.append(
                    ('warning', "Unmatched alternate names %s." % ', '.join(
                        unmatched)))
        elif domainnames == alt_names:
            msgs.append(
                ('info', "Alternate names match specified domains."))
        else:
            unmatched = alt_names.difference(domainnames)
            msgs.append(
                ('warning', "More alternate names than specified %s." % ', '.join(
                    unmatched)))
    return (msgs, earliest_expiration)


def check_domains(domains, domain_certs):
    result = []
    for domainnames in domains:
        domainnames_certs = [(dn, domain_certs[dn]) for dn in domainnames]
        msgs = []
        seen = set()
        earliest_expiration = None
        (dmsgs, expiration) = check(domainnames_certs)
        for level, msg in dmsgs:
            if expiration:
                if earliest_expiration is None or expiration < earliest_expiration:
                    earliest_expiration = expiration
            if msg not in seen:
                seen.add(msg)
                msgs.append((level, msg))
        result.append((domainnames, msgs, earliest_expiration))
    return result


@click.command()
@click.option('-f', '--file', metavar='FILE', help='File to read domains from. One per line.')
@click.option('-v', '--verbose', count=True, help='Increase verbosity. Can be used several times. Currently max verbosity is 2.')
@click.argument('domain', nargs=-1)
def main(file, domain, verbose):
    """Checks the TLS certificate for each DOMAIN.

       You can add checks for alternative names by separating them with a slash, like example.com/www.example.com.

       Exits with return code 3 when there are warnings and code 4 when there are errors.
    """
    domains = []
    if file:
        domains = itertools.chain(domains, (x.strip() for x in open(file, 'r', encoding='utf-8')))
    domains = itertools.chain(domains, domain)
    domains = [
        [Domain(d) for d in x.split('/')]
        for x in domains
        if x and not x.startswith('#')]
    domain_certs = get_domain_certs(domains)
    total_warnings = 0
    total_errors = 0
    earliest_expiration = None
    for domainnames, msgs, expiration in check_domains(domains, domain_certs):
        if expiration:
            if earliest_expiration is None or expiration < earliest_expiration:
                earliest_expiration = expiration
        warnings = 0
        errors = 0
        domain_msgs = [', '.join(domainnames)]
        for level, msg in msgs:
            if level == 'error':
                color = 'red'
                errors = errors + 1
            elif level == 'warning':
                color = 'yellow'
                warnings = warnings + 1
            else:
                color = None
            if color:
                msg = click.style(msg, fg=color)
            msg = "\n".join("    " + m for m in msg.split('\n'))
            domain_msgs.append(msg)
        if (verbose > 1) or warnings or errors:
            click.echo('\n'.join(domain_msgs))
        total_errors = total_errors + errors
        total_warnings = total_warnings + warnings
    msg = "%s error(s), %s warning(s)" % (total_errors, total_warnings)
    today = datetime.datetime.utcnow()
    if earliest_expiration:
        msg += "\nEarliest expiration on %s (%s)." % (
            earliest_expiration, earliest_expiration - today)
    if total_errors:
        click.echo(click.style(msg, fg="red"))
        sys.exit(4)
    elif total_warnings:
        click.echo(click.style(msg, fg="yellow"))
        sys.exit(3)
    if verbose:
        click.echo(click.style(msg, fg="green"))
