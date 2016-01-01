import asyncio
import click
import datetime
import itertools
import sys
import tempfile
import OpenSSL


@asyncio.coroutine
def get_cert_from_domain(domain):
    create = asyncio.create_subprocess_exec(
        'openssl', 's_client', '-servername', domain,
        '-connect', '%s:443' % domain,
        stdin=tempfile.TemporaryFile('rb'),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT)
    proc = yield from create
    data = yield from proc.stdout.read()
    yield from proc.wait()
    if proc.returncode == 0:
        data = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, data)
    return (domain, data)


@asyncio.coroutine
def get_domain_certs(domains):
    (done, pending) = yield from asyncio.wait([
        get_cert_from_domain(x)
        for x in itertools.chain(*domains)])
    return dict(x.result() for x in done)


def check(domainnames_certs, expiry_warn=14):
    msgs = []
    domainnames = set(dnc[0] for dnc in domainnames_certs)
    for domain, cert in domainnames_certs:
        if not isinstance(cert, OpenSSL.crypto.X509):
            msgs.append(
                ('error', "Couldn't fetch certificate for %s:\n%s" % (
                    domain, cert.decode('ascii'))))
            continue
        expires = datetime.datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        today = datetime.datetime.now()
        msgs.append(
            ('info', "Issued by: %s" % cert.get_issuer().commonName))
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
        if len(domainnames) == 1:
            name = cert.get_subject().commonName
            if name != domain:
                msgs.append(
                    ('error', "The requested domain %s doesn't match the certificate domain %s." % (domain, name)))
        for index in range(cert.get_extension_count()):
            ext = cert.get_extension(index)
            if ext.get_short_name() != 'subjectAltName':
                continue
            alt_names = [
                x.strip().replace('DNS:', '')
                for x in str(ext).split(',')]
            unmatched = domainnames.difference(set(alt_names))
            if unmatched:
                msgs.append(
                    ('warning', "Unmatched alternate names %s." % ', '.join(unmatched)))
    return msgs


def check_domains(domains, domain_certs):
    result = []
    for domainnames in domains:
        domainnames_certs = [(dn, domain_certs[dn]) for dn in domainnames]
        msgs = []
        seen = set()
        for level, msg in check(domainnames_certs):
            if msg not in seen:
                seen.add(msg)
                msgs.append((level, msg))
        result.append((domainnames, msgs))
    return result


@click.command()
@click.option('-f', '--file', metavar='FILE', help='File to read domains from. One per line.')
@click.argument('domain', nargs=-1)
def main(file, domain):
    """Checks the TLS certificate for each DOMAIN.

       You can add checks for alternative names by separating them with a slash, like example.com/www.example.com.

       Exits with return code 3 when there are warnings and code 4 when there are errors.
    """
    if sys.platform == "win32":
        loop = asyncio.ProactorEventLoop()
        asyncio.set_event_loop(loop)
    else:
        loop = asyncio.get_event_loop()
    domains = []
    if file:
        domains = itertools.chain(domains, (x.strip() for x in open(file, 'r', encoding='utf-8')))
    domains = itertools.chain(domains, domain)
    domains = [x.split('/') for x in domains if x]
    domain_certs = loop.run_until_complete(get_domain_certs(domains))
    loop.close()
    warnings = 0
    errors = 0
    for domainnames, msgs in check_domains(domains, domain_certs):
        click.echo(', '.join(domainnames))
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
            click.echo(msg)
    msg = "%s error(s), %s warning(s)" % (errors, warnings)
    if errors:
        click.echo(click.style(msg, fg="red"))
        sys.exit(4)
    elif warnings:
        click.echo(click.style(msg, fg="yellow"))
        sys.exit(3)
    click.echo(click.style(msg, fg="green"))
