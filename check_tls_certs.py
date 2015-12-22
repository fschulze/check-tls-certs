import click
import datetime
import itertools
import subprocess
import sys
import tempfile
import OpenSSL


def check(domainnames, expiry_warn=14):
    msgs = []
    for domain in domainnames:
        cmd = [
            'openssl', 's_client', '-servername', domain,
            '-connect', '%s:443' % domain]
        result = subprocess.check_output(
            cmd,
            stdin=tempfile.TemporaryFile('rb'),
            stderr=tempfile.TemporaryFile())
        cert = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, result)
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
            unmatched = set(domainnames).difference(set(alt_names))
            if unmatched:
                msgs.append(
                    ('warning', "Unmatched alternate names %s." % ', '.join(unmatched)))
    return msgs


@click.command()
@click.option('-f', '--file', metavar='FILE', help='File to read domains from. One per line.')
@click.argument('domain', nargs=-1)
def main(file, domain):
    """Checks the TLS certificate for each DOMAIN.

       You can add checks for alternative names by separating them with a slash, like example.com/www.example.com.

       Exits with return code 3 when there are warnings and code 4 when there are errors.
    """
    domains = []
    if file:
        domains = itertools.chain(domains, (x.strip() for x in open(file, 'r', encoding='utf-8')))
    domains = itertools.chain(domains, domain)
    domains = (x.split('/') for x in domains if x)
    warnings = 0
    errors = 0
    for domainnames in domains:
        click.echo(', '.join(domainnames))
        seen = set()
        for level, msg in check(domainnames):
            if level == 'error':
                color = 'red'
                errors = errors + 1
            elif level == 'warning':
                color = 'yellow'
                warnings = warnings + 1
            else:
                color = None
            if msg not in seen:
                seen.add(msg)
                if color:
                    msg = click.style(msg, fg=color)
                click.echo("    " + msg)
    if errors:
        sys.exit(4)
    elif warnings:
        sys.exit(3)
