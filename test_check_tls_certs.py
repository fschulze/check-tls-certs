from click.testing import CliRunner
from io import StringIO
import pytest
import re
import subprocess


@pytest.yield_fixture(scope="session", autouse=True)
def event_loop_closing():
    import check_tls_certs
    loop = set()

    def close_event_loop(_loop):
        loop.add(_loop)

    check_tls_certs.close_event_loop = close_event_loop
    yield
    for l in loop:
        l.close()


@pytest.fixture
def no_chain_validation(monkeypatch):
    monkeypatch.setattr(
        "check_tls_certs.validate_certificate_chain",
        lambda c, m: None)


@pytest.fixture
def makecert():
    import OpenSSL

    def makecert(cn='example.com', days=365):
        result = subprocess.check_output([
            'openssl',
            'req', '-x509',
            '-nodes',
            '-newkey', 'rsa:1024',
            '-days', '%s' % days,
            '-subj', '/C=DE/ST=Foo/L=Bar/O=Foo LTD/OU=Org/CN=%s' % cn])
        m = re.search(
            b'(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)',
            result,
            flags=re.DOTALL)
        return OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM,
            m.group(1))

    return makecert


@pytest.fixture
def utcnow():
    import datetime
    return datetime.datetime.utcnow() + datetime.timedelta(seconds=1)


def test_arg(monkeypatch):
    from check_tls_certs import main
    domain_fetches = []
    monkeypatch.setattr(
        "check_tls_certs.get_cert_from_domain",
        lambda x: domain_fetches.append(x) or (x, None))
    domain_checks = []
    monkeypatch.setattr(
        "check_tls_certs.check",
        lambda x, u, expiry_warn: domain_checks.append(x) or ([], None))
    runner = CliRunner()
    result = runner.invoke(main, ['-vv', 'example.com/www.example.com'])
    assert result.exit_code == 0
    assert [[d for d, c in x] for x in domain_checks] == [
        ['example.com', 'www.example.com']]
    assert result.output == (
        'example.com, www.example.com\n'
        '0 error(s), 0 warning(s)\n')


def test_file(monkeypatch, tmpdir):
    from check_tls_certs import main
    domain_fetches = []
    monkeypatch.setattr(
        "check_tls_certs.get_cert_from_domain",
        lambda x: domain_fetches.append(x) or (x, None))
    domain_checks = []
    monkeypatch.setattr(
        "check_tls_certs.check",
        lambda x, u, expiry_warn: domain_checks.append(x) or ([], None))
    f = tmpdir.join("domains.txt")
    f.write_binary(b"example.com/www.example.com\nfoo.com\nbar.com/\n    #none.bar.com\n    www.bar.com")
    runner = CliRunner()
    result = runner.invoke(main, ['-vv', '-f', f.strpath])
    assert result.exit_code == 0
    assert [[d for d, c in x] for x in domain_checks] == [
        ['example.com', 'www.example.com'],
        ['foo.com'],
        ['bar.com', 'www.bar.com']]
    assert result.output == (
        'example.com, www.example.com\n'
        'foo.com\n'
        'bar.com, www.bar.com\n'
        '0 error(s), 0 warning(s)\n')


def test_domain_definitions_from_cli_parse_error(capsys):
    from check_tls_certs import domain_definitions_from_cli
    with pytest.raises(SystemExit) as e:
        domain_definitions_from_cli(["foo:bar"])
    (out, err) = capsys.readouterr()
    assert "Error in definition 'foo:bar': Couldn't parse 'foo:bar', port 'bar' is not an integer" in err
    assert e.value.args == (5,)


def test_domain_definitions_from_lines_parse_error(capsys):
    from check_tls_certs import domain_definitions_from_lines
    with pytest.raises(SystemExit) as e:
        domain_definitions_from_lines(StringIO("foo:bar"))
    (out, err) = capsys.readouterr()
    assert "Error in definition starting on line 1: Couldn't parse 'foo:bar', port 'bar' is not an integer" in err
    assert e.value.args == (5,)
    with pytest.raises(SystemExit) as e:
        domain_definitions_from_lines(StringIO("# comment\nfoo:bar"))
    (out, err) = capsys.readouterr()
    assert "Error in definition starting on line 2: Couldn't parse 'foo:bar', port 'bar' is not an integer" in err
    assert e.value.args == (5,)
    with pytest.raises(SystemExit) as e:
        domain_definitions_from_lines(StringIO("# comment\nfoo:2/ham:egg"))
    (out, err) = capsys.readouterr()
    assert "Error in definition starting on line 2: Couldn't parse 'ham:egg', port 'egg' is not an integer" in err
    assert e.value.args == (5,)
    with pytest.raises(SystemExit) as e:
        domain_definitions_from_lines(StringIO("# comment\nfoo:2\nham:egg"))
    (out, err) = capsys.readouterr()
    assert "Error in definition starting on line 3: Couldn't parse 'ham:egg', port 'egg' is not an integer" in err
    assert e.value.args == (5,)


def test_domain_no_fetch():
    from check_tls_certs import Domain
    d = Domain('!foo')
    assert d.no_fetch
    assert d.host == 'foo'


def test_domain_connection_host():
    from check_tls_certs import Domain
    d = Domain('foo')
    assert d.host == 'foo'
    assert d.connection_host == 'foo'
    assert d == 'foo'
    d = Domain('foo|bar')
    assert d.host == 'foo'
    assert d.connection_host == 'bar'
    assert d == 'foo (bar)'


def test_get_cert_from_domain_no_fetch():
    from check_tls_certs import Domain
    from check_tls_certs import get_cert_from_domain
    d = Domain('!foo')
    assert get_cert_from_domain(d) == (d, None)
    assert get_cert_from_domain(d) == ("foo", None)


def test_get_cert_from_domain_socket_gaierror(monkeypatch):
    from check_tls_certs import Domain
    from check_tls_certs import get_cert_from_domain
    from unittest import mock
    import socket
    _get_cert_from_domain = mock.Mock()
    _get_cert_from_domain.side_effect = socket.gaierror
    monkeypatch.setattr(
        "check_tls_certs._get_cert_from_domain",
        _get_cert_from_domain)
    d = Domain('foo')
    result = get_cert_from_domain(d)
    (rd, e) = result
    assert rd == d
    assert isinstance(e, socket.gaierror)


def test_get_cert_from_domain_other_error(monkeypatch):
    from check_tls_certs import Domain
    from check_tls_certs import get_cert_from_domain
    from unittest import mock
    _get_cert_from_domain = mock.Mock()
    _get_cert_from_domain.side_effect = ValueError("ham")
    monkeypatch.setattr(
        "check_tls_certs._get_cert_from_domain",
        _get_cert_from_domain)
    d = Domain('foo')
    result = get_cert_from_domain(d)
    assert result == (d, _get_cert_from_domain.side_effect)


def test_check_self_signed(makecert, utcnow):
    from check_tls_certs import Domain
    from check_tls_certs import check
    d = Domain('example.com')
    cert = makecert()
    (msgs, earliest_expiration) = check([(d, [cert])], utcnow)
    (errmsg,) = [m for m in msgs if m[0] == 'error']
    assert 'Validation error' in errmsg[1]
    assert 'self signed certificate' in errmsg[1]


@pytest.mark.usefixtures('no_chain_validation')
def test_expiration_far_in_future(makecert, utcnow):
    from check_tls_certs import Domain
    from check_tls_certs import check
    d = Domain('example.com')
    cert = makecert()
    (msgs, earliest_expiration) = check([(d, [cert])], utcnow)
    (msg,) = [m for m in msgs if m[1].startswith('Valid until')]
    assert '(364 days,' in msg[1]
    assert (earliest_expiration - utcnow).days == 364


@pytest.mark.usefixtures('no_chain_validation')
def test_expiration_within_warning_range(makecert, utcnow):
    from check_tls_certs import Domain
    from check_tls_certs import check
    from check_tls_certs import default_expiry_warn
    d = Domain('example.com')
    cert = makecert(days=default_expiry_warn)
    (msgs, earliest_expiration) = check([(d, [cert])], utcnow)
    (msg,) = [m for m in msgs if 'certificate expires on' in m[1]]
    assert '(%s days,' % (default_expiry_warn - 1) in msg[1]
    assert (earliest_expiration - utcnow).days == (default_expiry_warn - 1)


@pytest.mark.usefixtures('no_chain_validation')
def test_expiration_expired(makecert, utcnow):
    from check_tls_certs import Domain
    from check_tls_certs import check
    import datetime
    d = Domain('example.com')
    cert = makecert(days=1)
    utcnow = utcnow + datetime.timedelta(days=1)
    (msgs, earliest_expiration) = check([(d, [cert])], utcnow)
    (msg,) = [m for m in msgs if 'certificate has expired on' in m[1]]
    assert msg[1].startswith('The certificate has expired on')
    assert (earliest_expiration - utcnow).days < 0


@pytest.mark.usefixtures('no_chain_validation')
def test_wildcard(makecert, utcnow):
    from check_tls_certs import Domain
    from check_tls_certs import check
    cert = makecert(cn='*.example.com')
    d = Domain('www.example.com')
    (msgs, earliest_expiration) = check([(d, [cert])], utcnow)
    errs = [m for m in msgs if "doesn't match the certificate domain" in m[1]]
    assert errs == []
    assert (earliest_expiration - utcnow).days > 360
    d = Domain('foo.bar.example.com')
    (msgs, earliest_expiration) = check([(d, [cert])], utcnow)
    (err,) = [m for m in msgs if "doesn't match the certificate domain" in m[1]]
    assert "foo.bar.example.com doesn't match the certificate domain *.example.com" in err[1]
    assert (earliest_expiration - utcnow).days > 360
