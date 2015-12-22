from click.testing import CliRunner


def test_arg(monkeypatch):
    from check_tls_certs import main
    l = []
    monkeypatch.setattr("check_tls_certs.check", lambda x: l.append(x) or [])
    runner = CliRunner()
    result = runner.invoke(main, ['example.com/www.example.com'])
    assert result.exit_code == 0
    assert l == [
        ['example.com', 'www.example.com']]
    assert result.output == u'example.com, www.example.com\n'


def test_file(monkeypatch, tmpdir):
    from check_tls_certs import main
    l = []
    monkeypatch.setattr("check_tls_certs.check", lambda x: l.append(x) or [])
    f = tmpdir.join("domains.txt")
    f.write_binary(b"example.com/www.example.com\nfoo.com\n")
    runner = CliRunner()
    result = runner.invoke(main, ['-f', f.strpath])
    assert result.exit_code == 0
    assert l == [
        ['example.com', 'www.example.com'],
        ['foo.com']]
    assert result.output == u'example.com, www.example.com\nfoo.com\n'
