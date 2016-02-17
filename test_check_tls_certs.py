from click.testing import CliRunner
import pytest


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


def test_arg(monkeypatch):
    from check_tls_certs import main
    l = []
    monkeypatch.setattr(
        "check_tls_certs.check",
        lambda x: l.append(x) or ([], None))
    runner = CliRunner()
    result = runner.invoke(main, ['-vv', 'example.com/www.example.com'])
    assert result.exit_code == 0
    assert [[d for d, c in x] for x in l] == [
        ['example.com', 'www.example.com']]
    assert result.output == (
        'example.com, www.example.com\n'
        '0 error(s), 0 warning(s)\n')


def test_file(monkeypatch, tmpdir):
    from check_tls_certs import main
    l = []
    monkeypatch.setattr(
        "check_tls_certs.check",
        lambda x: l.append(x) or ([], None))
    f = tmpdir.join("domains.txt")
    f.write_binary(b"example.com/www.example.com\nfoo.com\n")
    runner = CliRunner()
    result = runner.invoke(main, ['-vv', '-f', f.strpath])
    assert result.exit_code == 0
    assert [[d for d, c in x] for x in l] == [
        ['example.com', 'www.example.com'],
        ['foo.com']]
    assert result.output == (
        'example.com, www.example.com\n'
        'foo.com\n'
        '0 error(s), 0 warning(s)\n')
