from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

MODULE_PATH = Path(__file__).resolve().parents[2] / "src" / "tools" / "auth_context.py"
SPEC = spec_from_file_location("auth_context_module", MODULE_PATH)
assert SPEC and SPEC.loader
AUTH_CONTEXT = module_from_spec(SPEC)
sys.modules[SPEC.name] = AUTH_CONTEXT
SPEC.loader.exec_module(AUTH_CONTEXT)

_classify_login_result = AUTH_CONTEXT._classify_login_result
_classify_register_result = AUTH_CONTEXT._classify_register_result


def test_classify_login_result_detects_failed_login_form():
    body = """
    <html><title>Login</title>
    <form id=\"login_user\" action=\"/admin/login\">
      <input name=\"user[username]\" />
      <input name=\"user[password]\" />
      Username or Password incorrect
    </form>
    </html>
    """

    ok, reason = _classify_login_result(
        status_code=200,
        final_url="http://facts.htb/admin/login",
        location_header="",
        body=body,
        has_cookies=True,
        has_token=False,
        login_url="http://facts.htb/admin/login",
    )

    assert ok is False
    assert reason in {"failure marker in response body", "returned to login form"}


def test_classify_login_result_accepts_token_success():
    ok, reason = _classify_login_result(
        status_code=200,
        final_url="http://facts.htb/api/login",
        location_header="",
        body='{"token": "abc"}',
        has_cookies=False,
        has_token=True,
        login_url="http://facts.htb/api/login",
    )

    assert ok is True
    assert reason == "token captured"


def test_classify_login_result_accepts_redirect_away_from_login():
    ok, reason = _classify_login_result(
        status_code=302,
        final_url="http://facts.htb/admin/login",
        location_header="http://facts.htb/admin/dashboard",
        body="",
        has_cookies=True,
        has_token=False,
        login_url="http://facts.htb/admin/login",
    )

    assert ok is True
    assert reason == "redirected away from login"


def test_classify_register_result_detects_error_form():
    body = """
    <html>
      <form action=\"/admin/register\">
        <input name=\"password_confirmation\" />
      </form>
      <div class=\"alert-danger\">captcha invalid</div>
      Create an account
    </html>
    """

    ok, reason = _classify_register_result(
        status_code=200,
        final_url="http://facts.htb/admin/register",
        location_header="",
        body=body,
        register_url="http://facts.htb/admin/register",
    )

    assert ok is False
    assert reason == "registration error marker in response body"


def test_classify_register_result_accepts_redirect_away_from_register():
    ok, reason = _classify_register_result(
        status_code=302,
        final_url="http://facts.htb/admin/register",
        location_header="http://facts.htb/admin/login",
        body="",
        register_url="http://facts.htb/admin/register",
    )

    assert ok is True
    assert reason == "redirected away from register page"
