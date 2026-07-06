import pytest
import requests

from src.tools.wordpress import wordpress_xmlrpc_audit


@pytest.fixture(autouse=True)
def clear_tool_cache():
    from src.sdk.cache import get_tool_cache
    get_tool_cache().clear()


def _response(mocker, text, status_code=200):
    response = mocker.Mock()
    response.status_code = status_code
    response.text = text
    return response


@pytest.mark.asyncio
async def test_wordpress_xmlrpc_audit_uses_https_first_and_classifies_methods(mocker):
    list_methods = """<?xml version="1.0"?>
<methodResponse><params><param><value><array><data>
<value><string>system.listMethods</string></value>
<value><string>pingback.ping</string></value>
<value><string>wp.getUsers</string></value>
</data></array></value></param></params></methodResponse>"""
    auth_fault = """<?xml version="1.0"?>
<methodResponse><fault><value><struct>
<member><name>faultCode</name><value><int>405</int></value></member>
<member><name>faultString</name><value><string>XML-RPC services are disabled on this site.</string></value></member>
</struct></value></fault></methodResponse>"""
    post = mocker.patch(
        "src.tools.wordpress.requests.post",
        side_effect=[_response(mocker, list_methods), _response(mocker, auth_fault)],
    )

    result = await wordpress_xmlrpc_audit.invoke(target="example.com")

    assert post.call_args_list[0].args[0] == "https://example.com/xmlrpc.php"
    assert "Methods exposed: 3" in result
    assert "Pingback method listed: yes" in result
    assert "no authentication bypass proven" in result.lower()


@pytest.mark.asyncio
async def test_wordpress_xmlrpc_audit_falls_back_to_http(mocker):
    list_methods = """<?xml version="1.0"?>
<methodResponse><params><param><value><array><data>
<value><string>system.listMethods</string></value>
</data></array></value></param></params></methodResponse>"""
    post = mocker.patch(
        "src.tools.wordpress.requests.post",
        side_effect=[requests.exceptions.ConnectionError("tls failed"), _response(mocker, list_methods)],
    )

    result = await wordpress_xmlrpc_audit.invoke(target="fallback-example.test", probe_auth_methods=False)

    assert post.call_args_list[0].args[0] == "https://fallback-example.test/xmlrpc.php"
    assert post.call_args_list[1].args[0] == "http://fallback-example.test/xmlrpc.php"
    assert "Confirmed Endpoint" in result


@pytest.mark.asyncio
async def test_wordpress_xmlrpc_audit_blocks_private_pingback_callback(mocker):
    list_methods = """<?xml version="1.0"?>
<methodResponse><params><param><value><array><data>
<value><string>system.listMethods</string></value>
<value><string>pingback.ping</string></value>
</data></array></value></param></params></methodResponse>"""
    post = mocker.patch("src.tools.wordpress.requests.post", return_value=_response(mocker, list_methods))

    result = await wordpress_xmlrpc_audit.invoke(
        target="pingback-example.test",
        probe_auth_methods=False,
        test_pingback=True,
        callback_url="http://169.254.169.254/latest/meta-data/",
    )

    assert post.call_count == 1
    assert "must be a controlled public URL" in result
