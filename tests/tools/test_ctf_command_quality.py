from src.tools.forensics import _command_quality_error


def test_blocks_invalid_ldapsearch_h_option():
    message = _command_quality_error(
        'ldapsearch -x -h 10.129.75.231 -b "dc=checkpoint,dc=htb" "(objectclass=*)"'
    )

    assert message is not None
    assert "ldapsearch -h" in message
    assert "-H ldap://" in message


def test_blocks_raw_crackmapexec_when_netexec_should_be_used():
    message = _command_quality_error("crackmapexec smb 10.129.75.231 -u '' -p ''")

    assert message is not None
    assert "nxc smb" in message


def test_blocks_winrm_curl_status_as_auth_proof():
    message = _command_quality_error(
        'curl -s -o /dev/null -w "%{http_code}" http://10.129.75.231:5985/wsman -u "admin:admin"'
    )

    assert message is not None
    assert "WinRM" in message
    assert "HTTP 405" in message


def test_blocks_invalid_timeout_pipeline():
    message = _command_quality_error("nc -z -v 10.129.75.231 9389 2>&1 | timeout 5")

    assert message is not None
    assert "timeout 5 <command>" in message


def test_blocks_getnpusers_no_pass_without_user_source():
    message = _command_quality_error("GetNPUsers.py checkpoint.htb/ -dc-ip 10.129.75.231 -no-pass")

    assert message is not None
    assert "-usersfile" in message


def test_allows_getnpusers_with_usersfile():
    message = _command_quality_error(
        "GetNPUsers.py checkpoint.htb/ -dc-ip 10.129.75.231 -usersfile valid_users.txt -no-pass"
    )

    assert message is None


def test_allows_getnpusers_with_single_username():
    message = _command_quality_error(
        "GetNPUsers.py checkpoint.htb/administrator -dc-ip 10.129.75.231 -no-pass"
    )

    assert message is None
