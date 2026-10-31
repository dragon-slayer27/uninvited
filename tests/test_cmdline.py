from uninvited import cmdline


def test_quoted_executable_with_arguments():
    exe, args = cmdline.split_command(r'"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background')
    assert exe == r"C:\Program Files\Microsoft OneDrive\OneDrive.exe"
    assert args == "/background"


def test_unquoted_path_with_spaces_stops_at_extension():
    exe, args = cmdline.split_command(r"C:\Program Files\OpenVPN Connect\OpenVPNConnect.exe --opened-at-login --minimize")
    assert exe == r"C:\Program Files\OpenVPN Connect\OpenVPNConnect.exe"
    assert args == "--opened-at-login --minimize"


def test_environment_variables_are_expanded(monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\x\AppData\Local")
    exe, _ = cmdline.split_command(r'"%LOCALAPPDATA%\Discord\Update.exe" --processStart Discord.exe')
    assert exe == r"C:\Users\x\AppData\Local\Discord\Update.exe"


def test_service_style_prefixes(monkeypatch):
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    assert cmdline.expand(r"\SystemRoot\System32\drivers\x.sys") == r"C:\Windows\System32\drivers\x.sys"
    assert cmdline.expand(r"system32\svchost.exe") == r"C:\Windows\system32\svchost.exe"
    assert cmdline.expand(r"\??\C:\Tools\a.exe") == r"C:\Tools\a.exe"


def test_rundll32_payload_is_the_dll():
    exe, args, target = cmdline.target_of(r'C:\Windows\System32\rundll32.exe "C:\Users\x\AppData\Local\Temp\evil.dll",Start')
    assert exe.lower().endswith("rundll32.exe")
    assert target == r"C:\Users\x\AppData\Local\Temp\evil.dll"


def test_cmd_delete_is_not_a_payload():
    _, _, target = cmdline.target_of(r'C:\WINDOWS\system32\cmd.exe /q /c del /q "C:\Program Files\Microsoft OneDrive\Update\OneDriveSetup.exe"')
    assert target.lower().endswith("cmd.exe")


def test_wscript_payload():
    _, _, target = cmdline.target_of(r'wscript.exe //B "C:\Users\Public\run.vbs"')
    assert target == r"C:\Users\Public\run.vbs"


def test_empty_command():
    assert cmdline.split_command("") == ("", "")
    assert cmdline.target_of("")[2] == ""
