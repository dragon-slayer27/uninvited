from uninvited import collect


def test_every_task_action_becomes_an_entry():
    # Found in review: a harmless first action must not hide a second one.
    tasks = [{
        "path": "\\Vendor\\", "name": "Helper", "state": "Ready", "runAs": "SYSTEM",
        "actions": [
            {"type": "exec", "execute": r"C:\Program Files\Vendor\helper.exe", "arguments": "--check"},
            {"type": "exec", "execute": "powershell.exe", "arguments": "-enc AAAA"},
        ],
        "triggers": [{"type": "Logon", "enabled": True}],
    }]
    entries = collect._task_entries(tasks)
    assert len(entries) == 2
    assert len({e["id"] for e in entries}) == 2
    assert entries[0]["display_name"] == "Helper (action 1 of 2)"
    assert entries[1]["command"].startswith("powershell.exe")
    assert all(e["name"] == "Helper" and e["location"] == "\\Vendor\\" for e in entries)


def test_single_action_task_keeps_its_plain_name():
    tasks = [{"path": "\\", "name": "Solo", "state": "Disabled",
              "actions": [{"type": "exec", "execute": r'""C:\Program Files\A\a.exe""', "arguments": ""}]}]
    (e,) = collect._task_entries(tasks)
    assert e["display_name"] == "Solo" and not e["enabled"]
    assert e["exe"] == r"C:\Program Files\A\a.exe"


def test_trigger_descriptions():
    assert collect.describe_triggers([{"type": "Daily", "start": "2026-10-01T03:12:00", "enabled": True}]) == "every day at 03:12"
    assert collect.describe_triggers([{"type": "Time", "start": "2026-10-01T09:00:00", "interval": "PT1H", "enabled": True}]) == "at 09:00, repeating every 1 hour"
    assert collect.describe_triggers([]) == "only when another program asks"
