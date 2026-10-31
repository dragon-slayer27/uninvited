from datetime import datetime, timezone

from uninvited import wakes


def ev(eid, time, reason, text=None, **data):
    d = {"Reason": str(reason)}
    d.update({k: str(v) for k, v in data.items()})
    return {"id": eid, "time": time, "reasonText": text, "data": d}


def test_parse_time_with_seven_fraction_digits():
    t = wakes.parse_time("2026-10-28T07:25:42.3820027Z")
    assert t == datetime(2026, 10, 28, 7, 25, 42, 382002, tzinfo=timezone.utc)


def test_classify():
    assert wakes.classify("Input Keyboard") == "you"
    assert wakes.classify("Lid") == "you"
    assert wakes.classify("AC/DC Display Burst Suppressed") == "charger"
    assert wakes.classify("Austerity Battery Drain Budget Exceeded") == "windows"
    assert wakes.classify("16777220") == "unknown"


def test_reason_falls_back_to_code_table():
    assert wakes.reason_of({"data": {"Reason": "55"}, "reasonText": None}) == (55, "Austerity Battery Drain Budget Exceeded")
    assert wakes.reason_of({"data": {"Reason": "16777220"}, "reasonText": "16777220"}) == (16777220, "16777220")


def test_sessions_pair_enter_and_exit_and_measure_drain():
    events = [
        ev(506, "2026-10-30T20:00:00Z", 12, "Idle Timeout", BatteryRemainingCapacityOnEnter=50000, BatteryFullChargeCapacityOnEnter=60000),
        ev(507, "2026-10-30T22:00:00Z", 55, "Austerity Battery Drain Budget Exceeded", DurationInUs=7200 * 10**6,
           DripsResidencyInUs=3600 * 10**6, ActiveResidencyInUs=1800 * 10**6, BatteryRemainingCapacityOnExit=48800,
           BatteryFullChargeCapacityOnExit=60000, PowerStateAc="false", LidOpenState="false"),
        ev(506, "2026-10-30T22:00:30Z", 55, "Austerity Battery Drain Budget Exceeded"),
        ev(507, "2026-10-30T23:00:00Z", 15, "Lid", DurationInUs=3600 * 10**6, PowerStateAc="true"),
    ]
    s = wakes.sessions(events)
    assert len(s) == 2
    first = s[0]
    assert first["class"] == "windows" and round(first["drained_pct"], 2) == 2.0
    assert round(first["drips_pct"]) == 50 and first["active_s"] == 1800
    assert first["awake_after_s"] == 30
    assert s[1]["class"] == "you" and s[1]["drained_pct"] is None  # on the charger


def test_analyze_counts_nights_and_unknown_codes():
    # 2026-10-30T20:30Z is 02:00 in UTC+5:30 but we only rely on the machine's local time; use naive checks.
    events = [
        ev(506, "2026-10-29T10:00:00Z", 12, "Idle Timeout"),
        ev(507, "2026-10-29T11:00:00Z", 16777220, "16777220", DurationInUs=3600 * 10**6),
        ev(506, "2026-10-29T11:00:10Z", 12, "Idle Timeout"),
        ev(507, "2026-10-29T12:00:00Z", 31, "Input Keyboard", DurationInUs=3000 * 10**6),
    ]
    scan = {"standby": events, "log_start": "2026-10-28T00:00:00Z", "collected_at": "2026-10-30T00:00:00Z",
            "wake_timers": {"ac": 1, "dc": 1}, "wake_armed": ["HID Keyboard Device"]}
    w = wakes.analyze(scan)
    assert w["exits"] == 2 and w["not_you"] == 1
    assert w["unknown_codes"] == {"16777220": 1}
    assert w["window_days"] == 2.0
    assert sum(sum(v) for v in w["hist"].values()) == 2
    tip_ids = {t["id"] for t in w["tips"]}
    assert {"wake-timers", "unknown-codes"} <= tip_ids
