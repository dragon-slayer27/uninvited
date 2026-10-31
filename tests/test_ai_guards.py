from uninvited import ai, report, rules


def good_answer(**over):
    a = {"product": "Thing App", "vendor": "Thing Corp", "category": "chat-social",
         "what_it_does": "Lets you chat with friends.", "why_at_startup": "So messages arrive right away.",
         "if_disabled": "Messages arrive when you open it.", "confidence": "high"}
    a.update(over)
    return a


def test_vendor_matching():
    assert ai.vendor_matches("Oracle", "Oracle America, Inc.")
    assert ai.vendor_matches("ASUS", "ASUSTeK COMPUTER INC.")
    assert ai.vendor_matches("ETH Zurich", "ETH Zürich")
    assert ai.vendor_matches("Microsoft", "Google LLC") is False
    assert ai.vendor_matches("unknown", "Google LLC") is None
    assert ai.vendor_matches("Google", "", "") is None


def test_explain_retries_then_overrides_a_wrong_vendor(entry_factory, fake_ollama):
    e = rules.analyze(entry_factory())
    client = fake_ollama([good_answer(vendor="Microsoft"), good_answer(vendor="Microsoft")])
    out = ai.explain(e, client, use_cache=False)
    assert out["vendor"] == "Thing Corp" and out["confidence"] == "low"
    assert "vendor-overridden-by-signature" in out["notes"]
    assert "digital signature says the publisher is 'Thing Corp'" in client.prompts[1]
    # Low confidence means the rules refuse to make a call.
    assert rules.decide(e, out)[0] == "unknown"


def test_explain_fixed_on_retry(entry_factory, fake_ollama):
    e = rules.analyze(entry_factory())
    out = ai.explain(e, fake_ollama([good_answer(vendor="Contoso"), good_answer()]), use_cache=False)
    assert out["vendor"] == "Thing Corp" and "vendor-fixed-on-retry" in out["notes"]


def test_advice_and_scare_words_are_removed(entry_factory, fake_ollama):
    e = rules.analyze(entry_factory())
    answer = good_answer(what_it_does="Lets you chat. It could be malware. You should remove it.")
    out = ai.explain(e, fake_ollama([answer]), use_cache=False)
    assert out["what_it_does"] == "Lets you chat."
    assert {"advice-removed:what_it_does", "scare-words-removed:what_it_does"} <= set(out["notes"])


def test_explanations_are_cached_per_program(entry_factory, fake_ollama):
    a = rules.analyze(entry_factory(id="E1", name="One"))
    b = rules.analyze(entry_factory(id="E2", name="Two", kind="task"))
    client = fake_ollama([good_answer()])
    ai.explain(a, client)
    ai.explain(b, client)  # same program, served from cache
    assert len(client.prompts) == 1


def test_facts_hide_the_username(entry_factory, monkeypatch):
    monkeypatch.setenv("USERPROFILE", r"C:\Users\Alex Doe")
    monkeypatch.setenv("USERNAME", "Alex Doe")
    monkeypatch.setenv("COMPUTERNAME", "LAPTOP-ABC123")
    e = entry_factory(command=r'"C:\Users\Alex Doe\AppData\Local\Thing\thing.exe"', display_name="Task-S-1-5-21-1-2-3-1001",
                      kind="task", location="\\", author="LAPTOP-ABC123\\Alex Doe")
    text = ai.facts(rules.analyze(e))
    assert "Alex" not in text and "LAPTOP-ABC123" not in text
    assert "%USERPROFILE%" in text and "S-1-5-21-<you>" in text and "<this-pc>\\<you>" in text


def test_numbers_guard():
    stats = {"exits": 233, "awake_hours": 16.9, "window_days": 9.0}
    assert ai.numbers_ok("233 exits in 9 days, awake 16.9 hours", stats)[0]
    ok, bad = ai.numbers_ok("It woke 240 times", stats)
    assert not ok and bad == ["240"]


def test_story_falls_back_when_numbers_are_invented(fake_ollama):
    w = {"window_days": 9.0, "exits": 233, "not_you": 72, "standby_hours": 156.5, "awake_hours": 16.9,
         "austerity_count": 46, "austerity_nights": ["a"] * 9, "unknown_codes": {"16777220": 14}, "by_class": {}}
    client = fake_ollama([{"headline": "It woke 300 times", "story": "x"}, {"headline": "Still 301", "story": "y"}])
    out = ai.narrate_wakes(w, client)
    assert out["source"] == "template" and "300" in out["rejected_numbers"]
    assert "72 of 233" in out["headline"]


def test_story_accepted_when_numbers_check_out(fake_ollama):
    w = {"window_days": 9.0, "exits": 233, "not_you": 72, "awake_hours": 16.9, "by_class": {}}
    client = fake_ollama([{"headline": "72 of 233 wakes weren't you", "story": "For 9 days it was awake 16.9 hours."}])
    out = ai.narrate_wakes(w, client)
    assert out["source"] == "fake-gemma"


def test_grounded_citations_are_validated(entry_factory, fake_ollama):
    e = rules.analyze(entry_factory())
    results = [{"title": "a", "link": "https://a", "snippet": "s"}, {"title": "b", "link": "https://b", "snippet": "t"}]
    answer = {"product": "Thing", "vendor": "Thing Corp", "category": "media", "what_it_does": "Plays.", "citations": [1, 7], "confidence": "high"}
    out = ai.grounded_explain(e, results, fake_ollama([answer]))
    assert out["citations"] == [1] and not out["grounded"] and out["confidence"] == "low"


def test_seance_reports_invented_ids(entry_factory, fake_ollama):
    e = rules.analyze(entry_factory(id="E12345678"))
    e["verdict"] = "optional"
    client = fake_ollama([{"answer": "Thing starts at sign-in.", "cited_ids": ["E12345678", "E99999999"]}])
    out = ai.seance("what starts?", [e], {"by_class": {}}, client)
    assert out["cited_ids"] == ["E12345678"] and out["invented_ids"] == ["E99999999"]


def test_anonymized_export_has_no_paths(entry_factory, monkeypatch):
    monkeypatch.setenv("USERNAME", "Alex Doe")
    e = rules.analyze(entry_factory(name="Thing"))
    e["verdict"], e["explanation"] = "optional", good_answer()
    rep = {"entries": [e], "wakes": {"exits": 1, "night_events": [1]}, "machine": {"model": "X", "manufacturer": "Y", "os": "Z"}}
    rep["summary"] = report.summarize(rep)
    out = report.anonymized_export(rep)
    blob = str(out)
    assert "Program Files" not in blob and "night_events" not in blob
    assert out["entries"][0]["category"] == "chat-social"
