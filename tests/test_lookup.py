from uninvited import lookup, rules


def test_query_has_file_label_and_publisher_only(entry_factory, monkeypatch):
    monkeypatch.setenv("USERNAME", "Alex Doe")
    e = rules.analyze(entry_factory(kind="task", display_name="RunPlatformExperienceHelperOnUnlock",
                                    target=r"C:\Program Files\Google\Chrome\Application\platform_experience_helper.exe"))
    e["publisher"] = "Google LLC"
    assert lookup.build_query(e) == '"platform_experience_helper.exe" RunPlatformExperienceHelperOnUnlock Google LLC'


def test_query_drops_names_with_sids_guids_or_the_user(entry_factory, monkeypatch):
    monkeypatch.setenv("USERNAME", "Alex Doe")
    for label in ("OneDrive Reporting Task-S-1-5-21-1-2-3-1001", "Task for Alex Doe",
                  "msedge_cleanup_{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"):
        e = rules.analyze(entry_factory(display_name=label, target=r"C:\Program Files\X\x.exe"))
        e["publisher"] = "X Corp"
        assert lookup.build_query(e) == '"x.exe" X Corp', label


def test_lookup_without_key_explains_how_to_enable(entry_factory, monkeypatch):
    monkeypatch.delenv("SERPAPI_KEY", raising=False)
    monkeypatch.delenv("SERPAPI_API_KEY", raising=False)
    out = lookup.web_lookup(rules.analyze(entry_factory()), key=None)
    assert "SERPAPI_KEY" in out["error"]


def test_grounded_lookup_feeds_the_rules(entry_factory, fake_ollama, monkeypatch):
    e = rules.analyze(entry_factory())
    results = [{"title": "Thing helper", "link": "https://a", "snippet": "Thing's browser helper", "source": "a"}]
    monkeypatch.setattr(lookup, "search", lambda q, k, num=6: results)
    answer = {"product": "Thing", "vendor": "Thing Corp", "category": "browser", "what_it_does": "Helps.", "citations": [1], "confidence": "high"}
    out = lookup.web_lookup(e, fake_ollama([answer]), key="test")
    assert out["explanation"]["grounded"] and out["verdict"] == "optional"
    ungrounded = dict(answer, citations=[])
    out2 = lookup.web_lookup(rules.analyze(entry_factory(id="E2", target=r"C:\Program Files\Y\y.exe")), fake_ollama([ungrounded]), key="test")
    assert out2["verdict"] == "unknown"
