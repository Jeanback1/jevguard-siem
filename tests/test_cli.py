import json

from jevguard.cli import main


def test_ai_command_uses_local_provider(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("JEVGUARD_AI_PROVIDER", "local")
    monkeypatch.setenv("JEVGUARD_DB_PATH", str(tmp_path / "cli.db"))
    monkeypatch.setattr("sys.argv", ["jevguard", "test-ai"])

    main()

    result = json.loads(capsys.readouterr().out)
    assert result["provider"] == "local-rules"
    assert result["classification"] == "suspicious"
