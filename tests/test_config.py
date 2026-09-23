from pathlib import Path

from jevguard.config import Settings


def test_dotenv_is_loaded(monkeypatch, tmp_path: Path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("JEVGUARD_AI_PROVIDER", raising=False)
    (tmp_path / ".env").write_text("JEVGUARD_AI_PROVIDER=local\n")

    settings = Settings.from_env()

    assert settings.ai_provider == "local"
