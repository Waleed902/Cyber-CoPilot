from src.sdk.model_settings import ModelSettings


def test_openrouter_dead_arcee_model_falls_back(monkeypatch):
    monkeypatch.setenv("OPENROUTER_MODEL", "arcee-ai/trinity-large-preview:free")

    settings = ModelSettings()

    assert settings.get_model("openrouter") == "cognitivecomputations/dolphin-mistral-24b-venice-edition:free"
