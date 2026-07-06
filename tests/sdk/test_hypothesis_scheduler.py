from src.sdk.hypothesis_scheduler import select_next_hypothesis


def test_select_next_hypothesis_skips_done_and_picks_highest_score():
    hypotheses = [
        {"id": "done", "name": "done", "status": "confirmed", "score": 99, "confidence": 1, "cost": 1},
        {"id": "low", "name": "low", "status": "candidate", "score": 1.5, "confidence": 0.7, "cost": 1},
        {"id": "high", "name": "high", "status": "candidate", "score": 3.0, "confidence": 0.8, "cost": 2},
    ]

    selected = select_next_hypothesis(hypotheses)

    assert selected["id"] == "high"
