import json

import pytest

from src.tools.knowledge_importer import (
    bugbounty_knowledge_stats,
    import_bugbounty_knowledge,
    query_bugbounty_knowledge,
)


@pytest.mark.asyncio
async def test_import_bugbounty_knowledge_from_local_folder_dedupes(tmp_path):
    writeups = tmp_path / "writeups"
    writeups.mkdir()
    (writeups / "idor.md").write_text(
        "# IDOR in profile API\n\n"
        "A bug bounty report showed an IDOR by changing user_id in /api/users/{id}. "
        "Use two accounts, replay user A request with user B identifiers, compare the "
        "response body for private profile data, and keep a negative control where the "
        "owner can access their own profile. This validates broken object level "
        "authorization without relying on scanner output alone.\n",
        encoding="utf-8",
    )
    dataset = tmp_path / "bugbounty_dataset.json"

    first = await import_bugbounty_knowledge.invoke(
        source=str(writeups),
        dataset_path=str(dataset),
        reindex=False,
    )
    second = await import_bugbounty_knowledge.invoke(
        source=str(writeups),
        dataset_path=str(dataset),
        reindex=False,
    )

    data = json.loads(dataset.read_text(encoding="utf-8"))
    assert "Added entries: 1" in first
    assert "Added entries: 0" in second
    assert len(data) == 1
    assert data[0]["vuln_type"] == "idor"
    assert data[0]["content_hash"]
    assert data[0]["source_path"] == "idor.md"


@pytest.mark.asyncio
async def test_bugbounty_knowledge_stats_counts_entries(tmp_path):
    dataset = tmp_path / "bugbounty_dataset.json"
    dataset.write_text(
        json.dumps(
            [
                {"instruction": "a", "output": "b", "vuln_type": "xss", "source": "one"},
                {"instruction": "c", "output": "d", "vuln_type": "xss", "source": "one"},
                {"instruction": "e", "output": "f", "vuln_type": "ssrf", "source": "two"},
            ]
        ),
        encoding="utf-8",
    )

    result = await bugbounty_knowledge_stats.invoke(dataset_path=str(dataset))

    assert "Total entries: 3" in result
    assert "- xss: 2" in result
    assert "- ssrf: 1" in result
    assert "- one: 2" in result


@pytest.mark.asyncio
async def test_query_bugbounty_knowledge_keyword_fallback(tmp_path):
    dataset = tmp_path / "bugbounty_dataset.json"
    dataset.write_text(
        json.dumps(
            [
                {
                    "instruction": "Apply OAuth redirect_uri testing",
                    "output": "Test redirect_uri allowlist bypasses with sibling domains and encoded paths.",
                    "vuln_type": "oauth",
                    "source": "manual",
                    "source_path": "oauth.md",
                    "tags": ["oauth", "auth"],
                }
            ]
        ),
        encoding="utf-8",
    )

    result = await query_bugbounty_knowledge.invoke(
        query="oauth redirect_uri bypass",
        dataset_path=str(dataset),
        prefer_chroma=False,
    )

    assert "OAuth redirect_uri" in result
    assert "allowlist bypasses" in result
