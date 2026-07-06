import asyncio

from src.tools.artifacts import artifact_glob, artifact_grep, artifact_read, artifact_write


def _run(tool, **kwargs):
    return asyncio.run(tool.invoke(**kwargs))


def test_artifact_tools_are_scoped_and_searchable(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "targets" / "demo").mkdir(parents=True)

    write_result = _run(
        artifact_write,
        path="targets/demo/note.txt",
        scope="workspace",
        content="alpha\nneedle here\nomega\n",
    )
    assert "Wrote artifact" in write_result

    read_result = _run(artifact_read, path="targets/demo/note.txt", scope="workspace")
    assert "needle here" in read_result

    grep_result = _run(
        artifact_grep,
        pattern="needle",
        path_glob="**/*.txt",
        scope="workspace",
    )
    assert "note.txt:2" in grep_result

    glob_result = _run(artifact_glob, pattern="**/*.txt", scope="workspace")
    assert "targets/demo/note.txt" in glob_result


def test_artifact_read_rejects_path_escape(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = _run(artifact_read, path="../outside.txt", scope="workspace")
    assert "escapes workspace scope" in result
