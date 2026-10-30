import io
import json
import urllib.error
from pathlib import Path

import pytest

from engine import code_scanning, universal_run
from engine.universal import ModelError


class FakeResponse:
    def __init__(self, body, link=None):
        self._body = json.dumps(body).encode("utf-8")
        self.headers = {"Link": link} if link else {}

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def pages_opener(pages, seen=None):
    """Serves each page in turn; the Link header points at the next page until the last."""
    state = {"index": 0}

    def opener(request):
        if seen is not None:
            seen.append(request)
        index = state["index"]
        state["index"] += 1
        link = None
        if index + 1 < len(pages):
            link = f'<https://api.github.com/page{index + 2}>; rel="next"'
        return FakeResponse(pages[index], link)
    return opener


def alert(number, tool="gitleaks", rule="generic-api-key", path="api/config.py", line=3, severity="high"):
    return {
        "number": number,
        "tool": {"name": tool, "version": "8.28.0"},
        "rule": {"id": rule, "description": f"{rule} description", "severity": severity},
        "most_recent_instance": {
            "state": "open",
            "location": {"path": path, "start_line": line, "end_line": line, "start_column": 5},
            "message": {"text": f"{rule} at {path}"},
        },
    }


def test_fetch_follows_every_page():
    pages = [[alert(1)], [alert(2)], [alert(3)]]
    seen = []
    alerts = code_scanning.fetch_alerts("owner/repo", "refs/heads/main", "token",
                                        opener=pages_opener(pages, seen))
    assert [a["number"] for a in alerts] == [1, 2, 3]
    assert len(seen) == 3
    assert seen[0].get_header("Authorization") == "Bearer token"
    assert "ref=refs%2Fheads%2Fmain" in seen[0].full_url
    assert "state=open" in seen[0].full_url


def test_fetch_fails_closed_on_forbidden():
    def forbidden(request):
        raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", {}, io.BytesIO(b""))
    with pytest.raises(ModelError, match="HTTP 403"):
        code_scanning.fetch_alerts("owner/repo", "refs/heads/main", "token", opener=forbidden)


def test_fetch_needs_a_token():
    with pytest.raises(ModelError, match="security-events: read"):
        code_scanning.fetch_alerts("owner/repo", "refs/heads/main", "", opener=pages_opener([[]]))


def test_fetch_rejects_a_repo_without_owner():
    with pytest.raises(ModelError, match="owner/name"):
        code_scanning.fetch_alerts("repo", "refs/heads/main", "token", opener=pages_opener([[]]))


def test_one_sarif_document_per_tool():
    documents = code_scanning.alerts_to_sarif([
        alert(1, tool="gitleaks"),
        alert(2, tool="zizmor", rule="artipacked", path=".github/workflows/ci.yml", severity="medium"),
        alert(3, tool="gitleaks", line=9),
    ])
    assert set(documents) == {"gitleaks", "zizmor"}
    gitleaks = documents["gitleaks"]["runs"][0]
    assert gitleaks["tool"]["driver"] == {"name": "gitleaks", "version": "8.28.0"}
    assert len(gitleaks["results"]) == 2
    result = gitleaks["results"][0]
    assert result["ruleId"] == "generic-api-key"
    assert result["level"] == "error"
    region = result["locations"][0]["physicalLocation"]["region"]
    assert region == {"startLine": 3, "endLine": 3, "startColumn": 5}
    assert documents["zizmor"]["runs"][0]["results"][0]["level"] == "warning"


def test_alert_without_location_stays_locationless():
    no_location = alert(4)
    no_location["most_recent_instance"] = {"message": {"text": "flagged"}}
    result = code_scanning.alerts_to_sarif([no_location])["gitleaks"]["runs"][0]["results"][0]
    assert "locations" not in result
    assert result["message"]["text"] == "flagged"


def test_alert_without_rule_id_is_refused():
    broken = alert(5)
    broken["rule"] = {"description": "no id"}
    with pytest.raises(ModelError, match="no rule id"):
        code_scanning.alerts_to_sarif([broken])


def test_no_alerts_writes_one_empty_document(tmp_path):
    paths = code_scanning.write_alert_reports([], tmp_path / "code-scanning")
    assert [p.name for p in paths] == ["code-scanning.sarif"]
    document = json.loads(paths[0].read_text(encoding="utf-8"))
    assert document["runs"][0]["results"] == []


def test_write_one_file_per_tool(tmp_path):
    paths = code_scanning.write_alert_reports([alert(1), alert(2, tool="CodeQL", rule="py/sql")], tmp_path)
    assert sorted(p.name for p in paths) == ["CodeQL.sarif", "gitleaks.sarif"]


def test_sarif_adapter_routes_by_tool(tmp_path):
    from engine.sarif_adapter import SarifAdapter
    adapter = SarifAdapter()
    documents = code_scanning.alerts_to_sarif([
        alert(1, tool="gitleaks"),
        alert(2, tool="checkov", rule="CKV_DOCKER_2", path="Dockerfile", severity="low"),
        alert(3, tool="zizmor", rule="artipacked", path=".github/workflows/ci.yml", severity="medium"),
        alert(4, tool="CodeQL", rule="py/sql-injection", path="api/app.py", severity="high"),
    ])
    categories = {}
    for name, document in documents.items():
        findings, _ = adapter.parse(document, {"target": "x"})
        categories[name] = {f["category"] for f in findings}
    assert categories == {"gitleaks": {"SECRET"}, "checkov": {"IAC"}, "zizmor": {"CICD"}, "CodeQL": {"SAST"}}


def test_runner_refuses_missing_ref(tmp_path, capsys):
    with pytest.raises(SystemExit):
        universal_run.main(["--code-scanning-repo", "owner/repo", "--project-dir", str(tmp_path),
                            "--output-dir", str(tmp_path / "out")])
    assert "--code-scanning-ref" in capsys.readouterr().err


def test_runner_exits_two_when_alerts_cannot_be_read(tmp_path, monkeypatch, capsys):
    def refused(repo, ref, token, **kwargs):
        raise ModelError("could not read code scanning alerts for owner/repo on refs/heads/main: HTTP 403")
    monkeypatch.setattr(code_scanning, "fetch_alerts", refused)
    exit_code = universal_run.main(["--code-scanning-repo", "owner/repo", "--code-scanning-ref", "refs/heads/main",
                                    "--project-dir", str(tmp_path), "--output-dir", str(tmp_path / "out"),
                                    "--offline", "true"])
    assert exit_code == 2
    assert "HTTP 403" in capsys.readouterr().err


def test_runner_assesses_alerts_end_to_end(tmp_path, monkeypatch):
    project = tmp_path / "project"
    (project / "api").mkdir(parents=True)
    (project / "api" / "config.py").write_text("API_KEY = 'x'\n", encoding="utf-8")
    monkeypatch.setattr(code_scanning, "fetch_alerts",
                        lambda repo, ref, token, **kwargs: [alert(1), alert(2, tool="zizmor", rule="artipacked",
                                                                            path=".github/workflows/ci.yml",
                                                                            severity="medium")])
    output = tmp_path / "out"
    exit_code = universal_run.main(["--code-scanning-repo", "owner/repo", "--code-scanning-ref", "refs/heads/main",
                                    "--project-dir", str(project), "--output-dir", str(output), "--offline", "true"])
    assert exit_code == 0
    assert (output / "code-scanning" / "gitleaks.sarif").exists()
    assert (output / "code-scanning" / "zizmor.sarif").exists()
    findings = json.loads((output / "universal-findings.json").read_text(encoding="utf-8"))["findings"]
    assert sorted(f["category"] for f in findings) == ["CICD", "SECRET"]
