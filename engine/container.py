"""Container engine: Dockerfile-only assessment of Checkov findings.

This engine has no image and no runtime. It sees the Dockerfile and nothing else. For each
CONTAINER finding with a location:
1. Resolves the Dockerfile inside the project, as the other engines do.
2. Re-verifies the scanner's code block against the file (a mismatch is a stale scan, UNKNOWN).
3. If the rule is about an exposed port (its name says so) and the verified block is an EXPOSE of a
   port, the verdict is POTENTIALLY_EXPLOITABLE. Whether the port is published by the runtime, and
   what listens on it, is not known from the Dockerfile.
4. Any other container finding (no HEALTHCHECK, running as root, unpinned base) is UNKNOWN. These
   are build configuration. Their exploitability depends on the image and the runtime.

Image vulnerabilities are not assessed. They need an image scanner (Trivy or Grype), which
cannot run in this environment. See docs/UNIVERSAL_ARCHITECTURE.md, section 5.

It never returns CONFIRMED_EXPLOITABLE, NOT_EXPLOITABLE or MITIGATED.
"""

from engine.iac import block_matches
from engine.universal import (
    POTENTIALLY_EXPLOITABLE, UNKNOWN_STATUS, Condition, Engine, make_assessment,
    resolve_project_file, unknown_assessment,
)

NAME = "container-dockerfile"
EXPOSE_RULE_TERMS = ("expose", "port")


def _exposes_port(block_text: str) -> bool:
    return any(line.strip().upper().startswith("EXPOSE ")
               for line in block_text.splitlines())


class ContainerEngine(Engine):
    name = NAME
    categories = ("CONTAINER",)
    techniques = ("scanner block re-verification", "EXPOSE check on the verified block")
    limits = (
        "Dockerfile only: no image, no image layers, no installed packages",
        "no runtime: whether a declared port is published, and what listens on it, is not known",
        "image vulnerabilities are not assessed; they need an image scanner",
        "build configuration findings without an analysed attacker path are UNKNOWN",
    )

    def assess(self, finding: dict, context: dict):
        location = finding.get("location")
        if not location:
            return unknown_assessment("the finding has no source location", engine=self.name)
        target, problem = resolve_project_file(context["project_dir"], location["path"])
        if target is None:
            return unknown_assessment(problem, engine=self.name)

        lines = target.read_text(encoding="utf-8", errors="strict").splitlines(keepends=True)
        block = finding["original"].get("code_block") or []
        span = f"{location['path']}:{location['start_line']}-{location['end_line']}"
        if not block_matches(block, lines):
            return unknown_assessment(
                f"the scanned code block at {span} no longer matches the file; the scan is stale",
                engine=self.name)

        block_text = "".join(str(text) for _, text in block)
        check_name = (finding["original"].get("check_name") or "").lower()
        coverage = {"analysed": [f"{span} scanner block matches the Dockerfile"],
                    "not_analysed": list(self.limits)}

        if any(term in check_name for term in EXPOSE_RULE_TERMS) and _exposes_port(block_text):
            return make_assessment(
                POTENTIALLY_EXPLOITABLE,
                reason=("the image declares an exposed port that the rule is about; whether the "
                        "runtime publishes it is not known from the Dockerfile"),
                engine=self.name,
                conditions={
                    "reachable": Condition(UNKNOWN_STATUS),
                    "vulnerability_exists": Condition(UNKNOWN_STATUS),
                },
                evidence=[{"condition": None, "kind": "source",
                           "detail": f"EXPOSE declared at {span}"}],
                confidence="MEDIUM",
                confidence_reason="the declaration is verified; publication is not",
                coverage=coverage,
                limitations=list(self.limits),
                exposure=finding["exploitability_context"]["exposure"],
            )

        return unknown_assessment(
            "container build configuration: no image or runtime context to decide exploitability",
            engine=self.name)
