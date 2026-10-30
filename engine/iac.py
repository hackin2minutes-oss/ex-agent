"""IaC engine: verifies a Checkov finding against the source and checks network exposure.

For each IAC finding with a location:
1. Resolves the file inside the project, as the SAST engine does.
2. Compares the scanner's code block with the file's current lines. A mismatch means the
   scan does not describe the file, so the verdict is UNKNOWN. This is the stale-scan check.
3. If the finding's rule is about network exposure (its name says so) and the verified block
   is an ingress rule that admits 0.0.0.0/0 or ::/0, the verdict is POTENTIALLY_EXPLOITABLE.
   The rule accepts traffic from any address. Whether an attached resource is actually
   reachable is not analysed.
4. Any other configuration finding is UNKNOWN. No attacker path to the resource is analysed,
   and a missing setting is not a NOT_EXPLOITABLE result. A rule that is not about exposure
   does not become exposure because its block contains an open CIDR.

It never returns CONFIRMED_EXPLOITABLE. That needs a deployment graph and confirmed
reachability, and this engine has neither. It never returns MITIGATED or NOT_EXPLOITABLE.
"""

from engine.universal import (
    POTENTIALLY_EXPLOITABLE, UNKNOWN_STATUS, Condition, Engine, make_assessment,
    resolve_project_file, unknown_assessment,
)

NAME = "iac-block-exposure"
OPEN_CIDRS = ("0.0.0.0/0", "::/0")


def _block_matches(block, lines: list[str]) -> bool:
    if not block:
        return False
    for entry in block:
        if not (isinstance(entry, list) and len(entry) == 2):
            return False
        number, text = entry
        if not (isinstance(number, int) and 1 <= number <= len(lines)):
            return False
        if lines[number - 1].rstrip("\r\n") != str(text).rstrip("\r\n"):
            return False
    return True


# A rule is about network exposure only when its name says so. The block text alone is not
# enough: a description check on an open security group is not an exposure finding.
EXPOSURE_RULE_TERMS = ("0.0.0.0", "::/0", "ingress", "internet", "public")


def _admits_internet_ingress(block_text: str) -> bool:
    return "ingress" in block_text and any(cidr in block_text for cidr in OPEN_CIDRS)


def _rule_is_about_exposure(check_name: str) -> bool:
    name = check_name.lower()
    return any(term in name for term in EXPOSURE_RULE_TERMS)


class IacEngine(Engine):
    name = NAME
    categories = ("IAC",)
    techniques = ("scanner block re-verification", "ingress CIDR check on the verified block")
    limits = (
        "no deployment graph: attachment of a security group to a running resource is not checked",
        "provider defaults, variables and modules are not resolved",
        "the failed check is not re-evaluated; only the source it describes is verified",
        "configuration findings without an analysed attacker path are UNKNOWN, not safe",
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
        if not _block_matches(block, lines):
            return unknown_assessment(
                f"the scanned code block at {span} no longer matches the file; the scan is stale",
                engine=self.name)

        block_text = "".join(str(text) for _, text in block)
        coverage = {
            "analysed": [f"{span} scanner block matches the source"],
            "not_analysed": list(self.limits),
        }
        evidence = [{"condition": None, "kind": "source",
                     "detail": f"block at {span} matches the file"}]

        check_name = finding["original"].get("check_name") or ""
        if _rule_is_about_exposure(check_name) and _admits_internet_ingress(block_text):
            evidence.append({"condition": None, "kind": "source",
                             "detail": f"ingress rule at {span} admits 0.0.0.0/0 or ::/0"})
            return make_assessment(
                POTENTIALLY_EXPLOITABLE,
                reason=("the verified rule accepts ingress from any address; whether the attached "
                        "resource is reachable is not analysed"),
                engine=self.name,
                conditions={
                    "reachable": Condition(UNKNOWN_STATUS),
                    "vulnerability_exists": Condition(UNKNOWN_STATUS),
                },
                evidence=evidence,
                confidence="MEDIUM",
                confidence_reason="the rule text is verified against the file; reachability is not",
                coverage=coverage,
                limitations=list(self.limits),
                exposure=finding["exploitability_context"]["exposure"],
            )

        return unknown_assessment(
            "configuration finding: no attacker path to the resource is analysed for this rule",
            engine=self.name)
