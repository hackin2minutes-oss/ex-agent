"""Guidance added to every assessment: what is missing, what to investigate next, what the verdict assumes, and what
to do. It is derived from the assessment's own conditions and evidence, so it cannot say more than the verdict does.
"""

NEXT_STEP = {
    "vulnerability_exists": "Confirm the weakness exists in the assessed version or configuration (the affected range, the "
                            "resolved version, or the configuration value).",
    "reachable": "Trace which route, job or caller reaches the affected code. Add the caller to the scan, or confirm the "
                 "application's entry points.",
    "attacker_influence": "Trace the affected value back to its source. Determine whether an outside party controls it.",
    "preconditions": "Check the conditions the exploit needs: the input shape, the state, and the configuration.",
    "runtime_observed": "Collect runtime evidence: a request, a trace or an agent observation that reaches the code.",
    "blocked": "Check whether a runtime protection blocks the attack on this path, and on which requests.",
    "mitigation_effective": "Verify the mitigation on this path: that it runs for every request reaching the code, and "
                            "that it is effective for this sink.",
}
REMEDIATION = {
    "SAST": "Remove the injection channel at this call: use parameterised queries, validate or convert the input before "
            "use, or move the call out of the request path.",
    "SCA": "Upgrade the component to a fixed version, or remove the dependency. Check the fix version against the "
           "affected range.",
    "IAC": "Restrict the configuration: the least-privilege rule, the narrowest network range, and no public exposure "
           "unless it is required.",
    "CONTAINER": "Change the image or its runtime settings: run as non-root, pin and update the base image, and remove "
                 "unneeded packages.",
    "CICD": "Narrow the workflow: use the least token permission, do not run untrusted input in a shell step, and pin "
            "actions to a commit.",
    "SECRET": "Revoke and rotate the credential, remove it from the source, and load it from a secret store.",
    "DAST": "Fix the reflected or injected input at the endpoint: encode output for its context and validate input.",
    "IAST": "Fix the sink on the observed path, using the sanitiser or parameterisation the sink requires.",
    "RASP": "Keep the protection enabled for this endpoint, and fix the underlying weakness the attack reached.",
}
LIMITS_BY_ENGINE = {
    "sast-call-site": "Static analysis of one application. Dynamic dispatch, callers outside the project, and "
                      "interprocedural flows beyond the traced path are not followed.",
}


def enrich(finding: dict) -> dict:
    assessment = finding["assessment"]
    verdict = assessment["verdict"]
    unknown = [name for name, cond in assessment["conditions"].items() if cond["status"] == "UNKNOWN"]
    missing = [f"{name}: not established" for name in unknown]
    if verdict in ("UNKNOWN", "ANALYSIS_INCOMPLETE") and not missing:
        missing = [assessment["reason"]]
    assumptions = []
    if assessment.get("attack_path") is not None:
        assumptions.append("the traced path is the static call path in the analysed source")
    if verdict == "CONFIRMED_EXPLOITABLE":
        assumptions.append("the declared internet exposure is correct")
    if verdict in ("NOT_REACHABLE", "NOT_EXPLOITABLE"):
        assumptions.append("the analysed source is the code that is deployed")
    limit = LIMITS_BY_ENGINE.get(assessment.get("engine", ""))
    if limit and limit not in assessment["limitations"]:
        assessment["limitations"] = list(assessment["limitations"]) + [limit]
    category = finding["category"]
    if verdict in ("CONFIRMED_EXPLOITABLE", "POTENTIALLY_EXPLOITABLE"):
        remediation = REMEDIATION.get(category, "Fix the weakness at its source and re-run the assessment.")
    elif verdict in ("NOT_EXPLOITABLE", "NOT_REACHABLE", "NOT_AFFECTED", "MITIGATED"):
        remediation = "No change is required for this finding in the analysed context. Re-assess if the code or " \
                      "its callers change."
    else:
        remediation = "Provide the missing evidence listed under missing_information, then re-assess."
    # The question that most decides the verdict comes first. For a source finding, that is whether attacker data
    # reaches the call, not whether the call exists.
    priority = ["attacker_influence", "reachable", "preconditions", "runtime_observed", "blocked",
                "mitigation_effective", "vulnerability_exists"]
    next_step = next((NEXT_STEP[n] for n in priority if n in unknown), None)
    if next_step is None:
        next_step = "None: the decided conditions support the verdict. Re-assess when the source changes."
    assessment.update({
        "missing_information": missing,
        "assumptions": assumptions,
        "next_investigation": next_step,
        "recommended_remediation": remediation,
    })
    return finding
