"""The interface every language analyzer implements, and the verdict rules every analyzer shares.

The intelligence core asks an analyzer about one call site and reads what the analyzer says it can and cannot do. It
never reads a language's syntax itself, so a language is added by adding an analyzer, not by editing the core.

An analyzer must parse real syntax (a parser or AST), not match text. Its capability report must list what it does
not model, so a verdict can be read against that limit.

The verdict rules are the same for every language, so they live here. A language supplies a CallSite; `assess_site`
turns it into an assessment. Preconditions are never modelled by an analyzer, so no analyzer can reach
CONFIRMED_EXPLOITABLE on its own.
"""

from dataclasses import dataclass, field

from engine.universal import (
    CONFIRMED, NOT_CONFIRMED, NOT_EXPLOITABLE, POTENTIALLY_EXPLOITABLE, UNKNOWN, UNKNOWN_STATUS, Condition,
    make_assessment,
)

ENTRY_KINDS = ("route",)


@dataclass
class CallSite:
    """What an analyzer found at one call site. `sources` lists the receiver and each argument, with its kind:
    attacker (traced to a request value), constant (literals only), or unknown."""

    found: bool
    reason: str
    match: str = ""
    method: str | None = None
    attributes: list[str] = field(default_factory=list)
    entry_point: bool = False
    entry: str = ""
    sources: list[dict] = field(default_factory=list)


def assess_site(site: CallSite, location: dict, *, engine: str, exposure: str, limits) -> object:
    """The universal assessment for a call site. Attacker input reaching the call makes it at most
    POTENTIALLY_EXPLOITABLE here, because preconditions are not modelled. A call whose arguments are all literals is
    NOT_EXPLOITABLE, because no attacker-controlled data reaches it."""
    limits = list(limits)
    where = f"{location['path']}:{location['start_line']}"
    if not site.found:
        return make_assessment(UNKNOWN, reason=f"{where}: {site.reason}", engine=engine,
                               limitations=[site.reason, *limits], exposure=exposure)

    arguments = [s for s in site.sources if s["role"] == "argument"]
    attacker = next((s for s in site.sources if s["kind"] == "attacker"), None)
    constant = attacker is None and bool(arguments) and all(s["kind"] == "constant" for s in arguments)

    evidence = [
        {"condition": None, "kind": "location", "detail": f"{where} call expression located ({site.match} match)"},
        {"condition": None, "kind": "enclosing_method", "detail": site.method or "none",
         "attributes": site.attributes},
    ]
    conditions = {}
    if site.entry_point:
        conditions["reachable"] = Condition(CONFIRMED, [site.entry])
        evidence.append({"condition": "reachable", "kind": "entry_point",
                         "detail": f"{site.method or 'handler'} is an entry point: {site.entry}"})
    if attacker is not None:
        conditions["attacker_influence"] = Condition(CONFIRMED, [attacker["via"]])
        evidence.append({"condition": "attacker_influence", "kind": "taint",
                         "detail": f"{attacker['role']} {attacker['index']} `{attacker['text']}` carries "
                                   f"{attacker['via']}"})
    elif constant:
        conditions["attacker_influence"] = Condition(NOT_CONFIRMED, ["every argument is a literal"])
        evidence.append({"condition": "attacker_influence", "kind": "constant",
                         "detail": "every argument is a literal constant, and the receiver is not attacker input"})

    coverage = {"analysed": [where], "not_analysed": limits}
    if constant:
        return make_assessment(NOT_EXPLOITABLE, reason="every argument is a literal, so no attacker-controlled data "
                               "reaches the call", engine=engine, conditions=conditions, evidence=evidence,
                               confidence="HIGH", confidence_reason="a literal-only argument list is decided by the "
                               "syntax tree", coverage=coverage, limitations=limits, exposure=exposure)
    if attacker is not None:
        return make_assessment(POTENTIALLY_EXPLOITABLE, reason=f"attacker input reaches the call: {attacker['via']}",
                               engine=engine, conditions=conditions, evidence=evidence, confidence="MEDIUM",
                               confidence_reason="traced within one function; preconditions and callers are not",
                               coverage=coverage, limitations=limits, exposure=exposure)
    return make_assessment(UNKNOWN, reason="no argument is a literal, and none is traced to a request value in this "
                           "function", engine=engine, conditions={"attacker_influence": Condition(UNKNOWN_STATUS)},
                           evidence=evidence, confidence="LOW",
                           confidence_reason="the argument source is outside the analysed function",
                           coverage=coverage, limitations=limits, exposure=exposure)


class LanguageAnalyzer:
    """Base class. Subclasses set the class attributes and implement analyse_call."""

    name = ""
    extensions: tuple = ()
    # Analysis capabilities that are implemented and tested.
    implemented: tuple = ()
    # Constructs and flows the analysis does not model. Every verdict made with this analyzer is read against these.
    unsupported: tuple = ()
    call_graph = "not implemented"
    data_flow = "not implemented"
    test_corpus: tuple = ()
    measured_accuracy = "not measured"

    def capabilities(self) -> dict:
        return {
            "language": self.name,
            "status": "IMPLEMENTED_NOT_EXTERNALLY_VERIFIED" if self.implemented else "NOT_IMPLEMENTED",
            "implemented": list(self.implemented),
            "unsupported": list(self.unsupported),
            "call_graph": self.call_graph,
            "data_flow": self.data_flow,
            "test_corpus": list(self.test_corpus),
            "measured_accuracy": self.measured_accuracy,
        }

    def analyse_call(self, source: bytes, location: dict) -> CallSite:
        """Return the analyzer's CallSite for the call at `location` in `source`."""
        raise NotImplementedError

    def assess(self, source: bytes, location: dict, *, engine: str, exposure: str):
        """The universal assessment for the flagged call. Every analyzer gets the same verdict rules."""
        return assess_site(self.analyse_call(source, location), location, engine=engine, exposure=exposure,
                           limits=self.unsupported)
