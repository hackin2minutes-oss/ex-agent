"""The interface every language analyzer implements.

The intelligence core asks an analyzer about one call site and reads what the analyzer says it can and cannot do. It
never reads a language's syntax itself, so a language is added by adding an analyzer, not by editing the core.

An analyzer must parse real syntax (a parser or AST), not match text. Its capability report must list what it does
not model, so a verdict can be read against that limit.
"""


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

    def analyse_call(self, source: bytes, location: dict):
        """Return the analyzer's CallSite for the call at `location` in `source`."""
        raise NotImplementedError
