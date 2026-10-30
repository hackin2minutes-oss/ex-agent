"""DAST engine: checks a recorded request and response. It sends no new traffic.

Sending requests to a target is active testing, and this engine is not authorised to do it. So it only
reads the exchange the scanner recorded. For each DAST finding:
1. The request and response must both be present, and the response must carry a status line.
2. The request's query parameters are decoded. A parameter value that appears verbatim in the response
   body means the input is reflected without encoding. That is the one property this engine checks.
   Other template claims are not checked.
3. If a decoded value is reflected verbatim, the verdict is POTENTIALLY_EXPLOITABLE with HIGH confidence.
   The recorded exchange proves that one path reflects input on one endpoint. It does not prove that
   every path is exploitable, so this engine never returns CONFIRMED_EXPLOITABLE.
4. If no value is reflected verbatim, the verdict is UNKNOWN. The input may be encoded, or the template
   may claim something else. That is not a safe result, so it is never NOT_EXPLOITABLE.

It never returns MITIGATED, because no control is verified from one exchange.
"""

from urllib.parse import parse_qsl, urlsplit

from engine.universal import (
    POTENTIALLY_EXPLOITABLE, CONFIRMED, Condition, Engine, make_assessment, unknown_assessment,
)

NAME = "dast-recorded-exchange"
MIN_VALUE_LENGTH = 3  # shorter values match too often to mean anything


def _split_exchange(raw: str) -> tuple[str, str]:
    head, _, body = raw.replace("\r\n", "\n").partition("\n\n")
    return head, body


class DastEngine(Engine):
    name = NAME
    categories = ("DAST",)
    techniques = ("recorded exchange parsing", "verbatim reflection check on the response body")
    limits = (
        "one recorded request and response: other paths and parameters are not covered",
        "no new traffic is sent: the engine checks the recording, not the target now",
        "the template's own claim (for example, cross-site scripting) is not checked",
        "exposure of the endpoint is not assessed",
        "a reflected value is not proof of impact: the context it lands in is not parsed",
    )

    def assess(self, finding: dict, context: dict):
        original = finding["original"]
        request = original.get("request") or ""
        response = original.get("response") or ""
        if not request or not response:
            return unknown_assessment("the recorded request or response is missing", engine=self.name)

        request_line = request.split("\n", 1)[0].split(" ")
        head, body = _split_exchange(response)
        status = head.split("\n", 1)[0]
        if len(request_line) < 2 or not status.startswith("HTTP/"):
            return unknown_assessment("the recorded exchange has no usable request or status line",
                                      engine=self.name)

        target = urlsplit(request_line[1])
        values = [value for _, value in parse_qsl(target.query, keep_blank_values=False)
                  if len(value) >= MIN_VALUE_LENGTH]
        reflected = [value for value in values if value in body]
        span = finding["asset"]["name"]
        coverage = {"analysed": [f"recorded exchange for {span}"], "not_analysed": list(self.limits)}

        if not reflected:
            return unknown_assessment(
                f"no decoded input from the request appears verbatim in the response from {span}; "
                "the input may be encoded or the template claims something else",
                engine=self.name)

        value = reflected[0]
        return make_assessment(
            POTENTIALLY_EXPLOITABLE,
            reason=("the recorded response reflects a request parameter verbatim; this shows one "
                    "path on one endpoint, not every path"),
            engine=self.name,
            conditions={
                "reachable": Condition(CONFIRMED, [f"{status} recorded from {span}"]),
                "attacker_influence": Condition(CONFIRMED, ["parameter value sent in the request"]),
                "preconditions": Condition(CONFIRMED, ["value reflected verbatim in the body"]),
            },
            evidence=[
                {"condition": "reachable", "kind": "recorded-exchange", "detail": f"{status}"},
                {"condition": "attacker_influence", "kind": "recorded-exchange",
                 "detail": f"request parameter value {value[:60]!r} sent to {span}"},
                {"condition": "preconditions", "kind": "recorded-exchange",
                 "detail": f"{value[:60]!r} appears unencoded in the response body"},
            ],
            confidence="HIGH",
            confidence_reason="the exchange is recorded and the reflection is checked in the recording",
            coverage=coverage,
            limitations=list(self.limits),
            exposure=finding["exploitability_context"]["exposure"],
        )
