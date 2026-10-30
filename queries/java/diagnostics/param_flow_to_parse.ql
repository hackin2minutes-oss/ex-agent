/**
 * @name Flow from the direct() parameter to parse (diagnostic)
 * @id sawone/diag-param-flow
 * @kind path-problem
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

module ParamConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asParameter().getCallable().hasName("direct")
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall call |
      call.getMethod().hasName("parse") and sink.asExpr() = call.getAnArgument()
    )
  }
}

module ParamFlow = TaintTracking::Global<ParamConfig>;

import ParamFlow::PathGraph

from ParamFlow::PathNode source, ParamFlow::PathNode sink
where ParamFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "parameter flows to parse"
