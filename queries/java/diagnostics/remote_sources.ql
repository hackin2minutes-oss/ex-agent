/**
 * @name Remote flow sources (diagnostic)
 * @id sawone/diag-remote-sources
 * @kind problem
 */
import java
import semmle.code.java.dataflow.FlowSources

from RemoteFlowSource source
select source, "remote source"
