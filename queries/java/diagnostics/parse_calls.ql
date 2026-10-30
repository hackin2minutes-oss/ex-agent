/**
 * @name Calls to parse (diagnostic)
 * @id sawone/diag-parse-calls
 * @kind problem
 */
import java

from MethodCall call
where call.getMethod().hasName("parse")
select call, "parse call to " + call.getMethod().getDeclaringType().getQualifiedName()
