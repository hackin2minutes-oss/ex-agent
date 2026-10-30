/**
 * @name Parameters annotated with RequestParam (diagnostic)
 * @id sawone/diag-requestparam
 * @kind problem
 */
import java

from Parameter p, Annotation a
where a = p.getAnAnnotation() and a.getType().hasName("RequestParam")
select p, "annotated with " + a.getType().getName()
