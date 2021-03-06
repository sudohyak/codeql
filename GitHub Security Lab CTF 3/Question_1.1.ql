import javascript

/** Find advanced plugin definitions. */
from DataFlow::FunctionNode f, DataFlow::Node n, PropAccess p
where
  f.flowsTo(n) and
  n.asExpr().getChildExpr(0) = p and
  p.getBase().toString() = "$.fn"
select n