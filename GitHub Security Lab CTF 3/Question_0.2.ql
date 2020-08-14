import javascript

/** Find the dangerous arguments interpreted as HTML. */
from JQuery::MethodCall j, DataFlow::Node n
where 
  j.interpretsArgumentAsHtml(n) and 
  not n.asExpr() instanceof ConstantString
select n