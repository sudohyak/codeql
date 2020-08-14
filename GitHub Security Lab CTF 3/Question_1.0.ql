import javascript

/** Find simple plugin definitions like `$.fn.copyText = function() { ... }`. */
from AssignExpr a, PropAccess p, FunctionExpr f
where
  a.getLhs() = p and
  a.getRhs() = f and
  p.getBase().toString() = "$.fn"
select a