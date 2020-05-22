/**
 * @name Cross-site scripting vulnerable plugin
 * @kind path-problem
 * @id js/xss-unsafe-plugin
 */

import javascript
import DataFlow::PathGraph

class Configuration extends TaintTracking::Configuration {
  Configuration() { this = "XssUnsafeJQueryPlugin" }
  
  /** Hold if `source` is the plugin option. */
  override predicate isSource(DataFlow::Node source) {
    exists(DataFlow::FunctionNode f, DataFlow::Node n, PropAccess p | f.flowsTo(n) and
      n.asExpr().getChildExpr(0) = p and
      p.getBase().toString() = "$.fn" and
      source = f.getLastParameter())
  }
  
  /** Hold if `sink` is interpreted as HTML. */
  override predicate isSink(DataFlow::Node sink) {
    exists(JQuery::MethodCall j | j.interpretsArgumentAsHtml(sink) and
      not sink.asExpr() instanceof ConstantString)
  }
  
  /** Hold if `pre` taints `succ` through the `this.options` property. */
  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(DataFlow::ClassNode c | c.getAnInstanceReference().getAPropertyWrite("options").getRhs() = pred and
      c.getAnInstanceReference().getAPropertyRead("options") = succ)
  }
}

from Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Potential XSS vulnerability in plugin."