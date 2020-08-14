/**
 * @name Cross-site scripting vulnerable plugin
 * @kind path-problem
 * @id js/xss-unsafe-plugin
 */

import javascript
import DataFlow::PathGraph

/**
Options with a name or a default value that clearly signals that
dynamically constructed HTML is expected by the programmer.
*/
class ExpectedHTMLOption extends DataFlow::Node {
  ExpectedHTMLOption() {
    exists(DataFlow::ClassNode c, DataFlow::PropWrite default, DataFlow::PropWrite option |
      default = c.getAPropertyWrite() and
      default.getPropertyName() = "DEFAULTS" and
      option = default.getRhs().getALocalSource().getAPropertyWrite() and
      option.getPropertyName() = this.asExpr().(PropAccess).getPropertyName() and
      option.getRhs().asExpr() instanceof ConstantString and
      (option.getPropertyName().regexpMatch(".*(template|framework).*") or
        option.getRhs().toString().regexpMatch("'<.+>'"))
    )
  }
}

class Configuration extends TaintTracking::Configuration {
  Configuration() { this = "XssUnsafeJQueryPlugin" }
  
  /** Hold if `source` is the plugin option. */
  override predicate isSource(DataFlow::Node source) {
    exists(DataFlow::FunctionNode f, DataFlow::Node n, PropAccess p | f.flowsTo(n) and
      n.asExpr().getChildExpr(0) = p and
      p.getBase().toString() = "$.fn" and
      source = f.getLastParameter())
  }
  
  /** Hold if `sink` is interpreted as HTML or a selector, and is not expected by the programmer. */
  override predicate isSink(DataFlow::Node sink) {
    exists(JQuery::MethodCall j | j.interpretsArgumentAsHtml(sink) and
      j.interpretsArgumentAsSelector(sink) and
      not sink.asExpr() instanceof ConstantString) and
    not sink instanceof ExpectedHTMLOption
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