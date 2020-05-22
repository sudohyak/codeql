/**
 * @name Cross-site scripting vulnerable plugin
 * @description Using jQuery $-function with untrusted input from users
 *              could lead to Cross Site Scripting attacks.
 * @kind path-problem
 * @id js/xss-unsafe-plugin
 * @tag security
 *      external/cwe/cwe-79
 */

import javascript
import DataFlow::PathGraph

/**
 * Options with a name or a default value that clearly signals that
 * dynamically constructed HTML is expected by the programmer.
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

/** Options is sanitized if its type isn't string. */
class StringTypeofSanitizerGuard extends TaintTracking::SanitizerGuardNode, DataFlow::ValueNode {
  StringTypeofSanitizerGuard() {
    (this.asExpr() instanceof NEqExpr or
      this.asExpr() instanceof StrictNEqExpr) and
    this.asExpr().getChildExpr(0) instanceof TypeofExpr 
  }
  
  override predicate sanitizes(boolean outcome, Expr e) {
    outcome = true and
    e = this.asExpr().getChildExpr(0).(TypeofExpr).getOperand() and
    this.asExpr().getChildExpr(1).toString() = "'string'"
  }
}

/** Options is sanitized if its `jquery` property's type isn't `undefined`. */
class JQueryPropertyTypeofSanitizerGuard extends TaintTracking::SanitizerGuardNode, DataFlow::ValueNode {
  JQueryPropertyTypeofSanitizerGuard() {
    (this.asExpr() instanceof NEqExpr or
      this.asExpr() instanceof StrictNEqExpr) and
    this.asExpr().getChildExpr(0) instanceof TypeofExpr
  }
  
  override predicate sanitizes(boolean outcome, Expr e) {
    outcome = true and
    exists(PropAccess p |
      p = this.asExpr().getChildExpr(0).(TypeofExpr).getOperand() and
      e = p.getBase() and
      p.getPropertyName() = "jquery"
    ) and
    this.asExpr().getChildExpr(1).toString() = "'undefined'"
  }
}

/** Options is sanitized if it has `jquery` property. */
class JQueryPropertySanitizerGuard extends TaintTracking::SanitizerGuardNode {
  JQueryPropertySanitizerGuard() {
    this.asExpr() instanceof PropAccess
  }
  
  override predicate sanitizes(boolean outcome, Expr e) {
    outcome = true and
    e = this.asExpr().(PropAccess).getBase() and
    this.asExpr().(PropAccess).getPropertyName() = "jquery"
  }
}

class Configuration extends TaintTracking::Configuration {
  Configuration() { this = "XssUnsafeJQueryPlugin" }
  
  /** Hold if `source` is the plugin option. */
  override predicate isSource(DataFlow::Node source) {
    exists(DataFlow::FunctionNode f, DataFlow::Node n, PropAccess p |
      f.flowsTo(n) and
      n.asExpr().getChildExpr(0) = p and
      p.getBase().toString() = "$.fn" and
      source = f.getLastParameter()
    )
  }
  
  /** Hold if `sink` is interpreted as HTML or a selector, and is not expected by the programmer. */
  override predicate isSink(DataFlow::Node sink) {
    exists(JQuery::MethodCall j |
      j.interpretsArgumentAsHtml(sink) and
      j.interpretsArgumentAsSelector(sink) and
      not sink.asExpr() instanceof ConstantString
    ) and
    not sink instanceof ExpectedHTMLOption
  }
  
  /** Hold if `pre` taints `succ` through the `this.options` property. */
  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(DataFlow::ClassNode c |
      c.getAnInstanceReference().getAPropertyWrite("options").getRhs() = pred and
      c.getAnInstanceReference().getAPropertyRead("options") = succ
    )
  }
  
  /** Hold if `nd` is sanitized by checking if its type isn't string or it has `jquery` property. */
  override predicate isSanitizerGuard(TaintTracking::SanitizerGuardNode nd) {
    nd instanceof StringTypeofSanitizerGuard or
    nd instanceof JQueryPropertyTypeofSanitizerGuard or
    nd instanceof JQueryPropertySanitizerGuard
  }
}

from
  Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink,
  PropAccess plugin, PropAccess option
where
  cfg.hasFlowPath(source, sink) and
  exists(DataFlow::FunctionNode f, DataFlow::Node n |
    f.getLastParameter() = source.getNode() and
    f.flowsTo(n) and
    plugin = n.asExpr().getChildExpr(0) and
    plugin.getBase().toString() = "$.fn"
  ) and
  exists(DataFlow::PathNode step |
    step = source.getASuccessor+() and
    step.getASuccessor*() = sink and
    option = step.getNode().asExpr() and
    option.getBase().toString() = "this.options"
  )
select sink.getNode(), source, sink,
  "The plugin '" +
  plugin.getPropertyName() +
  "' may expose its clients to XSS attacks through the option '" +
  option.getPropertyName() +
  "'"