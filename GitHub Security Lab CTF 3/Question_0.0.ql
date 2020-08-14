import javascript

from DataFlow::GlobalVarRefNode var, DataFlow::CallNode call
where
  var.getName() = "$" and
  call = var.getACall()
select call.getArgument(0)