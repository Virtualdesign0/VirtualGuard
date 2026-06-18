local ConfigModule = require(script.Parent.Parent.Parent.Config)
local TextModule = require(script.Parent.Parent.Parent.Shared.Text)
local CallResolverModule = require(script.Parent.Parent.Resolution.CallResolver)

local canonicalizeCall = CallResolverModule.canonicalizeCall
local resolveDirectCallable = CallResolverModule.resolveDirectCallable
local extractIdentifierCalls = CallResolverModule.extractIdentifierCalls
local extractQualifiedCalls = CallResolverModule.extractQualifiedCalls

local function findTaintedModuleCallsInLine(doc, line, lineNumberValue, taints)
	local calls = {}
	local function addModuleCall(target, alias, method, separator, args, direct, functionAlias, invokedName)
		local taintedArgIndexes = {}
		local taintedArgNames = {}
		for index, arg in ipairs(args or {}) do
			local hit, taintName = TextModule.containsTaint(arg, taints)
			if hit then
				table.insert(taintedArgIndexes, index)
				taintedArgNames[index] = taintName
			end
		end
		if #taintedArgIndexes > 0 then
			table.insert(calls, {
				target = target,
				alias = alias,
				separator = separator,
				method = method,
				direct = direct == true,
				functionAlias = functionAlias == true,
				invokedName = invokedName,
				args = args,
				taintedArgIndexes = taintedArgIndexes,
				taintedArgNames = taintedArgNames,
				line = lineNumberValue,
			})
		end
	end

	for _, qualifiedCall in ipairs(extractQualifiedCalls(line or "")) do
		local resolvedCall = canonicalizeCall(doc, qualifiedCall)
		local target = doc.aliasTargets and doc.aliasTargets[resolvedCall.root]
		if target then
			addModuleCall(
				target,
				resolvedCall.root,
				qualifiedCall.method,
				qualifiedCall.separator,
				TextModule.splitTopLevelArgs(qualifiedCall.argsText),
				false,
				false,
				qualifiedCall.name
			)
		end
	end

	for _, directCall in ipairs(extractIdentifierCalls(line or "")) do
		if directCall.name == "pcall" or directCall.name == "xpcall" then
			local callbackArgs = TextModule.splitTopLevelArgs(directCall.argsText)
			local callbackName = ConfigModule.trim(callbackArgs[1] or ""):match("^([%a_][%w_%.:]*)$")
			if callbackName then
				local forwarded = {}
				local firstForwarded = directCall.name == "xpcall" and 3 or 2
				for index = firstForwarded, #callbackArgs do
					table.insert(forwarded, callbackArgs[index])
				end
				local callable = resolveDirectCallable(doc.analysisSource or doc.source, doc, callbackName)
				if callable.kind == "module-method" then
					addModuleCall(callable.target, callable.root, callable.method, nil, forwarded, false, true, callbackName)
				else
					local target = doc.aliasTargets and doc.aliasTargets[callable.resolvedName]
					if target then
						addModuleCall(target, callable.resolvedName, nil, nil, forwarded, true, false, callbackName)
					end
				end
			end
		else
			local callable = resolveDirectCallable(doc.analysisSource or doc.source, doc, directCall.name)
			if callable.kind == "module-method" then
				addModuleCall(
					callable.target,
					callable.root,
					callable.method,
					nil,
					TextModule.splitTopLevelArgs(directCall.argsText),
					false,
					true,
					directCall.name
				)
			else
				local target = doc.aliasTargets and doc.aliasTargets[callable.resolvedName]
				if target then
					addModuleCall(
						target,
						callable.resolvedName,
						nil,
						nil,
						TextModule.splitTopLevelArgs(directCall.argsText),
						true,
						false,
						directCall.name
					)
				end
			end
		end
	end

	return calls
end

return {
	findTaintedModuleCallsInLine = findTaintedModuleCallsInLine,
}
