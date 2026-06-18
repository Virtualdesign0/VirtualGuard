local CallResolverModule = require(script.Parent.Parent.Resolution.CallResolver)
local ConfigModule = require(script.Parent.Parent.Parent.Config)
local SemanticsModule = require(script.Parent.Parent.Parent.Rules.Semantics)
local SetModule = require(script.Parent.Parent.Parent.Shared.Set)
local TextModule = require(script.Parent.Parent.Parent.Shared.Text)

local SinkFlows = {}

function SinkFlows.findSinkFlowsInStatement(FlowAnalyzer, text, state, doc)
	local flows = {}
	local source = doc and (doc.analysisSource or doc.source) or ""

	local function inspectExpression(sinkKind, expression, evidenceLabel, subject)
		local fact = FlowAnalyzer.evaluateExpression(expression, state)
		if FlowAnalyzer.hasSources(fact) then
			local name = FlowAnalyzer.findTaintedFactInText(expression, state) or "sink operand"
			table.insert(flows, {
				name = name,
				fact = fact,
				sinkKind = sinkKind,
				evidence = evidenceLabel,
				subject = subject,
			})
		end
	end

	local function inspectRobloxMethodValue(callable, args, evidenceLabel)
		local effect = callable and callable.effect
		if not effect or (effect.kind ~= "mutation" and effect.kind ~= "sensitive") then
			return
		end
		local sinkKind = effect.sinkKind or "InstanceMutation"
		if effect.receiverSensitive and args[1] then
			inspectExpression(sinkKind, args[1], evidenceLabel .. " [method receiver]", args[1])
		end
		for _, index in ipairs(effect.sensitiveArguments or {}) do
			if args[index + 1] then
				inspectExpression(sinkKind, args[index + 1], evidenceLabel .. " [argument " .. tostring(index) .. "]")
			end
		end
	end

	for _, segment in ipairs(TextModule.splitTopLevelStatements(text or "")) do
		local code = TextModule.stripStringsForAnalysis(segment)
		local _, operator, _, assignment = SemanticsModule.parseAssignmentStatement(segment)
		if assignment and operator then
			local sinkKind = SemanticsModule.classifyAssignmentSink(assignment.rawLhs)
			if sinkKind then
				inspectExpression(sinkKind, assignment.rawRhs, ConfigModule.trim(segment))
			end
			local parentReceiver = assignment.rawLhs:match("^%s*(.-)%.Parent%s*$")
				or assignment.rawLhs:match("^%s*(.-)%[%s*[\"']Parent[\"']%s*%]%s*$")
			if parentReceiver and parentReceiver ~= "" then
				inspectExpression("InstanceMutation", parentReceiver, ConfigModule.trim(segment) .. " [receiver]", parentReceiver)
				inspectExpression("InstanceMutation", assignment.rawRhs, ConfigModule.trim(segment) .. " [new parent]")
			end
		end

		for _, qualifiedCall in ipairs(CallResolverModule.extractQualifiedCalls(segment)) do
			local resolvedCall = CallResolverModule.canonicalizeCall(doc, qualifiedCall, state)
			local helper = CallResolverModule.resolveCustomMethod(source, resolvedCall)
			local effect = CallResolverModule.resolveRobloxApiEffect(source, doc, resolvedCall, helper, state)
			if effect and (effect.kind == "mutation" or effect.kind == "sensitive") then
				local sinkKind = effect.sinkKind or "InstanceMutation"
				if effect.receiverSensitive then
					inspectExpression(
						sinkKind,
						qualifiedCall.rootPath,
						ConfigModule.trim(segment) .. " [receiver]",
						qualifiedCall.rootPath
					)
				end
				local args = TextModule.splitTopLevelArgs(qualifiedCall.argsText)
				for _, index in ipairs(effect.sensitiveArguments or {}) do
					if args[index] then
						inspectExpression(sinkKind, args[index], ConfigModule.trim(segment) .. " [argument " .. tostring(index) .. "]")
					end
				end
			end
		end

		for _, directCall in ipairs(CallResolverModule.extractIdentifierCalls(code)) do
			if directCall.name == "pcall" or directCall.name == "xpcall" then
				local callbackArgs = TextModule.splitTopLevelArgs(directCall.argsText)
				local callbackName = ConfigModule.trim(callbackArgs[1] or ""):match("^([%a_][%w_%.:]*)$")
				if callbackName then
					local forwarded = {}
					local firstForwarded = directCall.name == "xpcall" and 3 or 2
					for index = firstForwarded, #callbackArgs do
						table.insert(forwarded, callbackArgs[index])
					end
					local callable = CallResolverModule.resolveDirectCallable(source, doc, callbackName, state)
					if callable.kind == "roblox-method" or callable.kind == "roblox-method-hint" then
						inspectRobloxMethodValue(callable, forwarded, ConfigModule.trim(segment))
					end
				end
			else
				local callable = CallResolverModule.resolveDirectCallable(source, doc, directCall.name, state)
				if callable.kind == "roblox-method" or callable.kind == "roblox-method-hint" then
					inspectRobloxMethodValue(
						callable,
						TextModule.splitTopLevelArgs(directCall.argsText),
						ConfigModule.trim(segment)
					)
				end
			end
		end

		for _, call in ipairs(TextModule.extractFunctionCalls(code, "DealDamage")) do
			if CallResolverModule.shouldApplyNameBasedSinkFallback(source, doc, code, "DealDamage", call) then
				local args = TextModule.splitTopLevelArgs(call.expression)
				for _, arg in ipairs(args) do
					inspectExpression("Damage", arg, ConfigModule.trim(segment))
				end
			end
		end

		for _, callName in ipairs({ "AddCoins", "AddCurrency", "GrantCurrency", "SetCoins" }) do
			for _, call in ipairs(TextModule.extractFunctionCalls(code, callName)) do
				if CallResolverModule.shouldApplyNameBasedSinkFallback(source, doc, code, callName, call) then
					for _, arg in ipairs(TextModule.splitTopLevelArgs(call.expression)) do
						inspectExpression("Economy", arg, ConfigModule.trim(segment))
					end
				end
			end
		end

		for _, callName in ipairs({ "SetAsync", "UpdateAsync", "RemoveAsync", "IncrementAsync" }) do
			for _, call in ipairs(TextModule.extractFunctionCalls(code, callName)) do
				if CallResolverModule.shouldApplyNameBasedSinkFallback(source, doc, code, callName, call) then
					for _, arg in ipairs(TextModule.splitTopLevelArgs(call.expression)) do
						inspectExpression("DataStore", arg, ConfigModule.trim(segment))
					end
				end
			end
		end

		for _, callName in ipairs({ "Kick", "Teleport", "TeleportAsync" }) do
			for _, call in ipairs(TextModule.extractFunctionCalls(code, callName)) do
				if CallResolverModule.shouldApplyNameBasedSinkFallback(source, doc, code, callName, call) then
					for _, arg in ipairs(TextModule.splitTopLevelArgs(call.expression)) do
						inspectExpression("PlayerControl", arg, ConfigModule.trim(segment))
					end
				end
			end
		end
	end

	return flows
end

function SinkFlows.findSinkFlowInStatement(FlowAnalyzer, text, state, doc)
	local flows = SinkFlows.findSinkFlowsInStatement(FlowAnalyzer, text, state, doc)
	return flows[1]
end

function SinkFlows.applyValidationBarrier(text, state)
	local guaranteesByName = SemanticsModule.validationGuaranteesForLine(text, state.variables, "barrier")
	for name, guarantees in pairs(guaranteesByName) do
		if state.variables[name] then
			state.variables[name].guarantees = SetModule.unionSets(state.variables[name].guarantees, guarantees)
		end
	end
end

return SinkFlows
