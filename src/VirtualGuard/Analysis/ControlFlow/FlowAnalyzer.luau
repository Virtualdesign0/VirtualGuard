local CallResolverModule = require(script.Parent.Parent.Resolution.CallResolver)
local CFGModule = require(script.Parent.CFG)
local ConfigModule = require(script.Parent.Parent.Parent.Config)
local FlowDomainModule = require(script.Parent.FlowDomain)
local CallScannerModule = require(script.Parent.Parent.Scanning.CallScanner)
local SinkFlowsModule = require(script.Parent.Parent.Scanning.SinkFlows)
local ValueFactsModule = require(script.Parent.ValueFacts)
local ParserModule = require(script.Parent.Parent.Parsing.Parser)
local SemanticsModule = require(script.Parent.Parent.Parent.Rules.Semantics)
local SetModule = require(script.Parent.Parent.Parent.Shared.Set)
local TextModule = require(script.Parent.Parent.Parent.Shared.Text)

local FlowAnalyzer = {}
function FlowAnalyzer.hasSources(fact)
	return ValueFactsModule.hasSources(fact)
end

function FlowAnalyzer.evaluateExpression(expression, state)
	return ValueFactsModule.evaluateExpression(expression, state)
end

function FlowAnalyzer.evaluateRobloxQueryReturn(expression, state, doc)
	return ValueFactsModule.evaluateRobloxQueryReturn(expression, state, doc)
end

function FlowAnalyzer.evaluateValueExpression(expression, state, doc)
	return ValueFactsModule.evaluateValueExpression(expression, state, doc)
end

function FlowAnalyzer.findTaintedFactInText(text, state)
	return ValueFactsModule.findTaintedFactInText(text, state)
end

local bindingForExpression = ValueFactsModule.bindingForExpression
local invalidateDescendantGuarantees = ValueFactsModule.invalidateDescendantGuarantees

local function hasLogicalWord(code, word)
	return (code or ""):lower():find("%f[%w_]" .. word .. "%f[^%w_]") ~= nil
end

local function comparisonExists(code, leftPattern, operatorPattern, rightPattern)
	return (code or ""):find(leftPattern .. "%s*" .. operatorPattern .. "%s*" .. rightPattern) ~= nil
end

local function conditionHasSafeRangeFalseGuard(code, variableName)
	if hasLogicalWord(code, "not") or hasLogicalWord(code, "and") or not hasLogicalWord(code, "or") then
		return false
	end

	local variable = "%f[%w_]" .. TextModule.escapePattern(variableName) .. "%f[^%w_]"
	local number = "%-?%d[%d_]*%.?%d*"
	local lowerViolation = comparisonExists(code, variable, "<=?", number)
		or comparisonExists(code, number, ">=?", variable)
	local upperViolation = comparisonExists(code, variable, ">=?", number)
		or comparisonExists(code, number, "<=?", variable)

	return lowerViolation and upperViolation
end

local function expandTrustedValidatorCallee(callee, doc)
	local normalized = ConfigModule.normalizeTrustedValidatorName(callee)
	local variants = {
		[normalized] = true,
	}
	local first, rest = normalized:match("^([%w_]+)%.?(.*)$")
	if first and rest == "" and doc and doc.symbolAliases and doc.symbolAliases[first] then
		variants[ConfigModule.normalizeTrustedValidatorName(doc.symbolAliases[first])] = true
	end
	if first and rest and rest ~= "" then
		if doc and doc.symbolAliases and doc.symbolAliases[first] then
			variants[ConfigModule.normalizeTrustedValidatorName(doc.symbolAliases[first] .. "." .. rest)] = true
		end
		if doc and doc.serviceAliases and doc.serviceAliases[first] then
			variants[ConfigModule.normalizeTrustedValidatorName(doc.serviceAliases[first] .. "." .. rest)] = true
		end
		if doc and doc.pathAliases and doc.pathAliases[first] then
			local aliasTarget = doc.pathAliases[first]
			if typeof(aliasTarget) == "string" then
				variants[ConfigModule.normalizeTrustedValidatorName(aliasTarget .. "." .. rest)] = true
				local last = aliasTarget:match("([%w_]+)$")
				if last then
					variants[ConfigModule.normalizeTrustedValidatorName(last .. "." .. rest)] = true
				end
			elseif typeof(aliasTarget) == "Instance" then
				variants[ConfigModule.normalizeTrustedValidatorName(aliasTarget.Name .. "." .. rest)] = true
			end
		end
	end

	return variants
end

local function trustedValidatorBranchIsCertain(code, branchKind, passedBranch)
	if not passedBranch then
		return false
	end

	local hasOr = hasLogicalWord(code, "or")
	local hasAnd = hasLogicalWord(code, "and")
	if hasOr then
		return false
	end
	if branchKind == "true" then
		return true
	end
	if branchKind == "false" then
		return not hasAnd
	end

	return false
end

local function stripOuterParens(expression)
	local code = ConfigModule.trim(expression or "")
	while code:sub(1, 1) == "(" do
		local closeIndex = CallResolverModule.findMatchingParen(code, 1)
		if closeIndex ~= #code then
			break
		end
		code = ConfigModule.trim(code:sub(2, #code - 1))
	end
	return code
end

local function splitTopLevelLogicalAnd(expression)
	local parts = {}
	local code = expression or ""
	local startIndex = 1
	local depth = 0
	local index = 1

	while index <= #code do
		local char = code:sub(index, index)
		if char == "(" or char == "{" or char == "[" then
			depth += 1
			index += 1
		elseif char == ")" or char == "}" or char == "]" then
			depth = math.max(0, depth - 1)
			index += 1
		elseif depth == 0 and code:sub(index):find("^and%f[^%w_]") and (index == 1 or code:sub(index - 1, index - 1):match("[^%w_]")) then
			local part = ConfigModule.trim(code:sub(startIndex, index - 1))
			if part ~= "" then
				table.insert(parts, part)
			end
			index += 3
			startIndex = index
		else
			index += 1
		end
	end

	local final = ConfigModule.trim(code:sub(startIndex))
	if final ~= "" then
		table.insert(parts, final)
	end

	return parts
end

local function directCallCallee(expression)
	local code = stripOuterParens(expression)
	local callee, openIndex = code:match("^([%w_%.:]+)%s*()")
	if not callee then
		return nil
	end

	if code:sub(openIndex, openIndex) ~= "(" then
		return nil
	end

	local closeIndex = CallResolverModule.findMatchingParen(code, openIndex)
	if closeIndex and ConfigModule.trim(code:sub(closeIndex + 1)) == "" then
		return callee
	end

	return nil
end

local function positiveValidatorExpressionForBranch(predicate, branchKind)
	local code = stripOuterParens(predicate)

	if branchKind == "true" then
		if code:match("^not%f[^%w_]") then
			return nil
		end

		local left = code:match("^(.-)%s*==%s*true%s*$") or code:match("^(.-)%s*~=%s*false%s*$")
		if left then
			return stripOuterParens(left)
		end

		local right = code:match("^true%s*==%s*(.-)%s*$") or code:match("^false%s*~=%s*(.-)%s*$")
		if right then
			return stripOuterParens(right)
		end

		return directCallCallee(code) and code or nil
	end

	if branchKind == "false" then
		local negated = code:match("^not%f[^%w_](.+)$")
		if negated then
			negated = stripOuterParens(negated)
			return directCallCallee(negated) and negated or nil
		end

		local left = code:match("^(.-)%s*==%s*false%s*$") or code:match("^(.-)%s*~=%s*true%s*$")
		if left then
			return stripOuterParens(left)
		end

		local right = code:match("^false%s*==%s*(.-)%s*$") or code:match("^true%s*~=%s*(.-)%s*$")
		if right then
			return stripOuterParens(right)
		end
	end

	return nil
end

local function positiveValidatorCalleeForBranch(predicate, branchKind)
	local expression = positiveValidatorExpressionForBranch(predicate, branchKind)
	return expression and directCallCallee(expression) or nil
end

local function applyTrustedValidatorGuarantees(pathGuarantees, condition, branchKind, passedBranch, trustedValidators, doc)
	local code = TextModule.stripStringsForAnalysis(condition or "")
	if not trustedValidatorBranchIsCertain(code, branchKind, passedBranch) then
		return
	end

	for _, predicate in ipairs(splitTopLevelLogicalAnd(code)) do
		local callee = positiveValidatorCalleeForBranch(predicate, branchKind)
		if not callee then
			continue
		end

		local variants = expandTrustedValidatorCallee(callee, doc)
		for callName, grants in pairs(trustedValidators or {}) do
			if variants[ConfigModule.normalizeTrustedValidatorName(callName)] then
				for guarantee, value in pairs(grants) do
					if value == true then
						pathGuarantees[guarantee] = true
					end
				end
			end
		end
	end
end

local function applyRobloxValidatorGuarantees(state, condition, branchKind, doc)
	local code = TextModule.stripStringsForAnalysis(condition or "")
	if hasLogicalWord(code, "or") or (branchKind == "false" and hasLogicalWord(code, "and")) then
		return
	end
	local source = doc and (doc.analysisSource or doc.source) or ""
	for _, predicate in ipairs(splitTopLevelLogicalAnd(code)) do
		local callExpression = positiveValidatorExpressionForBranch(predicate, branchKind)
		if not callExpression then
			continue
		end
		for _, qualifiedCall in ipairs(CallResolverModule.extractQualifiedCalls(callExpression)) do
			if qualifiedCall.startIndex ~= 1 or qualifiedCall.closeIndex ~= #callExpression then
				continue
			end
			local resolvedCall = CallResolverModule.canonicalizeCall(doc, qualifiedCall, state)
			local helper = CallResolverModule.resolveCustomMethod(source, resolvedCall)
			local effect, resolution = CallResolverModule.resolveRobloxApiEffect(source, doc, resolvedCall, helper, state)
			if effect
				and effect.kind == "validator"
				and (resolution == "exact" or resolution == "method")
				and resolvedCall.method == "IsDescendantOf"
			then
				local ancestor = TextModule.splitTopLevelArgs(qualifiedCall.argsText)[1]
				local subject = ConfigModule.trim(qualifiedCall.rootPath or ""):gsub("%s+", "")
				local normalizedAncestor = ConfigModule.trim(ancestor or ""):gsub("%s+", "")
				if subject ~= "" and normalizedAncestor ~= "" then
					state.pathGuarantees.descendants = state.pathGuarantees.descendants or {}
					state.pathGuarantees.descendants[subject] =
						state.pathGuarantees.descendants[subject] or {}
					state.pathGuarantees.descendants[subject][normalizedAncestor] = true
				end
			end
		end
	end
end

local function applyConditionGuaranteesImpl(state, condition, branchKind, options)
	local code = TextModule.stripStringsForAnalysis(condition or "")
	local lower = code:lower()
	local negated = lower:match("^%s*not%s+") ~= nil
	local passedBranch = (branchKind == "true" and not negated) or (branchKind == "false" and negated)
	local safeAfterRangeGuard = branchKind == "false"

	state.pathGuarantees = state.pathGuarantees or {}
	applyTrustedValidatorGuarantees(
		state.pathGuarantees,
		code,
		branchKind,
		passedBranch,
		options and options.context and options.context.trustedValidators,
		options and options.doc
	)
	applyRobloxValidatorGuarantees(state, code, branchKind, options and options.doc)

	for variableName, fact in pairs(state.variables or {}) do
		if FlowAnalyzer.hasSources(fact) then
			local pattern = "%f[%w_]" .. TextModule.escapePattern(variableName) .. "%f[^%w_]"
			if code:find(pattern) then
				if safeAfterRangeGuard and conditionHasSafeRangeFalseGuard(code, variableName) then
					fact.guarantees.number = true
					fact.guarantees.bounded = true
				end
			end
		end
	end
end

local function applyForLoopTaintsImpl(state, condition, branchKind)
	if branchKind ~= "true" then
		return
	end

	local variablesText, iteratorText = tostring(condition or ""):match("^%s*for%s+(.+)%s+in%s+(.+)$")
	if variablesText and iteratorText then
		local iteratorFact = FlowAnalyzer.evaluateExpression(iteratorText, state)
		if FlowAnalyzer.hasSources(iteratorFact) then
			for _, variable in ipairs(TextModule.splitTopLevelList(variablesText)) do
				local name = TextModule.extractParameterName(variable)
				if name and name ~= "_" then
					local fact = FlowDomainModule.FlowDomain.cloneFact(iteratorFact)
					fact.guarantees = {}
					state.variables[name] = fact
				end
			end
		end
		return
	end

	local name, rangeText = tostring(condition or ""):match("^%s*for%s+([%a_][%w_]*)%s*=%s*(.+)$")
	if name and rangeText then
		local rangeFact = FlowAnalyzer.evaluateExpression(rangeText, state)
		if FlowAnalyzer.hasSources(rangeFact) then
			local fact = FlowDomainModule.FlowDomain.cloneFact(rangeFact)
			fact.guarantees = {}
			state.variables[name] = fact
		end
	end
end

local function refineEdgeImpl(state, edge, options)
	local result = FlowDomainModule.FlowDomain.cloneState(state)
	local condition = edge.condition or ""
	if condition:match("^%s*false%s*$") and edge.kind == "true" then
		result.reachable = false
		return result
	end
	if condition:match("^%s*true%s*$") and edge.kind == "false" then
		result.reachable = false
		return result
	end

	local name, operator, expected = condition:match('typeof%s*%(%s*([%w_%.]+)%s*%)%s*([~=]=)%s*"([^"]+)"')
	if not name then
		name, operator, expected = condition:match("typeof%s*%(%s*([%w_%.]+)%s*%)%s*([~=]=)%s*'([^']+)'")
	end
	if not name then
		name, operator, expected = condition:match('type%s*%(%s*([%w_%.]+)%s*%)%s*([~=]=)%s*"([^"]+)"')
	end
	if not name then
		name, operator, expected = condition:match("type%s*%(%s*([%w_%.]+)%s*%)%s*([~=]=)%s*'([^']+)'")
	end
	if name and expected == "number" then
		local guaranteesNumber = (operator == "==" and edge.kind == "true") or (operator == "~=" and edge.kind == "false")
		if guaranteesNumber and result.variables[name] then
			result.variables[name].guarantees.number = true
		end
	end

	local nilName, nilOperator = condition:match("([%w_%.]+)%s*([~=]=)%s*nil")
	if not nilName then
		nilOperator, nilName = condition:match("nil%s*([~=]=)%s*([%w_%.]+)")
	end
	if nilName and result.variables[nilName] and result.variables[nilName].guarantees.numberOrNil == true then
		local provesNotNil = (nilOperator == "~=" and edge.kind == "true") or (nilOperator == "==" and edge.kind == "false")
		if provesNotNil then
			result.variables[nilName].guarantees.number = true
		end
	end

	applyForLoopTaintsImpl(result, condition, edge.kind)
	applyConditionGuaranteesImpl(result, condition, edge.kind, options)
	for _, scopeId in ipairs(edge.scopeExits or {}) do
		FlowDomainModule.FlowDomain.exitBindingScope(result, scopeId)
	end
	for _, scopeId in ipairs(edge.scopeEnters or {}) do
		FlowDomainModule.FlowDomain.enterBindingScope(result, scopeId)
	end
	return result
end

function FlowAnalyzer.findSinkFlowsInStatement(text, state, doc)
	return SinkFlowsModule.findSinkFlowsInStatement(FlowAnalyzer, text, state, doc)
end

function FlowAnalyzer.findSinkFlowInStatement(text, state, doc)
	return SinkFlowsModule.findSinkFlowInStatement(FlowAnalyzer, text, state, doc)
end

function FlowAnalyzer.applyValidationBarrier(text, state)
	return SinkFlowsModule.applyValidationBarrier(text, state)
end

function FlowAnalyzer.inspectModuleCalls(context, doc, text, state)
	return CallScannerModule.inspectModuleCalls(FlowAnalyzer, context, doc, text, state)
end

function FlowAnalyzer.inspectLocalFunctionCalls(doc, text, state, ignoredNames)
	return CallScannerModule.inspectLocalFunctionCalls(FlowAnalyzer, doc, text, state, ignoredNames)
end

function FlowAnalyzer.transferSimpleStatement(options, statement, state, inspectFindings, analyzeCallees)
	local nextState = FlowDomainModule.FlowDomain.cloneState(state)
	local rawText = statement.text or ""
	local codeText = TextModule.stripStringsForAnalysis(rawText)
	FlowAnalyzer.applyValidationBarrier(codeText, nextState)

	local fieldRoot, fieldName, fieldExpression = SemanticsModule.parseFieldAssignment(rawText)
	if fieldRoot then
		local fact = FlowAnalyzer.evaluateValueExpression(TextModule.stripStringsForAnalysis(fieldExpression), nextState, options.doc)
		nextState.variables[fieldName] = fact
		local isParentAssignment = fieldName == fieldRoot .. ".Parent"
		if FlowAnalyzer.hasSources(fact) and not isParentAssignment then
			local rootFact = nextState.variables[fieldRoot] or FlowDomainModule.FlowDomain.emptyFact()
			rootFact.sources = SetModule.unionSets(rootFact.sources, fact.sources)
			nextState.variables[fieldRoot] = rootFact
		end
	end

	local assignedName, assignedExpression = SemanticsModule.parseSimpleAssignment(codeText)
	if assignedName then
		local assignedFact = FlowAnalyzer.evaluateValueExpression(assignedExpression, nextState, options.doc)
		local assignedBinding = bindingForExpression(options.doc, nextState, assignedExpression)
		if not assignedBinding and options.doc then
			if options.doc.serviceAliases
				and options.doc.serviceAliases[assignedName]
				and assignedExpression:find("game%s*:%s*GetService%s*%(")
			then
				assignedBinding = {
					kind = "service",
					target = options.doc.serviceAliases[assignedName],
				}
			elseif options.doc.aliasTargets
				and options.doc.aliasTargets[assignedName]
				and assignedExpression:find("^%s*require%s*%(")
			then
				assignedBinding = {
					kind = "module",
					target = assignedName,
				}
			end
		end
		nextState.variables[assignedName] = assignedFact
		invalidateDescendantGuarantees(nextState.pathGuarantees, assignedName)
		FlowDomainModule.FlowDomain.assignBinding(
			nextState,
			assignedName,
			assignedBinding,
			rawText:match("^%s*local%f[^%w_]") ~= nil
		)
	end

	local findings = {}
	local incompleteReason = nil
	local sinkFlows = inspectFindings ~= false and FlowAnalyzer.findSinkFlowsInStatement(rawText, nextState, options.doc) or {}
	for _, sinkFlow in ipairs(sinkFlows) do
		local trustLevel = SemanticsModule.classifySinkTrust(
			sinkFlow.fact,
			sinkFlow.sinkKind,
			nextState.pathGuarantees,
			sinkFlow.subject
		)
		table.insert(findings, {
			line = statement.line,
			evidence = "Tainted `" .. tostring(sinkFlow.name) .. "` reaches " .. tostring(sinkFlow.sinkKind) .. " sink operand: " .. tostring(sinkFlow.evidence),
			flow = options.initialFlow,
			mitigated = trustLevel == "mitigated",
			validated = trustLevel == "validated",
			trustLevel = trustLevel,
			fact = sinkFlow.fact,
		})
	end

	if inspectFindings == false and analyzeCallees ~= true then
		return nextState, nil
	end

	local function inspectCallee(call, targetDoc, methodBody, flowLabel, paramOffset)
		if TextModule.hasExceededCfgDeadline(options.context) then
			return nil, "CFG deadline exceeded before callee analysis."
		end
		local calleeState = FlowDomainModule.FlowDomain.newState()
		calleeState.pathGuarantees = FlowDomainModule.clonePathGuarantees(nextState.pathGuarantees)
		for index, fact in ipairs(call.argFacts or {}) do
			if call.functionAliasImplicitSelf then
				if index == 1 then
					calleeState.variables.self = FlowDomainModule.FlowDomain.cloneFact(fact or FlowDomainModule.FlowDomain.emptyFact())
				else
					local param = methodBody.args[index - 1]
					if param then
						calleeState.variables[param] = FlowDomainModule.FlowDomain.cloneFact(fact or FlowDomainModule.FlowDomain.emptyFact())
					elseif FlowAnalyzer.hasSources(fact) then
						incompleteReason = incompleteReason or "Tainted function-alias argument could not be mapped after implicit self."
					end
				end
			else
				local param = methodBody.args[index + (paramOffset or 0)]
				if param then
					calleeState.variables[param] = FlowDomainModule.FlowDomain.cloneFact(fact or FlowDomainModule.FlowDomain.emptyFact())
				elseif FlowAnalyzer.hasSources(fact) then
					incompleteReason = incompleteReason or "Tainted call argument could not be mapped to callee parameter."
				end
			end
		end
		if FlowAnalyzer.hasSources(call.receiverFact) then
			if (paramOffset or 0) > 0 and methodBody.args[1] then
				calleeState.variables[methodBody.args[1]] = FlowDomainModule.FlowDomain.cloneFact(call.receiverFact)
			elseif call.separator == ":" then
				calleeState.variables.self = FlowDomainModule.FlowDomain.cloneFact(call.receiverFact)
			end
		end
		for name, fact in pairs(call.capturedFacts or {}) do
			if not calleeState.variables[name] then
				calleeState.variables[name] = FlowDomainModule.FlowDomain.cloneFact(fact)
			end
		end

		local nextFlow = {}
		for _, item in ipairs(options.initialFlow or {}) do
			table.insert(nextFlow, item)
		end
		table.insert(nextFlow, flowLabel)

		local result = FlowAnalyzer.analyzeFunction({
			context = options.context,
			doc = targetDoc,
			source = methodBody.body,
			params = methodBody.args,
			initialState = calleeState,
			initialFlow = nextFlow,
			depth = (options.depth or 0) + 1,
			rootBudget = options.rootBudget,
		})
		if result and result.finding then
			table.insert(findings, result.finding)
		end
		if not result or result.success == false or result.complete == false then
			return result, result and result.reason or "Callee analysis did not return a result."
		end
		return result, nil
	end

	local function applyReturnFact(callName, result)
		if assignedName and assignedExpression and result and result.complete ~= false and result.returnFact
			and CallResolverModule.isDirectCallExpression(assignedExpression, TextModule.escapePattern(callName)) then
			nextState.variables[assignedName] = FlowDomainModule.FlowDomain.cloneFact(result.returnFact)
		end
	end

	for _, call in ipairs(FlowAnalyzer.inspectModuleCalls(options.context, options.doc, codeText, nextState)) do
		local targetDoc = options.context.modulesByInstance[call.target]
		if targetDoc then
			local targetSource = targetDoc.analysisSource or targetDoc.source
			local methodBody = call.direct and CallResolverModule.findReturnedFunctionBody(targetSource) or CallResolverModule.findMethodBody(targetSource, call.method, targetDoc.returnNames)
			if methodBody then
				local paramOffset = 0
				local methodUsesImplicitSelf = tostring(methodBody.name or ""):find(":", 1, true) ~= nil
				if call.functionAlias then
					call.functionAliasImplicitSelf = methodUsesImplicitSelf
				else
					if not call.direct and call.separator == ":" and not methodUsesImplicitSelf then
						paramOffset = 1
					end
					if not call.direct and call.separator == "." and methodUsesImplicitSelf then
						incompleteReason = incompleteReason or "Dot call to colon-declared module method has ambiguous self mapping."
					end
				end
				local labelMethod = call.direct and "return function" or tostring(methodBody.name or call.method)
				local result, reason = inspectCallee(
					call,
					targetDoc,
					methodBody,
					options.doc.path .. ":" .. tostring(statement.line) .. " -> " .. TextModule.getPath(call.target) .. ":" .. labelMethod,
					paramOffset
				)
				applyReturnFact(
					call.invokedName
						or (call.direct and call.alias or (call.alias .. tostring(call.separator or ".") .. tostring(call.method))),
					result
				)
				if reason then
					incompleteReason = incompleteReason or reason
					options.context.cfgIncompleteCallees = (options.context.cfgIncompleteCallees or 0) + 1
					options.context.cfgIncompleteReasons = options.context.cfgIncompleteReasons or {}
					if #options.context.cfgIncompleteReasons < 8 then
						table.insert(options.context.cfgIncompleteReasons, TextModule.getPath(call.target) .. ":" .. labelMethod .. " - " .. tostring(reason))
					end
				end
			else
				incompleteReason = incompleteReason or (call.direct and "Tainted direct ModuleScript function call could not be resolved." or "Tainted module method body could not be resolved.")
				options.context.cfgIncompleteCallees = (options.context.cfgIncompleteCallees or 0) + 1
				options.context.cfgIncompleteReasons = options.context.cfgIncompleteReasons or {}
				if #options.context.cfgIncompleteReasons < 8 then
					table.insert(options.context.cfgIncompleteReasons, TextModule.getPath(call.target) .. ":" .. tostring(call.method or "return function") .. " - " .. tostring(incompleteReason))
				end
			end
		else
			incompleteReason = incompleteReason or "Tainted module call target could not be resolved."
		end
	end

	local ignoredDirectCalls = {
		assert = true,
		error = true,
		ipairs = true,
		next = true,
		pairs = true,
		pcall = true,
		print = true,
		tonumber = true,
		tostring = true,
		type = true,
		typeof = true,
		warn = true,
		xpcall = true,
	}

	for _, localCall in ipairs(FlowAnalyzer.inspectLocalFunctionCalls(options.doc, codeText, nextState, ignoredDirectCalls)) do
		local helper = localCall.helper
		if not helper then
			local resolutionSource = options.doc.analysisSource or options.doc.source
			if localCall.qualified then
				helper = CallResolverModule.findExactQualifiedFunctionBody(resolutionSource, localCall.name)
			else
				helper = CallResolverModule.findExactDirectFunctionBody(resolutionSource, localCall.name)
			end
		end
		if helper then
			local paramOffset = 0
			local helperUsesImplicitSelf = helper.implicitSelf == true
				or (helper.implicitSelf == nil and tostring(helper.name or ""):find(":", 1, true) ~= nil)
			if localCall.separator == ":" and not helperUsesImplicitSelf then
				paramOffset = 1
			elseif localCall.separator == "." and helperUsesImplicitSelf then
				incompleteReason = incompleteReason or "Dot call to colon-declared local method has ambiguous self mapping."
			end
			local result, reason = inspectCallee(
				localCall,
				options.doc,
				helper,
				options.doc.path .. ":" .. tostring(statement.line) .. " -> local " .. tostring(helper.name or localCall.name),
				paramOffset
			)
			applyReturnFact(localCall.name, result)
			if reason then
				incompleteReason = incompleteReason or reason
			end
		else
			incompleteReason = incompleteReason or (
				localCall.qualified
					and ("Unresolved tainted qualified call: " .. tostring(localCall.name))
					or ("Tainted local/global function call could not be resolved: " .. tostring(localCall.name))
			)
		end
	end

	return nextState, FlowAnalyzer.chooseWorstFinding(findings), incompleteReason
end

function FlowAnalyzer.transferBlock(options, block, inputState, inspectFindings)
	local state = FlowDomainModule.FlowDomain.cloneState(inputState)
	local findings = {}
	local incompleteReason = nil
	for _, statement in ipairs(block.statements or {}) do
		if statement.kind == "Simple" then
			local nextState, finding, statementIncompleteReason = FlowAnalyzer.transferSimpleStatement(options, statement, state, inspectFindings)
			state = nextState
			if finding then
				table.insert(findings, finding)
			end
			if statementIncompleteReason then
				incompleteReason = incompleteReason or statementIncompleteReason
			end
		end
	end
	return state, FlowAnalyzer.chooseWorstFinding(findings), incompleteReason
end

local FLOW_TRUST_RANK = {
	none = 1,
	mitigated = 2,
	validated = 3,
}

local function findingTrustRank(finding)
	local trustLevel = finding and finding.trustLevel
	if trustLevel then
		return FLOW_TRUST_RANK[trustLevel] or FLOW_TRUST_RANK.none
	end
	if finding and finding.validated == true then
		return FLOW_TRUST_RANK.validated
	end
	if finding and finding.mitigated == true then
		return FLOW_TRUST_RANK.mitigated
	end
	return FLOW_TRUST_RANK.none
end

function FlowAnalyzer.chooseWorstFinding(findings)
	local best = nil
	for _, finding in ipairs(findings or {}) do
		if not best then
			best = finding
		else
			local bestRank = findingTrustRank(best)
			local currentRank = findingTrustRank(finding)
			if currentRank < bestRank then
				best = finding
			end
		end
	end
	return best
end

function FlowAnalyzer.inspectBlocks(options, cfg, inStates)
	local findings = {}
	local incompleteReasons = {}
	local blockIds = {}
	for blockId in pairs(cfg.blocks or {}) do
		table.insert(blockIds, blockId)
	end
	table.sort(blockIds)

	for _, blockId in ipairs(blockIds) do
		if TextModule.hasExceededCfgDeadline(options.context) then
			table.insert(incompleteReasons, "CFG deadline exceeded during block inspection.")
			break
		end
		local block = cfg.blocks[blockId]
		local inputState = inStates[blockId]
		if inputState and inputState.reachable then
			local _, finding, incompleteReason = FlowAnalyzer.transferBlock(options, block, inputState, true)
			if finding then
				table.insert(findings, finding)
			end
			if incompleteReason then
				table.insert(incompleteReasons, incompleteReason)
			end
			TextModule.maybeYield(options.context)
		end
	end
	return FlowAnalyzer.chooseWorstFinding(findings), incompleteReasons
end

function FlowAnalyzer.collectReturnFact(options, cfg, inStates)
	local returnFact = nil
	local hasReachableImplicitExit = false
	for blockId, block in pairs(cfg.blocks or {}) do
		if TextModule.hasExceededCfgDeadline(options.context) then
			return nil
		end
		local inputState = inStates[blockId]
		if inputState and inputState.reachable then
			local state = FlowDomainModule.FlowDomain.cloneState(inputState)
			for _, statement in ipairs(block.statements or {}) do
				if statement.kind == "Simple" then
					state = FlowAnalyzer.transferSimpleStatement(options, statement, state, false, true)
				elseif statement.kind == "Return" then
					local expression = tostring(statement.text or ""):gsub("^%s*return%s*", "")
					local firstExpression = TextModule.splitTopLevelArgs(expression)[1]
					if firstExpression and firstExpression ~= "" then
						local fact = FlowAnalyzer.evaluateValueExpression(firstExpression, state, options.doc)
						returnFact = returnFact and FlowDomainModule.FlowDomain.joinFact(returnFact, fact) or FlowDomainModule.FlowDomain.cloneFact(fact)
					else
						local emptyFact = FlowDomainModule.FlowDomain.emptyFact()
						returnFact = returnFact and FlowDomainModule.FlowDomain.joinFact(returnFact, emptyFact) or emptyFact
					end
				end
			end
			for _, edge in ipairs(block.successors or {}) do
				if edge.to == cfg.exit and edge.kind == "normal" then
					hasReachableImplicitExit = true
					break
				end
			end
		end
	end
	if hasReachableImplicitExit then
		local emptyFact = FlowDomainModule.FlowDomain.emptyFact()
		returnFact = returnFact and FlowDomainModule.FlowDomain.joinFact(returnFact, emptyFact) or emptyFact
	end
	return returnFact
end

function FlowAnalyzer.applyConditionGuarantees(state, condition, branchKind, options)
	return applyConditionGuaranteesImpl(state, condition, branchKind, options)
end

function FlowAnalyzer.applyForLoopTaints(state, condition, branchKind)
	return applyForLoopTaintsImpl(state, condition, branchKind)
end

function FlowAnalyzer.refineEdge(state, edge, options)
	return refineEdgeImpl(state, edge, options)
end
function FlowAnalyzer.analyzeCFG(options, cfg)
	local budgets = options.context.scanBudgets
	local inStates = {}
	local queue = { cfg.entry }
	local queued = {
		[cfg.entry] = true,
	}
	inStates[cfg.entry] = FlowDomainModule.FlowDomain.cloneState(options.initialState)
	local iterations = 0

	while #queue > 0 and iterations < budgets.maxWorklistIterations do
		iterations += 1
		if iterations % 40 == 0 then
			if TextModule.hasExceededCfgDeadline(options.context) then
				return {
					complete = false,
					solverComplete = false,
					semanticComplete = false,
					reason = "CFG deadline exceeded.",
					finding = nil,
				}
			end
			TextModule.maybeYield(options.context)
		end
		local blockId = table.remove(queue, 1)
		queued[blockId] = nil
		local block = cfg.blocks[blockId]
		local inputState = inStates[blockId]

		if block and inputState and inputState.reachable then
			local outputState = FlowAnalyzer.transferBlock(options, block, inputState, false)
			for _, edge in ipairs(block.successors or {}) do
				local edgeState = FlowAnalyzer.refineEdge(outputState, edge, options)
				local merged, changed = FlowDomainModule.FlowDomain.mergeState(inStates[edge.to], edgeState)
				inStates[edge.to] = merged
				if changed and not queued[edge.to] then
					queued[edge.to] = true
					table.insert(queue, edge.to)
				end
			end
		end
	end

	if #queue > 0 then
		options.context.cfgBudgetExceeded = true
		return {
			complete = false,
			solverComplete = false,
			semanticComplete = false,
			reason = "CFG worklist budget exceeded.",
			finding = nil,
		}
	end
	if TextModule.hasExceededCfgDeadline(options.context) then
		return {
			complete = false,
			solverComplete = false,
			semanticComplete = false,
			reason = "CFG deadline exceeded.",
			finding = nil,
		}
	end

	local returnFact = FlowAnalyzer.collectReturnFact(options, cfg, inStates)
	if TextModule.hasExceededCfgDeadline(options.context) then
		return {
			complete = false,
			solverComplete = true,
			semanticComplete = false,
			reason = "CFG deadline exceeded during return analysis.",
			finding = nil,
		}
	end
	local finding, incompleteReasons = FlowAnalyzer.inspectBlocks(options, cfg, inStates)
	if #incompleteReasons > 0 then
		return {
			complete = false,
			solverComplete = true,
			semanticComplete = false,
			reason = incompleteReasons[1],
			reasons = incompleteReasons,
			finding = finding,
			returnFact = returnFact,
		}
	end

	return {
		complete = true,
		solverComplete = true,
		semanticComplete = true,
		finding = finding,
		returnFact = returnFact,
	}
end

function FlowAnalyzer.buildSummaryKey(options)
	local names = {}
	local guaranteeKeys = {}
	local sourceKeys = {}
	for name, fact in pairs((options.initialState and options.initialState.variables) or {}) do
		if FlowAnalyzer.hasSources(fact) then
			table.insert(names, name)
			for source in pairs(fact.sources or {}) do
				table.insert(sourceKeys, name .. ":" .. source)
			end
			for guarantee in pairs(fact.guarantees or {}) do
				table.insert(guaranteeKeys, name .. ":" .. guarantee)
			end
		end
	end
	table.sort(names)
	table.sort(sourceKeys)
	table.sort(guaranteeKeys)
	local pathGuarantees = {}
	for guarantee, value in pairs((options.initialState and options.initialState.pathGuarantees) or {}) do
		if guarantee == "descendants" and type(value) == "table" then
			for subject, ancestors in pairs(value) do
				for ancestor in pairs(ancestors) do
					table.insert(pathGuarantees, "descendant:" .. subject .. "->" .. ancestor)
				end
			end
		elseif value == true then
			table.insert(pathGuarantees, guarantee)
		end
	end
	table.sort(pathGuarantees)
	local bindings = {}
	for name, binding in pairs((options.initialState and options.initialState.bindings) or {}) do
		table.insert(bindings, name .. ":" .. tostring(binding.kind) .. ":" .. tostring(binding.target or ""))
	end
	table.sort(bindings)
	return tostring(options.doc and options.doc.path or "unknown")
		.. "|hash="
		.. TextModule.stableHash(tostring(options.source or ""))
		.. "|taint="
		.. table.concat(names, ",")
		.. "|sources="
		.. table.concat(sourceKeys, ",")
		.. "|guarantees="
		.. table.concat(guaranteeKeys, ",")
		.. "|path="
		.. table.concat(pathGuarantees, ",")
		.. "|bindings="
		.. table.concat(bindings, ",")
end

function FlowAnalyzer.analyzeFunction(options)
	local budgets = options.context.scanBudgets
	options.initialState = FlowDomainModule.FlowDomain.cloneState(options.initialState or FlowDomainModule.FlowDomain.newState())
	for _, parameter in ipairs(options.params or {}) do
		if parameter and parameter ~= "" then
			FlowDomainModule.FlowDomain.assignBinding(options.initialState, parameter, {
				kind = "unknown",
			}, false)
		end
	end
	local isRoot = (options.depth or 0) == 0
	if TextModule.hasExceededCfgDeadline(options.context) then
		return {
			success = false,
			complete = false,
			reason = "CFG deadline exceeded.",
		}
	end
	if not ConfigModule.ENABLE_CFG_ANALYZER or (options.depth or 0) > budgets.maxDepth then
		return {
			success = false,
			complete = false,
			reason = "CFG analyzer disabled or max interprocedural depth reached.",
		}
	end
	if #(options.source or "") > budgets.maxHandlerChars then
		return {
			success = false,
			complete = false,
			reason = "CFG source budget exceeded.",
		}
	end
	options.context.flowSummaryCache = options.context.flowSummaryCache or {}
	options.context.flowInProgress = options.context.flowInProgress or {}
	local summaryKey = FlowAnalyzer.buildSummaryKey(options)
	local cached = options.context.flowSummaryCache[summaryKey]
	if cached then
		options.context.cfgSummaryCacheHits = (options.context.cfgSummaryCacheHits or 0) + 1
		return cached
	end
	if options.context.flowInProgress[summaryKey] then
		return {
			success = true,
			complete = false,
			reason = "Recursive flow skipped.",
			finding = nil,
		}
	end

	options.rootBudget = options.rootBudget or {
		analyses = 0,
	}
	options.context.cfgElapsed = options.context.cfgElapsed or 0
	if options.context.cfgElapsed >= budgets.maxTotalTime then
		options.context.cfgBudgetExceeded = true
		options.context.cfgTimeBudgetExceeded = true
		return {
			success = false,
			complete = false,
			reason = "CFG total time budget exceeded.",
		}
	end
	options.rootBudget.analyses += 1
	if options.rootBudget.analyses > budgets.maxAnalysesPerRoot then
		options.context.cfgBudgetExceeded = true
		options.context.cfgRootBudgetExceeded = (options.context.cfgRootBudgetExceeded or 0) + 1
		return {
			success = false,
			complete = false,
			reason = "CFG root handler analysis budget exceeded.",
		}
	end
	options.context.flowAnalysisCount = (options.context.flowAnalysisCount or 0) + 1
	if options.context.flowAnalysisCount > budgets.maxAnalysesPerScan then
		options.context.cfgBudgetExceeded = true
		return {
			success = false,
			complete = false,
			reason = "CFG scan budget exceeded.",
		}
	end

	if isRoot and not options.context.cfgDeadline then
		local remaining = math.max(0, budgets.maxTotalTime - (options.context.cfgElapsed or 0))
		options.context.cfgDeadline = os.clock() + remaining
	end
	local rootTimerStart = isRoot and os.clock() or nil
	options.context.flowInProgress[summaryKey] = true
	local ok, result = pcall(function()
		local unsupportedSyntax = ParserModule.detectUnsupportedFlowSyntax(options.source or "")
		if #unsupportedSyntax > 0 then
			return {
				success = true,
				complete = false,
				parseComplete = false,
				solverComplete = false,
				semanticComplete = false,
				reason = "CFG parser coverage partial: " .. table.concat(unsupportedSyntax, ", "),
				unsupportedSyntax = unsupportedSyntax,
				finding = nil,
				engine = "cfg",
			}
		end

		local statements = ParserModule.FlowParser.parse(options.source or "", budgets, options.context)
		local cfg = CFGModule.CFGBuilder.build(statements, budgets, options.context)
		if TextModule.hasExceededCfgDeadline(options.context) then
			return {
				success = true,
				complete = false,
				parseComplete = true,
				solverComplete = false,
				semanticComplete = false,
				reason = "CFG deadline exceeded after graph build.",
				finding = nil,
				engine = "cfg",
			}
		end
		local cfgAnalysis = FlowAnalyzer.analyzeCFG(options, cfg)
		return {
			success = true,
			complete = cfgAnalysis.complete ~= false,
			parseComplete = true,
			solverComplete = cfgAnalysis.solverComplete ~= false,
			semanticComplete = cfgAnalysis.semanticComplete ~= false,
			finding = cfgAnalysis.finding,
			returnFact = cfgAnalysis.returnFact,
			reason = cfgAnalysis.reason,
			reasons = cfgAnalysis.reasons,
			engine = "cfg",
		}
	end)
	options.context.flowInProgress[summaryKey] = nil
	if rootTimerStart then
		options.context.cfgElapsed += os.clock() - rootTimerStart
		options.context.cfgDeadline = nil
	end

	if ok then
		if not result.finding
			and (options.context.flowSummaryCacheCount or 0) < (budgets.maxSummaryCacheEntries or 100)
		then
			options.context.flowSummaryCache[summaryKey] = result
			options.context.flowSummaryCacheCount = (options.context.flowSummaryCacheCount or 0) + 1
		end
		return result
	end

	return {
		success = false,
		complete = false,
		reason = tostring(result),
	}
end

return {
	applyRobloxValidatorGuarantees = applyRobloxValidatorGuarantees,
	applyTrustedValidatorGuarantees = applyTrustedValidatorGuarantees,
	bindingForExpression = bindingForExpression,
	comparisonExists = comparisonExists,
	conditionHasSafeRangeFalseGuard = conditionHasSafeRangeFalseGuard,
	directCallCallee = directCallCallee,
	expandTrustedValidatorCallee = expandTrustedValidatorCallee,
	findingTrustRank = findingTrustRank,
	FLOW_TRUST_RANK = FLOW_TRUST_RANK,
	FlowAnalyzer = FlowAnalyzer,
	hasLogicalWord = hasLogicalWord,
	invalidateDescendantGuarantees = invalidateDescendantGuarantees,
	positiveValidatorCalleeForBranch = positiveValidatorCalleeForBranch,
	positiveValidatorExpressionForBranch = positiveValidatorExpressionForBranch,
	splitTopLevelLogicalAnd = splitTopLevelLogicalAnd,
	stripOuterParens = stripOuterParens,
	trustedValidatorBranchIsCertain = trustedValidatorBranchIsCertain,
}
