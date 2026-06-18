local CallResolverModule = require(script.Parent.Parent.Resolution.CallResolver)
local ConfigModule = require(script.Parent.Parent.Parent.Config)
local FlowDomainModule = require(script.Parent.FlowDomain)
local SetModule = require(script.Parent.Parent.Parent.Shared.Set)
local TextModule = require(script.Parent.Parent.Parent.Shared.Text)

local ValueFacts = {}

function ValueFacts.hasSources(fact)
	return fact and SetModule.hasSetValues(fact.sources)
end

function ValueFacts.evaluateExpression(expression, state)
	local result = FlowDomainModule.FlowDomain.emptyFact()
	local code = TextModule.stripStringsForAnalysis(expression or "")
	local matchedFacts = {}
	local matchedNames = {}
	for variableName, fact in pairs(state.variables or {}) do
		local pattern = "%f[%w_]" .. TextModule.escapePattern(variableName) .. "%f[^%w_]"
		if code:find(pattern) then
			result.sources = SetModule.unionSets(result.sources, fact.sources)
			if ValueFacts.hasSources(fact) then
				table.insert(matchedFacts, fact)
				table.insert(matchedNames, variableName)
			end
		end
	end

	if #matchedFacts == 1 then
		local directPattern = "^%s*" .. TextModule.escapePattern(matchedNames[1]) .. "%s*$"
		if code:find(directPattern) then
			result.guarantees = SetModule.unionSets(result.guarantees, matchedFacts[1].guarantees)
		else
			if matchedFacts[1].guarantees.number == true and not CallResolverModule.hasConcat(code) then
				result.guarantees.number = true
			end
			if not CallResolverModule.hasArithmeticOrConcat(code) then
				result.guarantees = SetModule.unionSets(result.guarantees, matchedFacts[1].guarantees)
			end
			result.guarantees.bounded = nil
		end
	elseif #matchedFacts > 1 then
		local shared = nil
		for _, fact in ipairs(matchedFacts) do
			shared = shared and SetModule.intersectSets(shared, fact.guarantees) or SetModule.unionSets(fact.guarantees, {})
		end
		result.guarantees = SetModule.unionSets(result.guarantees, shared)
		result.guarantees.bounded = nil
	end

	if CallResolverModule.isDirectCallExpression(code, "tonumber") then
		result.guarantees.numberOrNil = true
	end
	local clampArgs = CallResolverModule.getDirectCallArgs(code, "math%.clamp")
	if clampArgs then
		result.guarantees.number = true
		if CallResolverModule.isTrustedNumericBound(clampArgs[2]) and CallResolverModule.isTrustedNumericBound(clampArgs[3]) then
			result.guarantees.bounded = true
		end
	end
	return result
end

function ValueFacts.evaluateRobloxQueryReturn(expression, state, doc)
	local code = ConfigModule.trim(expression or "")
	local source = doc and (doc.analysisSource or doc.source) or ""

	for _, qualifiedCall in ipairs(CallResolverModule.extractQualifiedCalls(code)) do
		if qualifiedCall.startIndex == 1 and qualifiedCall.closeIndex == #code then
			local resolvedCall = CallResolverModule.canonicalizeCall(doc, qualifiedCall, state)
			local helper = CallResolverModule.resolveCustomMethod(source, resolvedCall)
			local effect, resolution = CallResolverModule.resolveRobloxApiEffect(source, doc, resolvedCall, helper, state)
			if effect and resolution == "exact" and effect.returnPolicy == "derived" then
				local result = FlowDomainModule.FlowDomain.emptyFact()
				local receiverFact = ValueFacts.evaluateExpression(qualifiedCall.rootPath, state)
				result.sources = SetModule.unionSets(result.sources, receiverFact.sources)
				for _, argument in ipairs(TextModule.splitTopLevelArgs(qualifiedCall.argsText)) do
					local argumentFact = ValueFacts.evaluateExpression(argument, state)
					result.sources = SetModule.unionSets(result.sources, argumentFact.sources)
				end
				return result
			end
		end
	end

	for _, directCall in ipairs(CallResolverModule.extractIdentifierCalls(code)) do
		if directCall.startIndex == 1 and directCall.closeIndex == #code then
			local callable = CallResolverModule.resolveDirectCallable(source, doc, directCall.name, state)
			local effect = callable and callable.effect
			if callable.kind == "roblox-method" and effect and effect.returnPolicy == "derived" then
				local result = FlowDomainModule.FlowDomain.emptyFact()
				for _, argument in ipairs(TextModule.splitTopLevelArgs(directCall.argsText)) do
					local argumentFact = ValueFacts.evaluateExpression(argument, state)
					result.sources = SetModule.unionSets(result.sources, argumentFact.sources)
				end
				return result
			end
		end
	end

	return nil
end

function ValueFacts.evaluateValueExpression(expression, state, doc)
	local result = ValueFacts.evaluateExpression(expression, state)
	local queryFact = ValueFacts.evaluateRobloxQueryReturn(expression, state, doc)
	if queryFact then
		result.sources = SetModule.unionSets(result.sources, queryFact.sources)
		result.guarantees = {}
	end
	return result
end

function ValueFacts.bindingForExpression(doc, state, expression)
	local normalized = ConfigModule.trim(expression or ""):gsub(":", ".")
	if not normalized:match("^[%a_][%w_%.]*$") then
		return nil
	end
	local target = CallResolverModule.canonicalizeSymbolName(doc, normalized, state)
	local root = target:match("^([%w_]+)")
	if root and doc and doc.aliasTargets and doc.aliasTargets[root] then
		return {
			kind = target == root and "module" or "module-method",
			target = target,
		}
	end
	local callable = CallResolverModule.resolveDirectCallable(doc and (doc.analysisSource or doc.source) or "", doc, target, state)
	if callable.kind == "roblox-method" then
		return {
			kind = "roblox-method",
			target = callable.resolvedName,
		}
	end
	return {
		kind = "symbol",
		target = target,
	}
end

function ValueFacts.invalidateDescendantGuarantees(pathGuarantees, assignedName)
	local descendants = pathGuarantees and pathGuarantees.descendants
	if not descendants or not assignedName then
		return
	end
	local normalized = tostring(assignedName):gsub("%s+", "")
	for subject, ancestors in pairs(descendants) do
		if subject == normalized or subject:find("^" .. TextModule.escapePattern(normalized) .. "%.") then
			descendants[subject] = nil
		else
			for ancestor in pairs(ancestors) do
				if ancestor == normalized or ancestor:find("^" .. TextModule.escapePattern(normalized) .. "%.") then
					ancestors[ancestor] = nil
				end
			end
			if next(ancestors) == nil then
				descendants[subject] = nil
			end
		end
	end
	if next(descendants) == nil then
		pathGuarantees.descendants = nil
	end
end

function ValueFacts.findTaintedFactInText(text, state)
	local code = TextModule.stripStringsForAnalysis(text or "")
	for variableName, fact in pairs(state.variables or {}) do
		if ValueFacts.hasSources(fact) then
			local pattern = "%f[%w_]" .. TextModule.escapePattern(variableName) .. "%f[^%w_]"
			if code:find(pattern) then
				return variableName, fact
			end
		end
	end
	return nil, nil
end

return ValueFacts
