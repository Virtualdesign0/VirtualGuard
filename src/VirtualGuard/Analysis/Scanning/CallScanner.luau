local CallResolverModule = require(script.Parent.Parent.Resolution.CallResolver)
local ConfigModule = require(script.Parent.Parent.Parent.Config)
local FlowDomainModule = require(script.Parent.Parent.ControlFlow.FlowDomain)
local TextModule = require(script.Parent.Parent.Parent.Shared.Text)

local CallScanner = {}

function CallScanner.inspectModuleCalls(FlowAnalyzer, context, doc, text, state)
	local calls = {}
	local function addModuleCall(target, alias, method, separator, args, direct, functionAlias, invokedName)
		local argFacts = {}
		local hasTaintedArg = false
		for index, arg in ipairs(args or {}) do
			local fact = FlowAnalyzer.evaluateExpression(arg, state)
			argFacts[index] = fact
			if FlowAnalyzer.hasSources(fact) then
				hasTaintedArg = true
			end
		end
		if hasTaintedArg then
			table.insert(calls, {
				target = target,
				alias = alias,
				separator = separator,
				method = method,
				direct = direct == true,
				functionAlias = functionAlias == true,
				invokedName = invokedName,
				args = args,
				argFacts = argFacts,
			})
		end
	end

	for _, qualifiedCall in ipairs(CallResolverModule.extractQualifiedCalls(text or "")) do
		local resolvedCall = CallResolverModule.canonicalizeCall(doc, qualifiedCall, state)
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

	for _, directCall in ipairs(CallResolverModule.extractIdentifierCalls(text)) do
		if directCall.name == "pcall" or directCall.name == "xpcall" then
			local callbackArgs = TextModule.splitTopLevelArgs(directCall.argsText)
			local callbackName = ConfigModule.trim(callbackArgs[1] or ""):match("^([%a_][%w_%.:]*)$")
			if callbackName then
				local forwarded = {}
				local firstForwarded = directCall.name == "xpcall" and 3 or 2
				for index = firstForwarded, #callbackArgs do
					table.insert(forwarded, callbackArgs[index])
				end
				local callable = CallResolverModule.resolveDirectCallable(doc.analysisSource or doc.source, doc, callbackName, state)
				if callable.kind == "module-method" then
					addModuleCall(
						callable.target,
						callable.root,
						callable.method,
						nil,
						forwarded,
						false,
						true,
						callbackName
					)
				else
					local resolvedName = callable.resolvedName
					local target = doc.aliasTargets and doc.aliasTargets[resolvedName]
					if target then
						addModuleCall(target, resolvedName, nil, nil, forwarded, true, false, callbackName)
					end
				end
			end
		else
			local callable = CallResolverModule.resolveDirectCallable(doc.analysisSource or doc.source, doc, directCall.name, state)
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
				local resolvedName = callable.resolvedName
				local target = doc.aliasTargets and doc.aliasTargets[resolvedName]
				if target then
					addModuleCall(
						target,
						resolvedName,
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

function CallScanner.inspectLocalFunctionCalls(FlowAnalyzer, doc, text, state, ignoredNames)
	local calls = {}
	local source = doc.analysisSource or doc.source or ""
	local safeQualifiedRoots = {
		BrickColor = true,
		CFrame = true,
		Color3 = true,
		ColorSequence = true,
		DateTime = true,
		NumberRange = true,
		NumberSequence = true,
		Random = true,
		Ray = true,
		Rect = true,
		TweenInfo = true,
		UDim = true,
		UDim2 = true,
		Vector2 = true,
		Vector3 = true,
		bit32 = true,
		buffer = true,
		coroutine = true,
		debug = true,
		math = true,
		os = true,
		string = true,
		table = true,
		task = true,
		utf8 = true,
	}
	local handledQualifiedMethods = {
		AddCoins = true,
		AddCurrency = true,
		DealDamage = true,
		GrantCurrency = true,
		IncrementAsync = true,
		Kick = true,
		RemoveAsync = true,
		SetAsync = true,
		SetCoins = true,
		TakeDamage = true,
		Teleport = true,
		TeleportAsync = true,
		UpdateAsync = true,
	}

	local function capturedFactsForHelper(helper)
		local captures = {}
		local parameters = {}
		local body = tostring(helper and helper.body or "")
		for _, parameter in ipairs(helper and helper.args or {}) do
			parameters[parameter] = true
		end
		for name, fact in pairs(state.variables or {}) do
			if not parameters[name] and FlowAnalyzer.hasSources(fact) then
				if CallResolverModule.helperBodyReferencesFreeName(body, name) then
					captures[name] = FlowDomainModule.FlowDomain.cloneFact(fact)
				end
			end
		end
		return captures
	end

	local function addCall(name, args, startIndex, helper, separator, receiverExpression, functionAlias)
		local argFacts = {}
		local hasTaintedArg = false
		for index, arg in ipairs(args) do
			local fact = FlowAnalyzer.evaluateExpression(arg, state)
			argFacts[index] = fact
			if FlowAnalyzer.hasSources(fact) then
				hasTaintedArg = true
			end
		end
		local receiverFact = receiverExpression
			and FlowAnalyzer.evaluateExpression(receiverExpression, state)
			or FlowDomainModule.FlowDomain.emptyFact()
		local hasTaintedReceiver = FlowAnalyzer.hasSources(receiverFact)
		local capturedFacts = helper and capturedFactsForHelper(helper) or {}
		if hasTaintedArg or hasTaintedReceiver or next(capturedFacts) ~= nil then
			table.insert(calls, {
				name = name,
				args = args,
				argFacts = argFacts,
				capturedFacts = capturedFacts,
				startIndex = startIndex,
				helper = helper,
				separator = separator,
				qualified = separator ~= nil,
				receiverExpression = receiverExpression,
				receiverFact = receiverFact,
				functionAlias = functionAlias == true,
				functionAliasImplicitSelf = functionAlias == true and helper and helper.implicitSelf == true or false,
			})
		end
	end

	for _, directCall in ipairs(CallResolverModule.extractIdentifierCalls(text)) do
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
				if callable.kind == "same-file-function" then
					addCall(
						callbackName,
						forwarded,
						directCall.startIndex,
						callable.helper,
						nil,
						nil,
						callable.functionAlias
					)
				elseif callable.kind == "unresolved" or callable.kind == "roblox-method-hint" then
					addCall(callbackName, forwarded, directCall.startIndex, nil, nil, nil, false)
				end
			end
			continue
		end
		if ignoredNames and ignoredNames[directCall.name] then
			continue
		end
		local callable = CallResolverModule.resolveDirectCallable(source, doc, directCall.name, state)
		if callable.kind == "module-method" or callable.kind == "roblox-method" then
			continue
		end
		if doc.aliasTargets and doc.aliasTargets[callable.resolvedName] then
			continue
		end

		addCall(
			directCall.name,
			TextModule.splitTopLevelArgs(directCall.argsText),
			directCall.startIndex,
			callable.helper,
			nil,
			nil,
			callable.functionAlias
		)
	end

	for _, qualifiedCall in ipairs(CallResolverModule.extractQualifiedCalls(text)) do
		local resolvedCall = CallResolverModule.canonicalizeCall(doc, qualifiedCall, state)
		local helper = CallResolverModule.resolveCustomMethod(source, resolvedCall)
		local _, effectResolution = CallResolverModule.resolveRobloxApiEffect(source, doc, resolvedCall, helper, state)
		local safeRoot = safeQualifiedRoots[resolvedCall.root]
			and not CallResolverModule.sourceShadowsRoot(source, resolvedCall.root)
		local moduleAlias = doc.aliasTargets and doc.aliasTargets[resolvedCall.root]
		local shouldAnalyzeCustom = helper ~= nil
		local shouldAnalyzeUnresolved = not safeRoot
			and not handledQualifiedMethods[resolvedCall.method]
			and effectResolution ~= "exact"
			and not moduleAlias
		if shouldAnalyzeCustom or shouldAnalyzeUnresolved then
			addCall(
				resolvedCall.name,
				TextModule.splitTopLevelArgs(qualifiedCall.argsText),
				qualifiedCall.startIndex,
				helper,
				qualifiedCall.separator,
				qualifiedCall.rootPath
			)
		end
	end

	return calls
end

return CallScanner
