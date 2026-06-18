local CallResolverModule = require(script.Parent.Parent.Analysis.Resolution.CallResolver)
local ModuleCallScannerModule = require(script.Parent.Parent.Analysis.Scanning.ModuleCallScanner)
local ConfigModule = require(script.Parent.Parent.Config)
local FlowDomainModule = require(script.Parent.Parent.Analysis.ControlFlow.FlowDomain)
local SemanticsModule = require(script.Parent.Parent.Rules.Semantics)
local TextModule = require(script.Parent.Parent.Shared.Text)

local function buildRemoteInitialState(doc, args, remoteKind)
	local state = FlowDomainModule.FlowDomain.newState()
	for index = 2, #(args or {}) do
		local argName = args[index]
		state.variables[argName] = {
			sources = {
				[remoteKind .. ":" .. tostring(doc.path) .. ":" .. tostring(argName)] = true,
			},
			guarantees = {},
		}
	end
	return state
end

local function findLegacySinkTaint(doc, source, statement, taints)
	local function inspectRobloxMethodValue(callable, args, evidenceLabel)
		local effect = callable and callable.effect
		if not effect or (effect.kind ~= "mutation" and effect.kind ~= "sensitive") then
			return nil
		end
		local sinkKind = effect.sinkKind or "InstanceMutation"
		if effect.receiverSensitive and args[1] then
			local hit, taintName = TextModule.containsTaint(args[1], taints)
			if hit then
				return sinkKind, taintName, evidenceLabel .. " [method receiver]"
			end
		end
		for _, index in ipairs(effect.sensitiveArguments or {}) do
			local hit, taintName = TextModule.containsTaint(args[index + 1] or "", taints)
			if hit then
				return sinkKind, taintName, evidenceLabel .. " [argument " .. tostring(index) .. "]"
			end
		end
		return nil
	end

	for _, segment in ipairs(TextModule.splitTopLevelStatements(statement or "")) do
		local code = TextModule.stripStringsForAnalysis(segment)
		local _, operator, _, assignment = SemanticsModule.parseAssignmentStatement(segment)
		if assignment and operator then
			local sinkKind = SemanticsModule.classifyAssignmentSink(assignment.rawLhs)
			if sinkKind then
				local hit, taintName = TextModule.containsTaint(assignment.rawRhs, taints)
				if hit then
					return sinkKind, taintName, ConfigModule.trim(segment)
				end
			end
			local parentReceiver = assignment.rawLhs:match("^%s*(.-)%.Parent%s*$")
				or assignment.rawLhs:match("^%s*(.-)%[%s*[\"']Parent[\"']%s*%]%s*$")
			if parentReceiver then
				local hit, taintName = TextModule.containsTaint(parentReceiver, taints)
				if hit then
					return "InstanceMutation", taintName, ConfigModule.trim(segment) .. " [receiver]"
				end
				hit, taintName = TextModule.containsTaint(assignment.rawRhs, taints)
				if hit then
					return "InstanceMutation", taintName, ConfigModule.trim(segment) .. " [new parent]"
				end
			end
		end

		for _, qualifiedCall in ipairs(CallResolverModule.extractQualifiedCalls(segment)) do
			local resolvedCall = CallResolverModule.canonicalizeCall(doc, qualifiedCall)
			local helper = CallResolverModule.resolveCustomMethod(source, resolvedCall)
			local effect = CallResolverModule.resolveRobloxApiEffect(source, doc, resolvedCall, helper)
			if effect and (effect.kind == "mutation" or effect.kind == "sensitive") then
				local sinkKind = effect.sinkKind or "InstanceMutation"
				if effect.receiverSensitive then
					local hit, taintName = TextModule.containsTaint(qualifiedCall.rootPath, taints)
					if hit then
						return sinkKind, taintName, ConfigModule.trim(segment) .. " [receiver]"
					end
				end
				local args = TextModule.splitTopLevelArgs(qualifiedCall.argsText)
				for _, index in ipairs(effect.sensitiveArguments or {}) do
					local hit, taintName = TextModule.containsTaint(args[index] or "", taints)
					if hit then
						return sinkKind, taintName, ConfigModule.trim(segment) .. " [argument " .. tostring(index) .. "]"
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
					local callable = CallResolverModule.resolveDirectCallable(source, doc, callbackName)
					if callable.kind == "roblox-method" or callable.kind == "roblox-method-hint" then
						local sinkKind, taintName, evidence =
							inspectRobloxMethodValue(callable, forwarded, ConfigModule.trim(segment))
						if sinkKind then
							return sinkKind, taintName, evidence
						end
					end
				end
			else
				local callable = CallResolverModule.resolveDirectCallable(source, doc, directCall.name)
				if callable.kind == "roblox-method" or callable.kind == "roblox-method-hint" then
					local sinkKind, taintName, evidence = inspectRobloxMethodValue(
						callable,
						TextModule.splitTopLevelArgs(directCall.argsText),
						ConfigModule.trim(segment)
					)
					if sinkKind then
						return sinkKind, taintName, evidence
					end
				end
			end
		end

		for _, callSpec in ipairs({
			{ kind = "Damage", names = { "TakeDamage", "DealDamage" } },
			{ kind = "Economy", names = { "AddCoins", "AddCurrency", "GrantCurrency", "SetCoins" } },
			{ kind = "DataStore", names = { "SetAsync", "UpdateAsync", "RemoveAsync", "IncrementAsync" } },
			{ kind = "PlayerControl", names = { "Kick", "Teleport", "TeleportAsync" } },
		}) do
			for _, callName in ipairs(callSpec.names) do
				for _, call in ipairs(TextModule.extractFunctionCalls(code, callName)) do
					if CallResolverModule.shouldApplyNameBasedSinkFallback(source, doc, code, callName, call) then
						for _, arg in ipairs(TextModule.splitTopLevelArgs(call.expression)) do
							local hit, taintName = TextModule.containsTaint(arg, taints)
							if hit then
								return callSpec.kind, taintName, ConfigModule.trim(segment)
							end
						end
					end
				end
			end
		end
	end

	return nil, nil, nil
end

local function addLegacyCapturedTaints(helper, taints, validated, mappedTaints, mappedValidated)
	local body = tostring(helper and helper.body or "")
	local parameters = {}
	for _, parameter in ipairs(helper and helper.args or {}) do
		parameters[parameter] = true
	end

	for name in pairs(taints or {}) do
		if not parameters[name] then
			if CallResolverModule.helperBodyReferencesFreeName(body, name) then
				mappedTaints[name] = true
				mappedValidated[name] = validated and validated[name] == true or false
			end
		end
	end
end

local function analyzeTaintedFlow(context, doc, source, initialTaints, depth, flow, visited, initialValidated)
	if not ConfigModule.ENABLE_LEGACY_FLOW_FALLBACK then
		return nil
	end
	if not doc or not source or #source > 8000 or depth > 2 then
		return nil
	end

	visited = visited or {}
	local visitKey = doc.path .. ":" .. table.concat(flow or {}, ">")
	if visited[visitKey] then
		return nil
	end
	visited[visitKey] = true

	local taints = TextModule.cloneBooleanMap(initialTaints)
	local validated = TextModule.cloneBooleanMap(initialValidated)
	local directTaints = {}
	local rootFieldSources = {}
	for name in pairs(initialTaints or {}) do
		if not tostring(name):find("[%.%[]") then
			directTaints[name] = true
		end
	end
	local lineStart = 1
	local resolutionSource = doc.analysisSource or doc.source or source

	local function addRootFieldSource(rootName, fieldName)
		rootFieldSources[rootName] = rootFieldSources[rootName] or {}
		rootFieldSources[rootName][fieldName] = true
		taints[rootName] = true
	end

	local function removeRootFieldSource(rootName, fieldName)
		local sources = rootFieldSources[rootName]
		if not sources then
			return
		end
		sources[fieldName] = nil
		if next(sources) == nil then
			rootFieldSources[rootName] = nil
			if not directTaints[rootName] then
				taints[rootName] = nil
				validated[rootName] = nil
			end
		end
	end

	local function analyzeLegacyHelperCall(
		helper,
		args,
		separator,
		receiverExpression,
		label,
		statementLine,
		functionAlias
	)
		local mappedTaints = {}
		local mappedValidated = {}
		local helperUsesImplicitSelf = helper.implicitSelf == true
			or (helper.implicitSelf == nil and tostring(helper.name or ""):find(":", 1, true) ~= nil)
		addLegacyCapturedTaints(helper, taints, validated, mappedTaints, mappedValidated)

		if functionAlias and helperUsesImplicitSelf then
			for index, arg in ipairs(args or {}) do
				local hit, sourceTaint = TextModule.containsTaint(arg, taints)
				if hit then
					if index == 1 then
						mappedTaints.self = true
						mappedValidated.self = sourceTaint and validated[sourceTaint] == true or false
					else
						local param = helper.args[index - 1]
						if param then
							mappedTaints[param] = true
							mappedValidated[param] = sourceTaint and validated[sourceTaint] == true or false
						end
					end
				end
			end
		else
			local paramOffset = separator == ":" and not helperUsesImplicitSelf and 1 or 0
			local ambiguousSelf = separator == "." and helperUsesImplicitSelf
			if ambiguousSelf then
				return nil
			end
			for index, arg in ipairs(args or {}) do
				local hit, sourceTaint = TextModule.containsTaint(arg, taints)
				local param = helper.args[index + paramOffset]
				if hit and param then
					mappedTaints[param] = true
					mappedValidated[param] = sourceTaint and validated[sourceTaint] == true or false
				end
			end

			local receiverHit, receiverTaint = TextModule.containsTaint(receiverExpression or "", taints)
			if receiverHit then
				if paramOffset > 0 and helper.args[1] then
					mappedTaints[helper.args[1]] = true
					mappedValidated[helper.args[1]] = receiverTaint and validated[receiverTaint] == true or false
				elseif separator == ":" then
					mappedTaints.self = true
					mappedValidated.self = receiverTaint and validated[receiverTaint] == true or false
				end
			end
		end

		if next(mappedTaints) == nil then
			return nil
		end

		local nextFlow = {}
		for _, item in ipairs(flow or {}) do
			table.insert(nextFlow, item)
		end
		table.insert(
			nextFlow,
			doc.path .. ":" .. tostring(statementLine) .. " -> local " .. tostring(helper.name or label)
		)
		return analyzeTaintedFlow(
			context,
			doc,
			helper.body,
			mappedTaints,
			depth + 1,
			nextFlow,
			visited,
			mappedValidated
		)
	end

	local function processStatement(statement, statementLine)
		local codeStatement = TextModule.stripStringsForAnalysis(statement)

		local fieldRoot, fieldName, fieldExpression = SemanticsModule.parseFieldAssignment(statement)
		if fieldRoot then
			local hit, taintName = TextModule.containsTaint(TextModule.stripStringsForAnalysis(fieldExpression), taints)
			if hit then
				taints[fieldName] = true
				if fieldName ~= fieldRoot .. ".Parent" then
					addRootFieldSource(fieldRoot, fieldName)
				end
				validated[fieldName] = validated[taintName] == true
			else
				if taints[fieldName] then
					taints[fieldName] = nil
					validated[fieldName] = nil
				end
				removeRootFieldSource(fieldRoot, fieldName)
			end
		end

		local assignedName, assignedExpression = SemanticsModule.parseSimpleAssignment(codeStatement)
		if assignedName then
			local hit, taintName = TextModule.containsTaint(assignedExpression, taints)
			rootFieldSources[assignedName] = nil
			if hit then
				taints[assignedName] = true
				directTaints[assignedName] = true
				validated[assignedName] = validated[taintName] == true
			else
				directTaints[assignedName] = nil
				if taints[assignedName] then
					taints[assignedName] = nil
					validated[assignedName] = nil
				end
			end
		end

		local sinkKind, taintName, sinkEvidence = findLegacySinkTaint(doc, resolutionSource, statement, taints)
		if sinkKind and taintName then
					return {
						line = statementLine,
						evidence = "Tainted `" .. tostring(taintName) .. "` reaches " .. tostring(sinkKind) .. " sink operand: " .. tostring(sinkEvidence),
						flow = flow,
						validated = validated[taintName] == true,
						validationTaint = nil,
					}
		end

		for _, directCall in ipairs(CallResolverModule.extractIdentifierCalls(codeStatement)) do
			if directCall.name == "pcall" or directCall.name == "xpcall" then
				local callbackArgs = TextModule.splitTopLevelArgs(directCall.argsText)
				local callbackName = ConfigModule.trim(callbackArgs[1] or ""):match("^([%a_][%w_%.:]*)$")
				if callbackName then
					local forwarded = {}
					local firstForwarded = directCall.name == "xpcall" and 3 or 2
					for index = firstForwarded, #callbackArgs do
						table.insert(forwarded, callbackArgs[index])
					end
					local helper, resolvedName, isFunctionAlias =
						CallResolverModule.resolveDirectFunctionValue(resolutionSource, doc, callbackName)
					if helper then
						local result = analyzeLegacyHelperCall(
							helper,
							forwarded,
							nil,
							nil,
							resolvedName,
							statementLine,
							isFunctionAlias
						)
						if result then
							return result
						end
					end
				end
			else
				local helper, resolvedName, isFunctionAlias =
					CallResolverModule.resolveDirectFunctionValue(resolutionSource, doc, directCall.name)
				if helper and not (doc.aliasTargets and doc.aliasTargets[resolvedName]) then
					local result = analyzeLegacyHelperCall(
						helper,
						TextModule.splitTopLevelArgs(directCall.argsText),
						nil,
						nil,
						resolvedName,
						statementLine,
						isFunctionAlias
					)
					if result then
						return result
					end
				end
			end
		end

		for _, qualifiedCall in ipairs(CallResolverModule.extractQualifiedCalls(codeStatement)) do
			local resolvedCall = CallResolverModule.canonicalizeCall(doc, qualifiedCall)
			if not (doc.aliasTargets and doc.aliasTargets[resolvedCall.root]) then
				local helper = CallResolverModule.resolveCustomMethod(resolutionSource, resolvedCall)
				if helper then
					local result = analyzeLegacyHelperCall(
						helper,
						TextModule.splitTopLevelArgs(qualifiedCall.argsText),
						qualifiedCall.separator,
						qualifiedCall.rootPath,
						resolvedCall.name,
						statementLine,
						false
					)
					if result then
						return result
					end
				end
			end
		end

		for _, call in ipairs(ModuleCallScannerModule.findTaintedModuleCallsInLine(doc, codeStatement, statementLine, taints)) do
			local targetDoc = context.modulesByInstance[call.target]
			if targetDoc then
				local targetSource = targetDoc.analysisSource or targetDoc.source
				local methodBody
				if call.direct then
					methodBody = CallResolverModule.findReturnedFunctionBody(targetSource)
				else
					methodBody = CallResolverModule.findMethodBody(targetSource, call.method, targetDoc.returnNames)
				end
				if methodBody then
					local mappedTaints = {}
					local mappedValidated = {}
					local methodUsesImplicitSelf = tostring(methodBody.name or ""):find(":", 1, true) ~= nil
					local ambiguousSelf = not call.functionAlias
						and not call.direct
						and call.separator == "."
						and methodUsesImplicitSelf
					local paramOffset = not call.functionAlias
						and not call.direct
						and call.separator == ":"
						and not methodUsesImplicitSelf
						and 1
						or 0
					for _, argIndex in ipairs(call.taintedArgIndexes) do
						if not ambiguousSelf then
							local sourceTaint = call.taintedArgNames[argIndex]
							if call.functionAlias and methodUsesImplicitSelf and argIndex == 1 then
								mappedTaints.self = true
								mappedValidated.self = sourceTaint and validated[sourceTaint] == true or false
							else
								local mappedIndex = call.functionAlias and methodUsesImplicitSelf
									and (argIndex - 1)
									or (argIndex + paramOffset)
								local param = methodBody.args[mappedIndex]
								if param then
									mappedTaints[param] = true
									mappedValidated[param] = sourceTaint and validated[sourceTaint] == true or false
								end
							end
						end
					end

					if next(mappedTaints) ~= nil then
						local nextFlow = {}
						for _, item in ipairs(flow or {}) do
							table.insert(nextFlow, item)
						end
						table.insert(nextFlow, doc.path .. ":" .. tostring(call.line) .. " -> " .. TextModule.getPath(call.target) .. ":" .. tostring(methodBody.name or call.method))

						local result = analyzeTaintedFlow(context, targetDoc, methodBody.body, mappedTaints, depth + 1, nextFlow, visited, mappedValidated)
						if result then
							return result
						end
					end
				end
			end
		end
	end

	local pendingStatement = nil
	local pendingLine = nil
	local pendingDepth = 0

	for line in (source .. "\n"):gmatch("(.-)\n") do
		local currentLineNumber = TextModule.lineNumber(source, lineStart)
		local delta = CallResolverModule.balanceDelta(line)

		if pendingStatement then
			pendingStatement ..= "\n" .. line
			pendingDepth += delta
			if not CallResolverModule.shouldContinueStatement(line, pendingDepth) then
				local result = processStatement(pendingStatement, pendingLine)
				if result then
					return result
				end
				pendingStatement = nil
				pendingLine = nil
				pendingDepth = 0
			end
		elseif CallResolverModule.shouldContinueStatement(line, delta) then
			pendingStatement = line
			pendingLine = currentLineNumber
			pendingDepth = delta
		else
			local result = processStatement(line, currentLineNumber)
			if result then
				return result
			end
		end

		lineStart += #line + 1
	end

	if pendingStatement then
		local result = processStatement(pendingStatement, pendingLine)
		if result then
			return result
		end
	end

	return nil
end

return {
	addLegacyCapturedTaints = addLegacyCapturedTaints,
	analyzeTaintedFlow = analyzeTaintedFlow,
	buildRemoteInitialState = buildRemoteInitialState,
	findLegacySinkTaint = findLegacySinkTaint,
}
