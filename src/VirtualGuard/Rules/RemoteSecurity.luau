local AnalyzerModule = require(script.Parent.Parent.Analysis.ProjectAnalyzer)
local CallResolverModule = require(script.Parent.Parent.Analysis.Resolution.CallResolver)
local ConfigModule = require(script.Parent.Parent.Config)
local FlowAnalyzerModule = require(script.Parent.Parent.Analysis.ControlFlow.FlowAnalyzer)
local LegacyFlowModule = require(script.Parent.Parent.Rules.LegacyFlow)
local SecurityHelpersModule = require(script.Parent.Parent.Rules.SecurityHelpers)
local SemanticsModule = require(script.Parent.Parent.Rules.Semantics)
local TextModule = require(script.Parent.Parent.Shared.Text)

local function shouldRunLegacyFallback(context, cfgComplete, clientTaints)
	if not ConfigModule.ENABLE_LEGACY_FLOW_FALLBACK then
		return false
	end
	if context.effectiveScanMode ~= "Deep" then
		return false
	end
	if not next(clientTaints or {}) then
		return false
	end
	if cfgComplete and not ConfigModule.COMPARE_OLD_AND_NEW_FLOW then
		return false
	end
	if (context.legacyFlowFallbacks or 0) >= (ConfigModule.LEGACY_FLOW_FALLBACK_LIMIT or 120) then
		context.legacyFlowFallbackLimitReached = true
		return false
	end
	return true
end

local function analyzeLegacyFallback(context, doc, handlerBody, clientTaints, initialFlow)
	context.legacyFlowFallbacks = (context.legacyFlowFallbacks or 0) + 1
	return LegacyFlowModule.analyzeTaintedFlow(context, doc, handlerBody, clientTaints, 0, initialFlow, nil)
end

function AnalyzerModule.Analyzer.scanRemoteSecurity(context, doc)
	local source = doc.analysisSource or doc.source
	local sinks = SecurityHelpersModule.detectSensitiveSinks(source)

	local function scanRemoteEventHandler(handler)
		local args = handler.args or {}
		local riskyArgs = SecurityHelpersModule.suspiciousRemoteArgs(args)
		local line = handler.line
		local handlerBody = handler.body and handler.body ~= "" and handler.body or TextModule.extractWindow(source, handler.index or 1, 2000)
		local hasHandlerRateLimit = TextModule.hasRateLimitEvidence(handlerBody)
		local protectedByVirtualNet = context.projectSignals.virtualNetRateLimitDetected and TextModule.isVirtualNetDocument(doc)
		local clientTaints = {}
		for index = 2, #args do
			clientTaints[args[index]] = true
		end

		local initialFlow = {
			doc.path .. ":" .. tostring(line) .. " OnServerEvent client args" .. (handler.name and (" via " .. handler.name) or ""),
		}
		if next(clientTaints) then
			context.cfgRootHandlers = (context.cfgRootHandlers or 0) + 1
		end
		local cfgResult = next(clientTaints) and FlowAnalyzerModule.FlowAnalyzer.analyzeFunction({
			context = context,
			doc = doc,
			source = handlerBody,
			params = args,
			initialState = LegacyFlowModule.buildRemoteInitialState(doc, args, "OnServerEvent"),
			initialFlow = initialFlow,
			depth = 0,
		}) or nil
		local cfgComplete = cfgResult and cfgResult.success and cfgResult.complete ~= false
		if next(clientTaints) then
			if cfgComplete then
				context.cfgCompleteHandlers = (context.cfgCompleteHandlers or 0) + 1
			else
				context.cfgFallbackHandlers = (context.cfgFallbackHandlers or 0) + 1
				if cfgResult and cfgResult.reason and #context.cfgIncompleteReasons < 8 then
					table.insert(context.cfgIncompleteReasons, "Root OnServerEvent " .. tostring(doc.path) .. ":" .. tostring(line) .. " - " .. tostring(cfgResult.reason))
				end
			end
		end
		local taintFlow = cfgResult and cfgResult.finding or nil
		local usedLegacyFlow = false
		local usedPartialCfgFlow = taintFlow ~= nil and not cfgComplete

		if shouldRunLegacyFallback(context, cfgComplete, clientTaints) then
			local legacyFlow = analyzeLegacyFallback(context, doc, handlerBody, clientTaints, initialFlow)
			if legacyFlow then
				local candidateFlows = {}
				if taintFlow then
					table.insert(candidateFlows, taintFlow)
				end
				table.insert(candidateFlows, legacyFlow)
				local chosenFlow = FlowAnalyzerModule.FlowAnalyzer.chooseWorstFinding(candidateFlows)
				if chosenFlow == legacyFlow then
					usedLegacyFlow = true
					usedPartialCfgFlow = false
				end
				taintFlow = chosenFlow
			end
		end

		if taintFlow then
			local trustLevel = taintFlow.trustLevel or (taintFlow.mitigated == true and "mitigated" or "none")
			local mitigatedFlow = trustLevel == "mitigated"
			local validatedFlow = trustLevel == "validated"
			local taintSeverity = "Critical"
			local taintConfidence = usedLegacyFlow and "Medium" or "High"
			local taintReason = "Interprocedural taint flow found from OnServerEvent arguments to a sensitive sink."

			if mitigatedFlow then
				taintSeverity = "High"
				taintConfidence = "Medium"
				taintReason = "Client-controlled flow is action-authorized and bounded, but the value is not proven server-derived, relation-aware, or within a configured safe limit."
				if hasHandlerRateLimit or protectedByVirtualNet then
					taintReason ..= " Rate-limit/framework markers were also found."
				end
			elseif validatedFlow then
				taintSeverity = "Medium"
				taintConfidence = "Medium"
				taintReason = "A branch-local relational validator constrains the mutated instance to an approved hierarchy, but ownership and action authorization may still require review."
			elseif hasHandlerRateLimit or protectedByVirtualNet then
				taintReason ..= " Rate-limit/framework markers were found, but they do not prove this client-controlled sink is authorized."
			end

			if usedLegacyFlow then
				taintReason ..= " Legacy fallback - authorization guarantees were not modeled."
			elseif usedPartialCfgFlow then
				taintReason ..= " CFG coverage was partial for this chain."
			end
			local engineLabel = usedLegacyFlow and "legacy-sequential fallback" or (usedPartialCfgFlow and "partial CFG flow" or "CFG flow")

			AnalyzerModule.Analyzer.addIssue(context, doc, {
				category = "Security",
				severity = taintSeverity,
				title = "Client-controlled data reaches sensitive module sink",
				line = line,
				problem = "A value provided by the client appears to flow through one or more ModuleScript calls into a sensitive operation.",
				suggestion = "Treat the client payload as intent only. Recompute trusted values server-side or validate schema, ownership, amount bounds, cooldown, and rate limit before calling the sink.",
				confidence = taintConfidence,
				reason = taintReason,
				evidence = taintFlow.evidence .. ". Engine: " .. engineLabel .. ". Trust: " .. tostring(trustLevel) .. ".",
				flow = taintFlow.flow,
			})
		end

		if not taintFlow and #riskyArgs > 0 and #sinks > 0 then
			local arg = riskyArgs[1]
			local callName, target = SecurityHelpersModule.findModuleCallWithArg(doc, arg)
			local targetDoc = target and context.modulesByInstance[target] or nil
			local targetSource = targetDoc and (targetDoc.analysisSource or targetDoc.source) or nil
			local targetSinks = targetSource and SecurityHelpersModule.detectSensitiveSinks(targetSource) or {}
			local flow = { doc.path, "OnServerEvent arg: " .. arg }

			if callName and target then
				table.insert(flow, callName)
				table.insert(flow, TextModule.getPath(target))
			end

			if #targetSinks > 0 then
				table.insert(flow, "sink: " .. table.concat(targetSinks, ", "))
			else
				table.insert(flow, "sink: " .. table.concat(sinks, ", "))
			end

			local validated = SemanticsModule.hasFocusedValidation(source, arg) or (targetSource and SemanticsModule.hasFocusedValidation(targetSource, arg))
			local locallyValidated = SemanticsModule.hasFocusedValidation(handlerBody, arg)
			local severity = "Critical"
			local confidence = "High"
			local reason = "No local validation marker was found near the remote flow."

			if locallyValidated and (hasHandlerRateLimit or protectedByVirtualNet) then
				severity = "High"
				confidence = "Medium"
				reason = "Local validation and rate-limit/framework markers were found, but they do not prove this sensitive flow is relation-aware or server-authoritative."
			elseif validated then
				severity = "High"
				confidence = "Medium"
				reason = "Validation-like markers were found, but not enough to prove this sensitive flow is fully server-authoritative."
			end

			AnalyzerModule.Analyzer.addIssue(context, doc, {
				category = "Security",
				severity = severity,
				title = "Client-controlled value appears to reach a sensitive operation",
				line = line,
				problem = "A RemoteEvent accepts a risky argument and the same flow reaches economy, combat, DataStore, teleport, or admin-like code.",
				suggestion = "Do not trust client-provided amounts, targets, prices, rewards, or damage. Derive those values on the server and validate ownership, distance, cooldowns, and rate limits.",
				confidence = confidence,
				reason = reason,
				evidence = "Risky client argument `" .. arg .. "` and sensitive sink marker found. Handler validation: " .. tostring(locallyValidated) .. ", rate-limit/framework: " .. tostring(hasHandlerRateLimit or protectedByVirtualNet) .. ".",
				flow = flow,
			})
		elseif #riskyArgs > 0 then
			local localValidation = SemanticsModule.hasFocusedValidation(handlerBody, riskyArgs[1])
			local localProtection = localValidation
			AnalyzerModule.Analyzer.addIssue(context, doc, {
				category = "Security",
				severity = localProtection and "Low" or "Medium",
				title = "RemoteEvent accepts high-risk client arguments",
				line = line,
				problem = "A RemoteEvent handler accepts argument names commonly used for money, damage, items, targets, or admin actions.",
				suggestion = "Validate all client arguments server-side and add rate limiting/cooldowns for this remote.",
				confidence = localProtection and "Low" or "Medium",
				reason = localProtection
					and "Risky argument names exist, but local validation markers reduce confidence."
					or "Risky arguments: " .. table.concat(riskyArgs, ", "),
				evidence = "Risky arguments: "
					.. table.concat(riskyArgs, ", ")
					.. ". Local validation marker: "
					.. tostring(localValidation)
					.. ". Rate-limit/framework marker: "
					.. tostring(hasHandlerRateLimit or protectedByVirtualNet)
					.. ".",
			})
		end

		local hasLocalRateLimit = hasHandlerRateLimit

		if not hasLocalRateLimit and not protectedByVirtualNet then
			local hasProjectRateLimit = context.projectSignals.projectRateLimitDetected

			AnalyzerModule.Analyzer.addIssue(context, doc, {
				category = "Security",
				severity = hasProjectRateLimit and "Low" or "Medium",
				title = "RemoteEvent has no obvious rate limit",
				line = line,
				problem = "The server handler may be spammed by an exploiter if no rate limit exists around the remote.",
				suggestion = "Add per-player cooldowns, request budgets, or a networking layer with rate-limit config.",
				confidence = hasProjectRateLimit and "Low" or "Medium",
				reason = hasProjectRateLimit
					and "Project-wide rate-limit markers were found, but this handler is not obviously tied to them."
					or "No RateLimit/cooldown/throttle/limiter marker found in this script.",
			})
		end
	end

	for handlerIndex, functionIndex in source:gmatch("()OnServerEvent%s*:%s*Connect%s*%(%s*()function%s*%(") do
		local handlerBody = CallResolverModule.extractLuaFunctionBody(source, functionIndex) or TextModule.extractWindow(source, functionIndex, 2000)
		scanRemoteEventHandler({
			args = TextModule.splitArgs(CallResolverModule.extractLuaFunctionArgs(source, functionIndex) or ""),
			body = handlerBody,
			index = functionIndex,
			line = TextModule.lineNumber(source, handlerIndex),
			name = "inline function",
		})
	end

	for handlerIndex, handlerName in source:gmatch("()OnServerEvent%s*:%s*Connect%s*%(%s*([%w_%.:]+)%s*%)") do
		local handler = CallResolverModule.findNamedFunctionBody(source, handlerName)
		if handler then
			scanRemoteEventHandler({
				args = handler.args,
				body = handler.body,
				index = handlerIndex,
				line = TextModule.lineNumber(source, handlerIndex),
				name = handlerName,
			})
		end
	end

	local function scanRemoteFunctionHandler(handler)
		local args = handler.args or {}
		local riskyArgs = SecurityHelpersModule.suspiciousRemoteArgs(args)
		local line = handler.line
		local handlerBody = handler.body and handler.body ~= "" and handler.body or TextModule.extractWindow(source, handler.index or 1, 1800)
		local yieldMarkers = { "GetAsync", "SetAsync", "UpdateAsync", "WaitForChild", "task.wait", "wait(", "HttpService", "TeleportService" }
		local hasHandlerRateLimit = TextModule.hasRateLimitEvidence(handlerBody)
		local protectedByVirtualNet = context.projectSignals.virtualNetRateLimitDetected and TextModule.isVirtualNetDocument(doc)
		local clientTaints = {}
		for index = 2, #args do
			clientTaints[args[index]] = true
		end

		local initialFlow = {
			doc.path .. ":" .. tostring(line) .. " OnServerInvoke client args" .. (handler.name and (" via " .. handler.name) or ""),
		}
		if next(clientTaints) then
			context.cfgRootHandlers = (context.cfgRootHandlers or 0) + 1
		end
		local cfgResult = next(clientTaints) and FlowAnalyzerModule.FlowAnalyzer.analyzeFunction({
			context = context,
			doc = doc,
			source = handlerBody,
			params = args,
			initialState = LegacyFlowModule.buildRemoteInitialState(doc, args, "OnServerInvoke"),
			initialFlow = initialFlow,
			depth = 0,
		}) or nil
		local cfgComplete = cfgResult and cfgResult.success and cfgResult.complete ~= false
		if next(clientTaints) then
			if cfgComplete then
				context.cfgCompleteHandlers = (context.cfgCompleteHandlers or 0) + 1
			else
				context.cfgFallbackHandlers = (context.cfgFallbackHandlers or 0) + 1
				if cfgResult and cfgResult.reason and #context.cfgIncompleteReasons < 8 then
					table.insert(context.cfgIncompleteReasons, "Root OnServerInvoke " .. tostring(doc.path) .. ":" .. tostring(line) .. " - " .. tostring(cfgResult.reason))
				end
			end
		end
		local taintFlow = cfgResult and cfgResult.finding or nil
		local usedLegacyFlow = false
		local usedPartialCfgFlow = taintFlow ~= nil and not cfgComplete

		if shouldRunLegacyFallback(context, cfgComplete, clientTaints) then
			local legacyFlow = analyzeLegacyFallback(context, doc, handlerBody, clientTaints, initialFlow)
			if legacyFlow then
				local candidateFlows = {}
				if taintFlow then
					table.insert(candidateFlows, taintFlow)
				end
				table.insert(candidateFlows, legacyFlow)
				local chosenFlow = FlowAnalyzerModule.FlowAnalyzer.chooseWorstFinding(candidateFlows)
				if chosenFlow == legacyFlow then
					usedLegacyFlow = true
					usedPartialCfgFlow = false
				end
				taintFlow = chosenFlow
			end
		end

		if taintFlow then
			local trustLevel = taintFlow.trustLevel or (taintFlow.mitigated == true and "mitigated" or "none")
			local mitigatedFlow = trustLevel == "mitigated"
			local validatedFlow = trustLevel == "validated"
			local taintSeverity = "Critical"
			local taintConfidence = usedLegacyFlow and "Medium" or "High"
			local taintReason = "Interprocedural taint flow found from OnServerInvoke arguments to a sensitive sink."

			if mitigatedFlow then
				taintSeverity = "High"
				taintConfidence = "Medium"
				taintReason = "Invoke flow is action-authorized and bounded, but the value is not proven server-derived, relation-aware, or within a configured safe limit."
				if hasHandlerRateLimit or protectedByVirtualNet then
					taintReason ..= " Rate-limit/framework markers were also found."
				end
			elseif validatedFlow then
				taintSeverity = "Medium"
				taintConfidence = "Medium"
				taintReason = "A branch-local relational validator constrains the mutated instance to an approved hierarchy, but ownership and action authorization may still require review."
			elseif hasHandlerRateLimit or protectedByVirtualNet then
				taintReason ..= " Rate-limit/framework markers were found, but they do not prove this client-controlled invoke sink is authorized."
			end

			if usedLegacyFlow then
				taintReason ..= " Legacy fallback - authorization guarantees were not modeled."
			elseif usedPartialCfgFlow then
				taintReason ..= " CFG coverage was partial for this chain."
			end
			local engineLabel = usedLegacyFlow and "legacy-sequential fallback" or (usedPartialCfgFlow and "partial CFG flow" or "CFG flow")

			AnalyzerModule.Analyzer.addIssue(context, doc, {
				category = "Security",
				severity = taintSeverity,
				title = "Client-controlled invoke data reaches sensitive module sink",
				line = line,
				problem = "A value provided through RemoteFunction.OnServerInvoke appears to flow through one or more ModuleScript calls into a sensitive operation.",
				suggestion = "Keep invoke payloads as client intent only. Validate schema, ownership, amount bounds, cooldown, and rate limit before the sink, or recompute trusted values server-side.",
				confidence = taintConfidence,
				reason = taintReason,
				evidence = taintFlow.evidence .. ". Engine: " .. engineLabel .. ". Trust: " .. tostring(trustLevel) .. ".",
				flow = taintFlow.flow,
			})
		end

		if TextModule.hasAnyPlain(handlerBody, yieldMarkers) then
			AnalyzerModule.Analyzer.addIssue(context, doc, {
				category = "Security",
				severity = "Medium",
				title = "RemoteFunction may yield or do expensive work",
				line = line,
				problem = "RemoteFunction.OnServerInvoke can block the caller while server code yields or performs expensive operations.",
				suggestion = "Use RemoteEvent request/response patterns or cache results before OnServerInvoke returns.",
				confidence = "Medium",
				reason = "Yielding/expensive API marker found near the OnServerInvoke handler.",
			})
		elseif TextModule.hasAnyPlain(source, yieldMarkers) then
			AnalyzerModule.Analyzer.addIssue(context, doc, {
				category = "Security",
				severity = "Low",
				title = "RemoteFunction and yielding API exist in same script",
				line = line,
				problem = "RemoteFunction.OnServerInvoke is present and the script also uses yielding/expensive APIs, but VirtualGuard did not prove they run in the handler.",
				suggestion = "Confirm OnServerInvoke returns quickly and does not directly perform DataStore, HTTP, teleport, or long waits.",
				confidence = "Low",
				reason = "Markers were found in the same script, not in the local handler window.",
			})
		end

		if not taintFlow and #riskyArgs > 0 then
			local localProtection = SemanticsModule.hasFocusedValidation(handlerBody, riskyArgs[1])
			AnalyzerModule.Analyzer.addIssue(context, doc, {
				category = "Security",
				severity = localProtection and "Low" or "Medium",
				title = "RemoteFunction accepts high-risk client arguments",
				line = line,
				problem = "A RemoteFunction handler accepts client values that may control data, economy, combat, item, or target decisions.",
				suggestion = "Keep client input as intent only. Resolve amounts, ownership, prices, and targets on the server.",
				confidence = localProtection and "Low" or "Medium",
				reason = localProtection
					and "Risky arguments exist, but validation-like markers were found in the resolved invoke handler."
					or "Risky arguments: " .. table.concat(riskyArgs, ", "),
			})
		end
	end

	for handlerIndex, functionIndex in source:gmatch("()OnServerInvoke%s*=%s*()function%s*%(") do
		scanRemoteFunctionHandler({
			args = TextModule.splitArgs(CallResolverModule.extractLuaFunctionArgs(source, functionIndex) or ""),
			body = CallResolverModule.extractLuaFunctionBody(source, functionIndex) or TextModule.extractWindow(source, functionIndex, 1800),
			index = functionIndex,
			line = TextModule.lineNumber(source, handlerIndex),
			name = "inline function",
		})
	end

	for handlerIndex, handlerName in source:gmatch("()OnServerInvoke%s*=%s*([%w_%.:]+)") do
		if handlerName ~= "function" then
			local handler = CallResolverModule.findNamedFunctionBody(source, handlerName)
			if handler then
				scanRemoteFunctionHandler({
					args = handler.args,
					body = handler.body,
					index = handlerIndex,
					line = TextModule.lineNumber(source, handlerIndex),
					name = handlerName,
				})
			end
		end
	end
end

return true
