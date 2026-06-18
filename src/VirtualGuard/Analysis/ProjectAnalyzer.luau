local CallResolverModule = require(script.Parent.Resolution.CallResolver)
local ConfigModule = require(script.Parent.Parent.Config)
local ReportingModule = require(script.Parent.Parent.Reporting)
local TextModule = require(script.Parent.Parent.Shared.Text)

local Analyzer = {}

local function readSource(instance)
	if ConfigModule.ScriptEditorService then
		local okEditor, editorSource = pcall(function()
			return ConfigModule.ScriptEditorService:GetEditorSource(instance)
		end)

		if okEditor and typeof(editorSource) == "string" then
			return editorSource, "editor"
		end
	end

	local okSource, source = pcall(function()
		return instance.Source
	end)

	if okSource and typeof(source) == "string" then
		return source, "source"
	end

	return nil, "unreadable"
end

function Analyzer.readDocuments()
	local documents = {}
	local modulesByInstance = {}
	local allInstances = game:GetDescendants()

	for index, instance in ipairs(allInstances) do
		if index % 80 == 0 then
			task.wait()
		end
		if TextModule.isScriptLike(instance) then
			local source, sourceMode = readSource(instance)
			if typeof(source) == "string" then
				local analysisSource = TextModule.stripComments(source)
				local serviceAliases = TextModule.extractServiceAliases(analysisSource)
				local pathAliases = TextModule.extractPathAliases(analysisSource, instance, serviceAliases)
				local symbolAliases, ambiguousSymbolAliases =
					TextModule.extractSymbolAliases(analysisSource, serviceAliases, pathAliases)
				local doc = {
					instance = instance,
					source = source,
					analysisSource = analysisSource,
					sourceMode = sourceMode,
					path = TextModule.getPath(instance),
					className = instance.ClassName,
					serviceAliases = serviceAliases,
					pathAliases = pathAliases,
					symbolAliases = symbolAliases,
					ambiguousSymbolAliases = ambiguousSymbolAliases,
					returnNames = instance:IsA("ModuleScript") and CallResolverModule.inferModuleReturnNames(analysisSource) or {},
					requireEdges = {},
					aliasTargets = {},
				}

				table.insert(documents, doc)

				if instance:IsA("ModuleScript") then
					modulesByInstance[instance] = doc
				end
			end
		end
	end

	table.sort(documents, function(a, b)
		return a.path < b.path
	end)

	return documents, modulesByInstance
end

local function resolveScanMode(requestedMode, documents)
	if requestedMode == "Fast" or requestedMode == "Deep" then
		return requestedMode
	end

	local sourceCharacters = 0
	for _, doc in ipairs(documents or {}) do
		sourceCharacters += #(doc.analysisSource or doc.source or "")
	end

	if #(documents or {}) <= 180 and sourceCharacters <= 900000 then
		return "Deep"
	end
	return "Fast"
end

function Analyzer.createContext(requestedMode)
	local documents, modulesByInstance = Analyzer.readDocuments()
	local longLivedPaths = ConfigModule.loadLongLivedMap()
	local falsePositiveIssues = ConfigModule.loadFalsePositiveMap()
	local trustedValidators = ConfigModule.loadTrustedValidators()
	if requestedMode ~= "Fast" and requestedMode ~= "Deep" then
		requestedMode = "Automatic"
	end
	local effectiveMode = resolveScanMode(requestedMode, documents)

	for _, doc in ipairs(documents) do
		doc.longLived = longLivedPaths[ConfigModule.normalizePathKey(doc.path)] == true
	end

	return {
		documents = documents,
		modulesByInstance = modulesByInstance,
		longLivedPaths = longLivedPaths,
		falsePositiveIssues = falsePositiveIssues,
		trustedValidators = trustedValidators,
		requestedScanMode = requestedMode,
		effectiveScanMode = effectiveMode,
		scanBudgets = ConfigModule.SCAN_MODE_BUDGETS[effectiveMode],
		startedAt = os.clock(),
		lastYieldAt = os.clock(),
		flowAnalysisCount = 0,
		cfgElapsed = 0,
		cfgDeadline = nil,
		cfgBudgetExceeded = false,
		cfgTimeBudgetExceeded = false,
		cfgRootBudgetExceeded = 0,
		cfgSummaryCacheHits = 0,
		flowSummaryCache = {},
		flowSummaryCacheCount = 0,
		cfgRootHandlers = 0,
		cfgCompleteHandlers = 0,
		cfgFallbackHandlers = 0,
		cfgIncompleteCallees = 0,
		cfgIncompleteReasons = {},
		issues = {},
		issueId = 0,
		incomingRequires = {},
		graph = {},
		integrations = {},
		integrationSet = {},
		projectSignals = {},
	}
end

function Analyzer.addIssue(context, doc, fields)
	context.issueId += 1

	fields.id = context.issueId
	fields.category = fields.category or "Security"
	fields.severity = fields.severity or "Medium"
	fields.confidence = fields.confidence or "Medium"
	fields.sourcePath = fields.sourcePath or (doc and doc.path) or "Project"
	fields.line = fields.line
	fields.flow = fields.flow or {}
	fields.reason = fields.reason or ""
	if not fields.snippetHash then
		if doc and fields.line then
			fields.snippetHash = TextModule.stableHash(TextModule.getLineWindow(doc.analysisSource or doc.source or "", fields.line, 3))
		else
			fields.snippetHash = TextModule.stableHash((fields.evidence or fields.reason or fields.title or "") .. "|" .. (fields.sourcePath or ""))
		end
	end
	fields = ReportingModule.decorateIssue(context, doc, fields)

	table.insert(context.issues, fields)
end

function Analyzer.addIntegration(context, text)
	if context.integrationSet[text] then
		return
	end

	context.integrationSet[text] = true
	table.insert(context.integrations, text)
end

function Analyzer.collectProjectSignals(context)
	local allSource = {}
	local virtualNetRateLimitDetected = false

	for index, doc in ipairs(context.documents) do
		if index % 25 == 0 then
			TextModule.maybeYield(context)
		end
		local source = doc.analysisSource or doc.source
		table.insert(allSource, source)

		if TextModule.hasVirtualNetEvidence(doc.path .. "\n" .. source) and TextModule.hasRateLimitEvidence(source) then
			virtualNetRateLimitDetected = true
		end
	end

	local sourceBlob = table.concat(allSource, "\n")
	local lowerBlob = sourceBlob:lower()
	local virtualNetDetected = TextModule.hasVirtualNetEvidence(sourceBlob)
	local rateLimitDetected = TextModule.hasRateLimitEvidence(sourceBlob)

	if virtualNetDetected and TextModule.hasAnyPlain(sourceBlob, {
		"virtualnetratelimit",
		"virtualnet rate limit",
		"vnetratelimit",
		"vnet rate limit",
	}) then
		virtualNetRateLimitDetected = true
	end

	context.projectSignals = {
		sourceBlob = lowerBlob,
		projectRateLimitDetected = rateLimitDetected,
		virtualNetDetected = virtualNetDetected,
		virtualNetRateLimitDetected = virtualNetDetected and virtualNetRateLimitDetected,
		longLivedCount = TextModule.countMap(context.longLivedPaths),
		remoteEventHandlers = TextModule.countPattern(sourceBlob, "OnServerEvent%s*:%s*Connect"),
		remoteFunctionHandlers = TextModule.countPattern(sourceBlob, "OnServerInvoke%s*="),
		dataStoreCalls = TextModule.countPattern(sourceBlob, "GetAsync%s*%(")
			+ TextModule.countPattern(sourceBlob, "SetAsync%s*%(")
			+ TextModule.countPattern(sourceBlob, "UpdateAsync%s*%(")
			+ TextModule.countPattern(sourceBlob, "RemoveAsync%s*%(")
			+ TextModule.countPattern(sourceBlob, "IncrementAsync%s*%("),
		signalConnections = TextModule.countPattern(sourceBlob, ":Connect%s*%("),
		frameConnections = TextModule.countPattern(sourceBlob, "RenderStepped%s*:%s*Connect")
			+ TextModule.countPattern(sourceBlob, "Heartbeat%s*:%s*Connect")
			+ TextModule.countPattern(sourceBlob, "Stepped%s*:%s*Connect"),
		requireCalls = TextModule.countPattern(sourceBlob, "require%s*%("),
		validationDetected = TextModule.hasAnyPlain(sourceBlob, {
			"validate",
			"validation",
			"schema",
			"typeof",
			"math.clamp",
			"assert(",
		}),
		cleanupFrameworkDetected = TextModule.hasAnyPlain(sourceBlob, {
			"garbageman",
			"janitor",
			"trove",
			"maid",
		}),
		trustedValidatorCount = TextModule.countMap(context.trustedValidators),
	}

	if lowerBlob:find("virtualstore", 1, true) then
		Analyzer.addIntegration(context, "VirtualStore detected")
	end

	if virtualNetDetected then
		if context.projectSignals.virtualNetRateLimitDetected then
			Analyzer.addIntegration(context, "VirtualNet detected with rate-limit markers")
		else
			Analyzer.addIntegration(context, "VirtualNet detected")
		end
	end

	if lowerBlob:find("garbageman", 1, true) then
		Analyzer.addIntegration(context, "GarbageMan cleanup markers detected")
	end

	if TextModule.countMap(context.longLivedPaths) > 0 then
		Analyzer.addIntegration(context, tostring(TextModule.countMap(context.longLivedPaths)) .. " long-lived source override(s)")
	end
end

function Analyzer.scanRequires(context)
	for index, doc in ipairs(context.documents) do
		if index % 20 == 0 then
			TextModule.maybeYield(context)
		end
		local source = doc.analysisSource or doc.source
		local requireCalls = TextModule.extractFunctionCalls(source, "require")

		for _, call in ipairs(requireCalls) do
			local alias = TextModule.findAliasBeforeRequire(source, call.startIndex)
			local target, state = TextModule.resolveRequire(doc, call.expression)

			if alias and target and target:IsA("ModuleScript") then
				doc.aliasTargets[alias] = target
			end

			if target and target:IsA("ModuleScript") then
				table.insert(doc.requireEdges, target)
				context.graph[doc.instance] = context.graph[doc.instance] or {}
				table.insert(context.graph[doc.instance], target)

				context.incomingRequires[target] = context.incomingRequires[target] or {}
				table.insert(context.incomingRequires[target], doc.instance)

				if doc.instance:IsA("LocalScript") and TextModule.isServerOnly(target) then
					Analyzer.addIssue(context, doc, {
						category = "Modules",
						severity = "Critical",
						title = "Client script requires a server-only module",
						line = call.line,
						problem = "A LocalScript appears to require a ModuleScript stored in ServerScriptService or ServerStorage.",
						suggestion = "Move shared client-safe modules to ReplicatedStorage and keep server-only code behind RemoteEvents/RemoteFunctions.",
						confidence = "High",
						reason = "Require target resolved to " .. TextModule.getPath(target),
						flow = { doc.path, TextModule.getPath(target) },
					})
				end
			elseif state == "dynamic" then
				Analyzer.addIssue(context, doc, {
					category = "Modules",
					severity = "Medium",
					title = "Dynamic require cannot be resolved statically",
					line = call.line,
					problem = "VirtualGuard cannot prove where this require points because the expression is dynamic.",
					suggestion = "Prefer direct require paths for core services or add a documented module registry.",
					confidence = "Medium",
					reason = "Require expression: " .. call.expression,
				})
			elseif state == "unresolved" or not target then
				Analyzer.addIssue(context, doc, {
					category = "Modules",
					severity = "Low",
					title = "Require target could not be resolved",
					line = call.line,
					problem = "A require call did not resolve to a ModuleScript during static scan.",
					suggestion = "Check the path or use script-relative/module-registry patterns that can be inspected.",
					confidence = "Medium",
					reason = "Require expression: " .. call.expression,
				})
			end
		end
	end
end

function Analyzer.scanModuleGraph(context)
	local visiting = {}
	local visited = {}
	local stack = {}
	local reportedCycles = {}

	local function stackIndexOf(instance)
		for index, item in ipairs(stack) do
			if item == instance then
				return index
			end
		end

		return nil
	end

	local function visit(instance)
		if visiting[instance] then
			local startIndex = stackIndexOf(instance)
			if startIndex then
				local cycleParts = {}
				for index = startIndex, #stack do
					table.insert(cycleParts, TextModule.getPath(stack[index]))
				end
				table.insert(cycleParts, TextModule.getPath(instance))

				local key = table.concat(cycleParts, "|")
				if not reportedCycles[key] then
					reportedCycles[key] = true
					Analyzer.addIssue(context, nil, {
						category = "Modules",
						severity = "High",
						title = "Circular require detected",
						sourcePath = TextModule.getPath(instance),
						problem = "ModuleScripts require each other in a cycle. This can create partial module state or load-order bugs.",
						suggestion = "Extract shared logic into a third module or invert one dependency through events/callbacks.",
						confidence = "High",
						reason = "Cycle found in resolved require graph.",
						flow = cycleParts,
					})
				end
			end
			return
		end

		if visited[instance] then
			return
		end

		visiting[instance] = true
		table.insert(stack, instance)

		for _, target in ipairs(context.graph[instance] or {}) do
			visit(target)
		end

		stack[#stack] = nil
		visiting[instance] = nil
		visited[instance] = true
	end

	for moduleInstance in pairs(context.modulesByInstance) do
		visit(moduleInstance)
	end

	for moduleInstance, doc in pairs(context.modulesByInstance) do
		local incoming = context.incomingRequires[moduleInstance]
		local modulePath = doc.path:lower()

		if (not incoming or #incoming == 0)
			and not modulePath:find("init", 1, true)
			and not modulePath:find("package", 1, true)
			and not TextModule.isToolingDocument(doc) then
			Analyzer.addIssue(context, doc, {
				category = "Modules",
				severity = "Low",
				title = "Unused ModuleScript candidate",
				problem = "No static require was found for this ModuleScript.",
				suggestion = "Remove dead modules or document runtime/dynamic loading if it is intentional.",
				confidence = "Low",
				reason = "No incoming require edge in the resolved module graph.",
			})
		end
	end
end

function Analyzer.scanProjectWide(context)
	local allSource = {}
	local dataStoreUsed = false
	local playerRemovingFound = false
	local bindToCloseFound = false
	local sourceBlob = ""

	if ConfigModule.ServerScriptService:FindFirstChild("_VirtualGuardPlaytestMonitor") or ConfigModule.ReplicatedStorage:FindFirstChild("VirtualGuardWatch") then
		Analyzer.addIssue(context, nil, {
			category = "Performance",
			severity = "Info",
			title = "VirtualGuard Watch monitor is installed",
			sourcePath = "ServerScriptService._VirtualGuardPlaytestMonitor / ReplicatedStorage.VirtualGuardWatch",
			problem = "The temporary Watch monitor or report container is present in the place. It is useful during testing but should not be published with the game.",
			suggestion = "Press Watch again to remove the monitor before publishing. Remove ReplicatedStorage.VirtualGuardWatch if it remains after testing.",
			confidence = "High",
			reason = "VirtualGuard Watch runtime objects were found in the DataModel.",
			evidence = "Found _VirtualGuardPlaytestMonitor or VirtualGuardWatch.",
			review = "Remove temporary VirtualGuard Watch objects before release builds.",
		})
	end

	for index, doc in ipairs(context.documents) do
		if index % 25 == 0 then
			TextModule.maybeYield(context)
		end
		local source = doc.analysisSource or doc.source
		table.insert(allSource, source)

		if TextModule.hasAnyPlain(source, { "GetAsync", "SetAsync", "UpdateAsync", "DataStoreService" }) then
			dataStoreUsed = true
		end
		if source:find("PlayerRemoving", 1, true) then
			playerRemovingFound = true
		end
		if source:find("BindToClose", 1, true) then
			bindToCloseFound = true
		end
	end

	sourceBlob = table.concat(allSource, "\n"):lower()

	if dataStoreUsed and not playerRemovingFound then
		Analyzer.addIssue(context, nil, {
			category = "Data",
			severity = "Medium",
			title = "DataStore usage without PlayerRemoving save marker",
			sourcePath = "Project",
			problem = "Player data appears to be used, but no PlayerRemoving save hook was found.",
			suggestion = "Save or release profiles on Players.PlayerRemoving.",
			confidence = "Medium",
			reason = "DataStore markers found project-wide without PlayerRemoving marker.",
		})
	end

	if dataStoreUsed and not bindToCloseFound then
		Analyzer.addIssue(context, nil, {
			category = "Data",
			severity = "Medium",
			title = "DataStore usage without BindToClose marker",
			sourcePath = "Project",
			problem = "Servers may shut down before final data writes complete.",
			suggestion = "Add game:BindToClose handling or use a profile system that handles shutdown saves.",
			confidence = "Medium",
			reason = "DataStore markers found project-wide without BindToClose marker.",
		})
	end

	if sourceBlob:find("virtualstore", 1, true) then
		Analyzer.addIntegration(context, "VirtualStore detected")
	end
	if sourceBlob:find("virtualnet", 1, true) then
		if context.projectSignals.virtualNetRateLimitDetected then
			Analyzer.addIntegration(context, "VirtualNet detected with rate-limit markers")
		else
			Analyzer.addIntegration(context, "VirtualNet detected")
		end
	end
	if sourceBlob:find("garbageman", 1, true) then
		Analyzer.addIntegration(context, "GarbageMan cleanup markers detected")
	end
end

function Analyzer.finalize(context)
	table.sort(context.issues, function(a, b)
		local aOrder = ConfigModule.SEVERITY_ORDER[a.severity] or 99
		local bOrder = ConfigModule.SEVERITY_ORDER[b.severity] or 99

		if aOrder == bOrder then
			return (a.sourcePath or "") < (b.sourcePath or "")
		end

		return aOrder < bOrder
	end)

	local counts = {
		Critical = 0,
		High = 0,
		Medium = 0,
		Low = 0,
		Info = 0,
	}

	local weights = {
		Critical = 12,
		High = 5,
		Medium = 2,
		Low = 0.35,
		Info = 0,
	}

	local confidenceWeight = {
		High = 1,
		Medium = 0.7,
		Low = 0.35,
	}
	local categoryWeights = {
		Security = 0.36,
		Data = 0.2,
		Performance = 0.16,
		Memory = 0.14,
		Modules = 0.14,
	}
	local categoryPenalty = {
		Security = 0,
		Data = 0,
		Performance = 0,
		Memory = 0,
		Modules = 0,
	}
	local categoryCaps = {
		Security = 55,
		Data = 34,
		Performance = 28,
		Memory = 24,
		Modules = 20,
	}
	local titleCaps = {
		["Security|Client-controlled data reaches sensitive module sink"] = 30,
		["Security|Client-controlled invoke data reaches sensitive module sink"] = 30,
		["Security|Client-controlled value appears to reach a sensitive operation"] = 18,
		["Security|RemoteEvent has no obvious rate limit"] = 8,
		["Security|RemoteEvent accepts high-risk client arguments"] = 10,
		["Security|RemoteFunction accepts high-risk client arguments"] = 10,
		["Modules|Unused ModuleScript candidate"] = 4,
		["Modules|Require target could not be resolved"] = 8,
		["Performance|Frequent GetDescendants usage"] = 8,
	}
	local titlePenalty = {}
	local activeIssues = {}
	local falsePositiveIssues = {}

	for _, issue in ipairs(context.issues) do
		if issue.falsePositive then
			table.insert(falsePositiveIssues, issue)
			continue
		end

		table.insert(activeIssues, issue)
		counts[issue.severity] = (counts[issue.severity] or 0) + 1
		local penalty = (weights[issue.severity] or 0) * (confidenceWeight[issue.confidence] or 0.7)
		if issue.longLived and (issue.category == "Memory" or issue.category == "Performance") then
			penalty *= 0.35
		end

		local titleKey = tostring(issue.category or "") .. "|" .. tostring(issue.title or "")
		local titleCap = titleCaps[titleKey] or 14
		local remainingTitlePenalty = math.max(0, titleCap - (titlePenalty[titleKey] or 0))
		local appliedPenalty = math.min(penalty, remainingTitlePenalty)
		titlePenalty[titleKey] = (titlePenalty[titleKey] or 0) + appliedPenalty

		if categoryPenalty[issue.category] ~= nil then
			local remainingCategoryPenalty = math.max(0, (categoryCaps[issue.category] or 25) - categoryPenalty[issue.category])
			categoryPenalty[issue.category] += math.min(appliedPenalty, remainingCategoryPenalty)
		end
	end

	local categoryScores = {}
	for category, penalty in pairs(categoryPenalty) do
		categoryScores[category] = math.floor(math.clamp(100 - penalty, 0, 100) + 0.5)
	end

	local weightedScore = 0
	local totalCategoryWeight = 0
	for category, weight in pairs(categoryWeights) do
		weightedScore += (categoryScores[category] or 100) * weight
		totalCategoryWeight += weight
	end
	local score = math.floor((weightedScore / math.max(totalCategoryWeight, 0.001)) + 0.5)

	local moduleCount = 0
	for _ in pairs(context.modulesByInstance) do
		moduleCount += 1
	end

	local result = {
		score = score,
		categoryScores = categoryScores,
		counts = counts,
		issues = context.issues,
		activeIssues = activeIssues,
		falsePositiveIssues = falsePositiveIssues,
		falsePositiveCount = #falsePositiveIssues,
		scriptCount = #context.documents,
		moduleCount = moduleCount,
		requestedScanMode = context.requestedScanMode,
		effectiveScanMode = context.effectiveScanMode,
		integrations = context.integrations,
		longLivedCount = TextModule.countMap(context.longLivedPaths),
		projectSignals = {
			projectRateLimitDetected = context.projectSignals.projectRateLimitDetected == true,
			virtualNetDetected = context.projectSignals.virtualNetDetected == true,
			virtualNetRateLimitDetected = context.projectSignals.virtualNetRateLimitDetected == true,
			validationDetected = context.projectSignals.validationDetected == true,
			trustedValidatorCount = context.projectSignals.trustedValidatorCount or 0,
			cleanupFrameworkDetected = context.projectSignals.cleanupFrameworkDetected == true,
			longLivedCount = context.projectSignals.longLivedCount or 0,
			remoteEventHandlers = context.projectSignals.remoteEventHandlers or 0,
			remoteFunctionHandlers = context.projectSignals.remoteFunctionHandlers or 0,
			dataStoreCalls = context.projectSignals.dataStoreCalls or 0,
			signalConnections = context.projectSignals.signalConnections or 0,
			frameConnections = context.projectSignals.frameConnections or 0,
			requireCalls = context.projectSignals.requireCalls or 0,
			cfgRootHandlers = context.cfgRootHandlers or 0,
			cfgCompleteHandlers = context.cfgCompleteHandlers or 0,
			cfgFallbackHandlers = context.cfgFallbackHandlers or 0,
			cfgIncompleteCallees = context.cfgIncompleteCallees or 0,
			cfgIncompleteReasons = context.cfgIncompleteReasons or {},
		},
		generatedAt = os.date("!%Y-%m-%dT%H:%M:%SZ"),
	}

	result.reportMarkdown = ReportingModule.buildReport(result)

	local exportIssues = {}
	for _, issue in ipairs(result.issues) do
		table.insert(exportIssues, {
			id = issue.id,
			key = issue.key,
			snippetHash = issue.snippetHash,
			category = issue.category,
			severity = issue.severity,
			title = issue.title,
			sourcePath = issue.sourcePath,
			line = issue.line,
			problem = issue.problem,
			suggestion = issue.suggestion,
			confidence = issue.confidence,
			reason = issue.reason,
			evidence = issue.evidence,
			impact = issue.impact,
			review = issue.review,
			lifecycle = issue.lifecycle,
			longLived = issue.longLived,
			falsePositive = issue.falsePositive,
			flow = issue.flow,
		})
	end

	result.reportJson = ConfigModule.HttpService:JSONEncode({
		score = result.score,
		counts = result.counts,
		scriptCount = result.scriptCount,
		moduleCount = result.moduleCount,
		requestedScanMode = result.requestedScanMode,
		effectiveScanMode = result.effectiveScanMode,
		integrations = result.integrations,
		longLivedCount = result.longLivedCount,
		falsePositiveCount = result.falsePositiveCount,
		projectSignals = result.projectSignals,
		issues = exportIssues,
		generatedAt = result.generatedAt,
	})

	return result
end

function Analyzer.scan(requestedMode)
	local context = Analyzer.createContext(requestedMode)

	Analyzer.collectProjectSignals(context)
	Analyzer.scanRequires(context)
	Analyzer.scanModuleGraph(context)

	for index, doc in ipairs(context.documents) do
		if index % 3 == 0 then
			TextModule.maybeYield(context)
		end
		Analyzer.scanRemoteSecurity(context, doc)
		Analyzer.scanDataStore(context, doc)
		Analyzer.scanPerformance(context, doc)
		Analyzer.scanMemory(context, doc)
		Analyzer.scanPrivacy(context, doc)
	end

	if context.cfgBudgetExceeded then
		Analyzer.addIssue(context, nil, {
			category = "Performance",
			severity = "Info",
			title = "Deep CFG scan budget reached",
			sourcePath = "VirtualGuard",
			problem = "The deep control-flow analyzer reached its per-scan budget and some remaining handlers used the faster fallback analyzer.",
			suggestion = "Review handlers marked as fallback coverage. VirtualGuard caps each root handler, total analyses, and CFG wall time to keep Studio responsive.",
			confidence = "High",
			reason = "CFG analysis budget was reached during this scan.",
			evidence = "CFG analyses used: " .. tostring(context.flowAnalysisCount or 0)
				.. "/" .. tostring(context.scanBudgets.maxAnalysesPerScan)
				.. ". Per-root limit: " .. tostring(context.scanBudgets.maxAnalysesPerRoot)
				.. ". Time limit: " .. tostring(context.scanBudgets.maxTotalTime) .. "s"
				.. ". CFG time used: " .. string.format("%.3fs", context.cfgElapsed or 0)
				.. ". Completed handlers: " .. tostring(context.cfgCompleteHandlers or 0)
				.. "/" .. tostring(context.cfgRootHandlers or 0)
				.. ". Fallback handlers: " .. tostring(context.cfgFallbackHandlers or 0)
				.. ". Incomplete callees: " .. tostring(context.cfgIncompleteCallees or 0)
				.. ". Root budgets exceeded: " .. tostring(context.cfgRootBudgetExceeded or 0)
				.. ". Summary cache hits: " .. tostring(context.cfgSummaryCacheHits or 0)
				.. ". Time budget exceeded: " .. tostring(context.cfgTimeBudgetExceeded == true),
		})
	end

	Analyzer.scanProjectWide(context)

	return Analyzer.finalize(context)
end

return {
	Analyzer = Analyzer,
	readSource = readSource,
	resolveScanMode = resolveScanMode,
}
