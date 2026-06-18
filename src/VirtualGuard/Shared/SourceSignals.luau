local ConfigModule = require(script.Parent.Parent.Config)

local function hasAnyPlain(source, tokens)
	local lower = tostring(source or ""):lower()

	for _, token in ipairs(tokens or {}) do
		if lower:find(tostring(token):lower(), 1, true) then
			return true
		end
	end

	return false
end

local function hasRateLimitEvidence(source)
	return hasAnyPlain(source, ConfigModule.RATE_LIMIT_MARKERS)
end

local function hasVirtualNetEvidence(source)
	return hasAnyPlain(source, ConfigModule.VIRTUALNET_MARKERS)
end

local function isVirtualNetDocument(doc)
	if not doc then
		return false
	end

	return doc.path:lower():find("vnet", 1, true) ~= nil
		or doc.path:lower():find("virtualnet", 1, true) ~= nil
		or hasVirtualNetEvidence(doc.analysisSource or doc.source)
end

local isEphemeralDocument

local function isRuntimeLikeDocument(doc)
	if not doc then
		return false
	end

	if doc.longLived then
		return true
	end

	return hasAnyPlain(doc.path, {
		"runtime",
		"transport",
		"peer",
		"service",
		"server",
		"network",
		"loader",
		"bootstrap",
		"virtualnet",
		"vnet",
	})
end

local function isToolingDocument(doc)
	if not doc then
		return false
	end

	return hasAnyPlain(doc.path, {
		"robloxlsp",
		"lsp_settings",
		"lsp.settings",
		"testservice.robox",
		"testservice.roblox",
		"selene",
		"stylua",
		"sourcemap",
	})
end

local function getLifecycleClass(doc)
	if not doc then
		return "Project"
	end

	if isToolingDocument(doc) then
		return "Tooling/config"
	end

	if doc.longLived then
		return "Marked long-lived"
	end

	if isRuntimeLikeDocument(doc) then
		return "Runtime-like"
	end

	if isEphemeralDocument(doc) then
		return "Temporary/controller-like"
	end

	return "Unclassified"
end

isEphemeralDocument = function(doc)
	if not doc then
		return false
	end

	return hasAnyPlain(doc.path, {
		"controller",
		"character",
		"tool",
		"weapon",
		"ui",
		"gui",
		"effect",
		"ability",
		"client.player",
	})
end

local function hasShutdownOrLifecycleEvidence(source)
	return hasAnyPlain(source, {
		"BindToClose",
		"PlayerRemoving",
		"Destroying",
		"AncestryChanged",
		":Disconnect",
		"Disconnect()",
		"Cleanup",
		"Destroy",
		"Trove",
		"Maid",
		"Janitor",
		"GarbageMan",
	})
end

local function extractWindow(source, startIndex, maxLength)
	return source:sub(startIndex, math.min(#source, startIndex + maxLength))
end

local function hasYieldEvidence(source)
	return hasAnyPlain(source, {
		"task.wait",
		"wait(",
		"Heartbeat:Wait",
		"Stepped:Wait",
		"RenderStepped:Wait",
		"Promise.delay",
		"Promise.retry",
	})
end

local function hasLoopExitEvidence(source)
	return source:find("%f[%w]break%f[%W]") ~= nil
		or source:find("%f[%w]return%f[%W]") ~= nil
		or source:find("%f[%w]error%f[%W]") ~= nil
end

local function forEachWhileTrue(source, callback)
	local searchIndex = 1

	while true do
		local startIndex = source:find("while%s+true%s+do", searchIndex)
		if not startIndex then
			break
		end

		local window = extractWindow(source, startIndex, 1600)
		callback(startIndex, window)
		searchIndex = startIndex + 1
	end
end

local function frameCallbackHasExpensiveScan(source)
	for _, marker in ipairs({ "RenderStepped:Connect", "Heartbeat:Connect", "Stepped:Connect" }) do
		local searchIndex = 1

		while true do
			local startIndex = source:find(marker, searchIndex, true)
			if not startIndex then
				break
			end

			local window = extractWindow(source, startIndex, 1800)
			if hasAnyPlain(window, { "GetDescendants", "GetChildren", "FindPartsInRegion", "GetPartBoundsInBox" }) then
				return true
			end

			searchIndex = startIndex + #marker
		end
	end

	return false
end

local function hasValidation(source, argName)
	local lower = source:lower()
	local arg = (argName or ""):lower()
	local markers = {
		"validate",
		"validation",
		"typeof(" .. arg,
		"type(" .. arg,
		"tonumber(" .. arg,
		"math.clamp",
		"ratelimit",
		"rate limit",
		"cooldown",
		"canbuy",
		"canhit",
		"canuse",
		"distance",
		"magnitude",
		"whitelist",
		"schema",
		"assert(",
	}

	for _, marker in ipairs(markers) do
		if marker ~= "" and lower:find(marker, 1, true) then
			return true
		end
	end

	return false
end

local function hasCleanup(source)
	return hasAnyPlain(source, {
		":Disconnect",
		"Disconnect()",
		"Maid",
		"Trove",
		"Janitor",
		"GarbageMan",
		"Cleaner",
		"Cleanup",
		"Destroying",
		"AncestryChanged",
	})
end

return {
	extractWindow = extractWindow,
	forEachWhileTrue = forEachWhileTrue,
	frameCallbackHasExpensiveScan = frameCallbackHasExpensiveScan,
	getLifecycleClass = getLifecycleClass,
	hasCleanup = hasCleanup,
	hasLoopExitEvidence = hasLoopExitEvidence,
	hasRateLimitEvidence = hasRateLimitEvidence,
	hasShutdownOrLifecycleEvidence = hasShutdownOrLifecycleEvidence,
	hasValidation = hasValidation,
	hasVirtualNetEvidence = hasVirtualNetEvidence,
	hasYieldEvidence = hasYieldEvidence,
	isEphemeralDocument = isEphemeralDocument,
	isRuntimeLikeDocument = isRuntimeLikeDocument,
	isToolingDocument = isToolingDocument,
	isVirtualNetDocument = isVirtualNetDocument,
}
