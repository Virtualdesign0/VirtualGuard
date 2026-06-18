local ConfigModule = require(script.Parent.Parent.Config)
local TextMask = require(script.Parent.TextMask)
local SourceSignals = require(script.Parent.SourceSignals)

local appendMasked = TextMask.appendMasked
local maskNonNewlineChars = TextMask.maskNonNewlineChars
local preserveNewlines = TextMask.preserveNewlines
local stripComments = TextMask.stripComments
local stripStringsForAnalysis = TextMask.stripStringsForAnalysis
local stripStringsPreservingBracketKeys = TextMask.stripStringsPreservingBracketKeys

local function countMap(map)
	local count = 0
	for _ in pairs(map or {}) do
		count += 1
	end
	return count
end

local function maybeYield(context)
	if not context then
		return
	end

	local now = os.clock()
	if (now - (context.lastYieldAt or now)) >= ConfigModule.SCAN_YIELD_INTERVAL then
		context.lastYieldAt = now
		task.wait()
	end
end

local function hasExceededCfgDeadline(context)
	if context and context.cfgDeadline and os.clock() >= context.cfgDeadline then
		context.cfgBudgetExceeded = true
		context.cfgTimeBudgetExceeded = true
		return true
	end
	return false
end

local function escapePattern(value)
	return (value:gsub("([^%w])", "%%%1"))
end

local function splitTopLevelList(argText)
	local args = {}
	local startIndex = 1
	local depth = 0
	local quote = nil
	local escaped = false
	local index = 1

	argText = argText or ""

	while index <= #argText do
		local char = argText:sub(index, index)

		if quote then
			if escaped then
				escaped = false
			elseif char == "\\" then
				escaped = true
			elseif char == quote then
				quote = nil
			end
		else
			if char == '"' or char == "'" or char == "`" then
				quote = char
			elseif char == "[" then
				local equals = argText:sub(index):match("^%[(=*)%[")
				if equals then
					local closeToken = "]" .. equals .. "]"
					local closeIndex = argText:find(closeToken, index + 2 + #equals, true)
					index = closeIndex and (closeIndex + #closeToken - 1) or #argText
				else
					depth += 1
				end
			elseif char == "(" or char == "{" then
				depth += 1
			elseif char == ")" or char == "}" or char == "]" then
				depth = math.max(0, depth - 1)
			elseif char == "," and depth == 0 then
				table.insert(args, ConfigModule.trim(argText:sub(startIndex, index - 1)))
				startIndex = index + 1
			end
		end

		index += 1
	end

	local final = ConfigModule.trim((argText or ""):sub(startIndex))
	if final ~= "" then
		table.insert(args, final)
	end

	return args
end

local function extractParameterName(parameter)
	local clean = ConfigModule.trim(parameter or "")
	clean = clean:gsub("^%.%.%.%s*", "")
	return clean:match("^([%a_][%w_]*)")
end

local function splitArgs(argText)
	local args = {}

	for _, item in ipairs(splitTopLevelList(argText)) do
		local name = extractParameterName(item)
		if name then
			table.insert(args, name)
		end
	end

	return args
end

local function splitTopLevelArgs(argText)
	local args = {}

	for _, item in ipairs(splitTopLevelList(argText)) do
		local clean = ConfigModule.trim(item)
		if clean ~= "" then
			table.insert(args, clean)
		end
	end

	return args
end

local function splitTopLevelStatements(source)
	local statements = {}
	local startIndex = 1
	local depth = 0
	local quote = nil
	local escaped = false
	local index = 1

	source = source or ""

	while index <= #source do
		local char = source:sub(index, index)

		if quote then
			if escaped then
				escaped = false
			elseif char == "\\" then
				escaped = true
			elseif char == quote then
				quote = nil
			end
		else
			if char == '"' or char == "'" or char == "`" then
				quote = char
			elseif char == "[" then
				local equals = source:sub(index):match("^%[(=*)%[")
				if equals then
					local closeToken = "]" .. equals .. "]"
					local closeIndex = source:find(closeToken, index + 2 + #equals, true)
					index = closeIndex and (closeIndex + #closeToken - 1) or #source
				else
					depth += 1
				end
			elseif char == "(" or char == "{" then
				depth += 1
			elseif char == ")" or char == "}" or char == "]" then
				depth = math.max(0, depth - 1)
			elseif char == ";" and depth == 0 then
				local statement = ConfigModule.trim(source:sub(startIndex, index - 1))
				if statement ~= "" then
					table.insert(statements, statement)
				end
				startIndex = index + 1
			end
		end

		index += 1
	end

	local final = ConfigModule.trim(source:sub(startIndex))
	if final ~= "" then
		table.insert(statements, final)
	end

	return statements
end

local function countPattern(source, pattern)
	local count = 0
	for _ in source:gmatch(pattern) do
		count += 1
	end
	return count
end

local function lineNumber(source, index)
	if not index or index <= 1 then
		return 1
	end

	local prefix = source:sub(1, index)
	local _, newlines = prefix:gsub("\n", "\n")
	return newlines + 1
end

local function getLineStartIndex(source, index)
	local lineStart = 1
	local searchIndex = 1

	while true do
		local newline = source:find("\n", searchIndex, true)
		if not newline or newline >= index then
			break
		end

		lineStart = newline + 1
		searchIndex = newline + 1
	end

	return lineStart
end

local function getPath(instance)
	local parts = {}
	local current = instance

	while current and current ~= game do
		table.insert(parts, 1, current.Name)
		current = current.Parent
	end

	return table.concat(parts, ".")
end

local function isScriptLike(instance)
	return instance:IsA("Script") or instance:IsA("LocalScript") or instance:IsA("ModuleScript")
end

local function isServerOnly(instance)
	return instance:IsDescendantOf(ConfigModule.ServerScriptService) or instance:IsDescendantOf(ConfigModule.ServerStorage)
end

local function getServiceIfExists(serviceName)
	local ok, service = pcall(function()
		return game:GetService(serviceName)
	end)

	if ok then
		return service
	end

	return nil
end

local function walkPath(root, path)
	local current = root
	local cleanPath = path or ""

	if cleanPath:sub(1, 1) == "." then
		cleanPath = cleanPath:sub(2)
	end

	if cleanPath == "" then
		return current
	end

	for token in cleanPath:gmatch("[^%.]+") do
		if token ~= "" then
			if token == "Parent" then
				current = current and current.Parent
			else
				current = current and current:FindFirstChild(token)
			end

			if not current then
				return nil
			end
		end
	end

	return current
end

local function normalizeRequireExpression(expression)
	local expr = ConfigModule.trim(expression)
	expr = expr:gsub("%s+", "")
	expr = expr:gsub(':WaitForChild%("([^"]+)"%)', ".%1")
	expr = expr:gsub(":WaitForChild%('([^']+)'%)", ".%1")
	expr = expr:gsub(':FindFirstChild%("([^"]+)"%)', ".%1")
	expr = expr:gsub(":FindFirstChild%('([^']+)'%)", ".%1")
	expr = expr:gsub('%["([^"]+)"%]', ".%1")
	expr = expr:gsub("%['([^']+)'%]", ".%1")
	return expr
end

local function extractFunctionCalls(source, name)
	local calls = {}
	local searchIndex = 1

	while true do
		local startIndex = source:find(name, searchIndex, true)
		if not startIndex then
			break
		end

		local prevChar = startIndex > 1 and source:sub(startIndex - 1, startIndex - 1) or ""
		local nextChar = source:sub(startIndex + #name, startIndex + #name)
		if prevChar:match("[%w_]") or nextChar:match("[%w_]") then
			searchIndex = startIndex + #name
		else
			local openIndex = source:find("(", startIndex + #name, true)
			if not openIndex then
				break
			end

			local quote = nil
			local escaped = false
			local depth = 0
			local closeIndex = nil
			local index = openIndex

			while index <= #source do
				local char = source:sub(index, index)

				if quote then
					if escaped then
						escaped = false
					elseif char == "\\" then
						escaped = true
					elseif char == quote then
						quote = nil
					end
				else
					if char == '"' or char == "'" then
						quote = char
					elseif char == "(" then
						depth += 1
					elseif char == ")" then
						depth -= 1
						if depth == 0 then
							closeIndex = index
							break
						end
					end
				end

				index += 1
			end

			if closeIndex then
				table.insert(calls, {
					expression = ConfigModule.trim(source:sub(openIndex + 1, closeIndex - 1)),
					startIndex = startIndex,
					openIndex = openIndex,
					closeIndex = closeIndex,
					line = lineNumber(source, startIndex),
				})
				searchIndex = closeIndex + 1
			else
				searchIndex = openIndex + 1
			end
		end
	end

	return calls
end

local function extractServiceAliases(source)
	local aliases = {}

	for name, service in source:gmatch('local%s+([%w_]+)%s*=%s*game:GetService%s*%(%s*"([^"]+)"%s*%)') do
		aliases[name] = service
	end

	for name, service in source:gmatch("local%s+([%w_]+)%s*=%s*game:GetService%s*%(%s*'([^']+)'%s*%)") do
		aliases[name] = service
	end

	return aliases
end

local function resolvePathAliasExpression(expression, baseInstance, serviceAliases, pathAliases)
	local expr = normalizeRequireExpression(expression)

	if expr:find("require", 1, true) or expr:find("function", 1, true) then
		return nil
	end

	if expr == "script" then
		return baseInstance
	end

	if expr:sub(1, 7) == "script." then
		return walkPath(baseInstance, expr:sub(8))
	end

	local _, serviceEnd, serviceName = expr:find('^game:GetService%("([^"]+)"%)')
	if not serviceName then
		_, serviceEnd, serviceName = expr:find("^game:GetService%('([^']+)'%)")
	end

	if serviceName then
		local rest = expr:sub(serviceEnd + 1)
		return serviceName .. rest
	end

	if expr:sub(1, 5) == "game." then
		return expr:sub(6)
	end

	local first, rest = expr:match("^([%w_]+)%.?(.*)$")
	if not first then
		return nil
	end

	if serviceAliases[first] then
		return serviceAliases[first] .. (rest ~= "" and ("." .. rest) or "")
	end

	if pathAliases[first] then
		local aliasTarget = pathAliases[first]
		if typeof(aliasTarget) == "Instance" then
			return rest ~= "" and walkPath(aliasTarget, rest) or aliasTarget
		end

		return aliasTarget .. (rest ~= "" and ("." .. rest) or "")
	end

	if getServiceIfExists(first) and rest ~= "" then
		return first .. "." .. rest
	end

	return nil
end

local function extractPathAliases(source, baseInstance, serviceAliases)
	local aliases = {}

	for _ = 1, 5 do
		local changed = false

		for name, expr in source:gmatch("local%s+([%w_]+)%s*=%s*([^\n]+)") do
			if not serviceAliases[name] then
				local resolved = resolvePathAliasExpression(expr, baseInstance, serviceAliases, aliases)
				if resolved and aliases[name] ~= resolved then
					aliases[name] = resolved
					changed = true
				end
			end
		end

		for name, expr in source:gmatch("\n%s*([%w_]+)%s*=%s*([^\n]+)") do
			if not serviceAliases[name] and ConfigModule.trim(expr):sub(1, 1) ~= "=" then
				local resolved = resolvePathAliasExpression(expr, baseInstance, serviceAliases, aliases)
				if resolved and aliases[name] ~= resolved then
					aliases[name] = resolved
					changed = true
				end
			end
		end

		if not changed then
			break
		end
	end

	return aliases
end

local function extractSymbolAliases(source, serviceAliases, pathAliases)
	local aliases = {}
	local assignmentCounts = {}
	local ambiguous = {}

	for name in (source or ""):gmatch("local%s+([%w_]+)%s*=") do
		assignmentCounts[name] = (assignmentCounts[name] or 0) + 1
	end
	for name in (source or ""):gmatch("\n%s*([%w_]+)%s*=") do
		assignmentCounts[name] = (assignmentCounts[name] or 0) + 1
	end
	local firstAssignedName = (source or ""):match("^%s*([%w_]+)%s*=")
	if firstAssignedName then
		assignmentCounts[firstAssignedName] = (assignmentCounts[firstAssignedName] or 0) + 1
	end
	for name, count in pairs(assignmentCounts) do
		if count > 1 then
			ambiguous[name] = true
		end
	end

	local function canRecord(name, normalized)
		if ambiguous[name]
			or (serviceAliases and serviceAliases[name])
			or (pathAliases and pathAliases[name])
		then
			return false
		end
		local first = normalized:match("^([%w_]+)")
		return normalized ~= ""
			and first ~= "game"
			and first ~= "workspace"
			and first ~= "script"
			and first ~= "require"
			and not normalized:find("function", 1, true)
	end

	for _ = 1, 5 do
		local changed = false

		for name, expr in (source or ""):gmatch("local%s+([%w_]+)%s*=%s*([%w_%.:]+)") do
			local normalized = normalizeRequireExpression(expr):gsub(":", ".")
			if canRecord(name, normalized) then
				local first, rest = normalized:match("^([%w_]+)%.?(.*)$")
				if first and aliases[first] then
					normalized = aliases[first] .. (rest ~= "" and ("." .. rest) or "")
				end
				if aliases[name] ~= normalized then
					aliases[name] = normalized
					changed = true
				end
			end
		end

		for name, expr in (source or ""):gmatch("\n%s*([%w_]+)%s*=%s*([%w_%.:]+)") do
			local normalized = normalizeRequireExpression(expr):gsub(":", ".")
			if canRecord(name, normalized) then
				local first, rest = normalized:match("^([%w_]+)%.?(.*)$")
				if first and aliases[first] then
					normalized = aliases[first] .. (rest ~= "" and ("." .. rest) or "")
				end
				if aliases[name] ~= normalized then
					aliases[name] = normalized
					changed = true
				end
			end
		end

		if not changed then
			break
		end
	end

	return aliases, ambiguous
end

local function findAliasBeforeRequire(source, index)
	local lineStart = getLineStartIndex(source, index)
	local before = source:sub(lineStart, index - 1)
	local alias = before:match("local%s+([%w_]+)%s*=%s*$")
		or before:match("^%s*([%w_]+)%s*=%s*$")

	return alias
end

local function resolveRequire(doc, expression)
	local expr = normalizeRequireExpression(expression)

	if expr:find("%.%.", 1, true) then
		return nil, "dynamic"
	end

	local _, serviceEnd, serviceName = expr:find('^game:GetService%("([^"]+)"%)')
	if not serviceName then
		_, serviceEnd, serviceName = expr:find("^game:GetService%('([^']+)'%)")
	end

	if serviceName then
		local service = getServiceIfExists(serviceName)
		return walkPath(service, expr:sub(serviceEnd + 1)), nil
	end

	if expr == "script" then
		return doc.instance, nil
	end

	if expr:sub(1, 7) == "script." then
		return walkPath(doc.instance, expr:sub(8)), nil
	end

	if expr:sub(1, 5) == "game." then
		local path = expr:sub(6)
		local first, rest = path:match("^([^%.]+)%.?(.*)$")
		if first then
			local root = getServiceIfExists(first) or game:FindFirstChild(first)
			return walkPath(root, rest), nil
		end
	end

	local first, rest = expr:match("^([%w_]+)%.?(.*)$")
	if first and doc.pathAliases and doc.pathAliases[first] then
		local aliasTarget = doc.pathAliases[first]
		if typeof(aliasTarget) == "Instance" then
			return walkPath(aliasTarget, rest), nil
		elseif typeof(aliasTarget) == "string" then
			local rootName, rootRest = aliasTarget:match("^([^%.]+)%.?(.*)$")
			if rootName then
				local root = getServiceIfExists(rootName) or game:FindFirstChild(rootName)
				local fullRest = rootRest or ""
				if rest and rest ~= "" then
					fullRest = fullRest ~= "" and (fullRest .. "." .. rest) or rest
				end
				return walkPath(root, fullRest), nil
			end
		end
	end

	if first and doc.serviceAliases[first] then
		local root = getServiceIfExists(doc.serviceAliases[first])
		return walkPath(root, rest), nil
	end

	if first then
		local service = getServiceIfExists(first)
		if service then
			return walkPath(service, rest), nil
		end
	end

	if expr:find("(", 1, true) or expr:find(":", 1, true) then
		return nil, "dynamic"
	end

	return nil, "unresolved"
end

local function hasAnyPlain(source, tokens)
	local lower = source:lower()

	for _, token in ipairs(tokens) do
		if lower:find(token:lower(), 1, true) then
			return true
		end
	end

	return false
end

local function getLineWindow(source, line, radius)
	local lines = {}
	for item in (source .. "\n"):gmatch("(.-)\n") do
		table.insert(lines, item)
	end

	local startLine = math.max(1, (line or 1) - (radius or 2))
	local endLine = math.min(#lines, (line or 1) + (radius or 2))
	local window = {}
	for lineIndex = startLine, endLine do
		table.insert(window, ConfigModule.trim(lines[lineIndex] or ""))
	end

	return table.concat(window, "\n")
end

local function stableHash(text)
	local hash = 5381
	for index = 1, #text do
		hash = (hash * 33 + string.byte(text, index)) % 2147483647
	end
	return tostring(math.floor(hash))
end

local extractWindow = SourceSignals.extractWindow
local forEachWhileTrue = SourceSignals.forEachWhileTrue
local frameCallbackHasExpensiveScan = SourceSignals.frameCallbackHasExpensiveScan
local getLifecycleClass = SourceSignals.getLifecycleClass
local hasCleanup = SourceSignals.hasCleanup
local hasLoopExitEvidence = SourceSignals.hasLoopExitEvidence
local hasRateLimitEvidence = SourceSignals.hasRateLimitEvidence
local hasShutdownOrLifecycleEvidence = SourceSignals.hasShutdownOrLifecycleEvidence
local hasValidation = SourceSignals.hasValidation
local hasVirtualNetEvidence = SourceSignals.hasVirtualNetEvidence
local hasYieldEvidence = SourceSignals.hasYieldEvidence
local isEphemeralDocument = SourceSignals.isEphemeralDocument
local isRuntimeLikeDocument = SourceSignals.isRuntimeLikeDocument
local isToolingDocument = SourceSignals.isToolingDocument
local isVirtualNetDocument = SourceSignals.isVirtualNetDocument

local function containsTaint(expression, taints)
	local code = stripStringsForAnalysis(expression or "")
	for name in pairs(taints or {}) do
		local pattern = "%f[%w_]" .. escapePattern(name) .. "%f[^%w_]"
		if code:find(pattern) then
			return true, name
		end
	end

	return false, nil
end

local function cloneBooleanMap(map)
	local result = {}
	for key, value in pairs(map or {}) do
		if value then
			result[key] = true
		end
	end
	return result
end

return {
	appendMasked = appendMasked,
	cloneBooleanMap = cloneBooleanMap,
	containsTaint = containsTaint,
	countMap = countMap,
	countPattern = countPattern,
	escapePattern = escapePattern,
	extractFunctionCalls = extractFunctionCalls,
	extractParameterName = extractParameterName,
	extractPathAliases = extractPathAliases,
	extractServiceAliases = extractServiceAliases,
	extractSymbolAliases = extractSymbolAliases,
	extractWindow = extractWindow,
	findAliasBeforeRequire = findAliasBeforeRequire,
	forEachWhileTrue = forEachWhileTrue,
	frameCallbackHasExpensiveScan = frameCallbackHasExpensiveScan,
	getLifecycleClass = getLifecycleClass,
	getLineStartIndex = getLineStartIndex,
	getLineWindow = getLineWindow,
	getPath = getPath,
	getServiceIfExists = getServiceIfExists,
	hasAnyPlain = hasAnyPlain,
	hasCleanup = hasCleanup,
	hasExceededCfgDeadline = hasExceededCfgDeadline,
	hasLoopExitEvidence = hasLoopExitEvidence,
	hasRateLimitEvidence = hasRateLimitEvidence,
	hasShutdownOrLifecycleEvidence = hasShutdownOrLifecycleEvidence,
	hasValidation = hasValidation,
	hasVirtualNetEvidence = hasVirtualNetEvidence,
	hasYieldEvidence = hasYieldEvidence,
	isEphemeralDocument = isEphemeralDocument,
	isRuntimeLikeDocument = isRuntimeLikeDocument,
	isScriptLike = isScriptLike,
	isServerOnly = isServerOnly,
	isToolingDocument = isToolingDocument,
	isVirtualNetDocument = isVirtualNetDocument,
	lineNumber = lineNumber,
	maskNonNewlineChars = maskNonNewlineChars,
	maybeYield = maybeYield,
	normalizeRequireExpression = normalizeRequireExpression,
	preserveNewlines = preserveNewlines,
	resolvePathAliasExpression = resolvePathAliasExpression,
	resolveRequire = resolveRequire,
	splitArgs = splitArgs,
	splitTopLevelArgs = splitTopLevelArgs,
	splitTopLevelList = splitTopLevelList,
	splitTopLevelStatements = splitTopLevelStatements,
	stableHash = stableHash,
	stripComments = stripComments,
	stripStringsForAnalysis = stripStringsForAnalysis,
	stripStringsPreservingBracketKeys = stripStringsPreservingBracketKeys,
	walkPath = walkPath,
}
