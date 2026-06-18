local ConfigModule = require(script.Parent.Parent.Config)
local TextModule = require(script.Parent.Parent.Shared.Text)

local function hasProfileDataReference(text)
	local codeLower = TextModule.stripStringsForAnalysis(text or ""):lower()
	local memberLower = TextModule.stripStringsPreservingBracketKeys(text or ""):lower()
	return codeLower:find("%f[%w_]profile%s*%.%s*data%f[^%w_]") ~= nil
		or memberLower:find("%f[%w_]profile%s*%[%s*[\"']data[\"']%s*%]") ~= nil
end

local function hasHealthFieldTarget(text)
	local codeLower = TextModule.stripStringsForAnalysis(text or ""):lower()
	local memberLower = TextModule.stripStringsPreservingBracketKeys(text or ""):lower()
	return codeLower:find("%.health%s*$") ~= nil
		or memberLower:find("%[%s*[\"']health[\"']%s*%]%s*$") ~= nil
end

local function classifySensitiveSink(line)
	local code = TextModule.stripStringsForAnalysis(line or "")
	local lower = code:lower()

	if hasProfileDataReference(line)
		or lower:find("leaderstats", 1, true) ~= nil
		or lower:find("addcoins", 1, true) ~= nil
		or lower:find("addcurrency", 1, true) ~= nil
		or lower:find("grantcurrency", 1, true) ~= nil
		or lower:find("setcoins", 1, true) ~= nil
	then
		return "Economy"
	end

	if lower:find("takedamage", 1, true) ~= nil
		or lower:find("dealdamage", 1, true) ~= nil
		or lower:find("%.health%s*[%+%-]?=") ~= nil
		or TextModule.stripStringsPreservingBracketKeys(line or ""):lower():find("%[%s*[\"']health[\"']%s*%]%s*[%+%-]?=") ~= nil
	then
		return "Damage"
	end

	if lower:find("setasync", 1, true) ~= nil
		or lower:find("updateasync", 1, true) ~= nil
		or lower:find("removeasync", 1, true) ~= nil
		or lower:find("incrementasync", 1, true) ~= nil
	then
		return "DataStore"
	end

	if lower:find("teleportservice", 1, true) ~= nil
		or lower:find(":kick%(", 1, false) ~= nil
		or lower:find("ban", 1, true) ~= nil
	then
		return "PlayerControl"
	end

	return nil
end

local function lineHasSensitiveSink(line)
	return classifySensitiveSink(line) ~= nil
end

local function classifyAssignmentSink(lhs)
	if hasHealthFieldTarget(lhs) then
		return "Damage"
	end

	return classifySensitiveSink(lhs)
end

local function classifySinkTrust(fact, sinkKind, pathGuarantees, subject)
	local guarantees = fact and fact.guarantees or {}
	pathGuarantees = pathGuarantees or {}
	local normalizedSubject = ConfigModule.trim(TextModule.stripStringsForAnalysis(subject or "")):gsub("%s+", "")
	local descendantGuarantees = pathGuarantees.descendants
	local subjectDescendants = descendantGuarantees
		and normalizedSubject ~= ""
		and descendantGuarantees[normalizedSubject]

	if sinkKind == "InstanceMutation" and subjectDescendants and next(subjectDescendants) ~= nil then
		return "validated"
	end

	if sinkKind == "Economy" then
		if guarantees.number == true and guarantees.bounded == true and pathGuarantees.economyAuthorized == true then
			return "mitigated"
		end
		return "none"
	end

	if sinkKind == "Damage" then
		local actionAuthorized = pathGuarantees.damageAuthorized == true or pathGuarantees.distanceChecked == true
		if guarantees.number == true and guarantees.bounded == true and actionAuthorized then
			return "mitigated"
		end
		return "none"
	end

	return "none"
end

local function inferValidationGuaranteesForName(line, name, mode)
	local code = TextModule.stripStringsForAnalysis(line or "")
	local lower = code:lower()
	local escaped = TextModule.escapePattern(name)
	local boundary = "%f[%w_]" .. escaped .. "%f[^%w_]"
	local guarantees = {}
	local hasName = code:find(boundary) ~= nil

	if not hasName then
		return nil
	end

	if lower:find("assert", 1, true)
		and (
			code:find("assert%s*%([^%)]*typeof%s*%([^%)]*" .. boundary)
			or code:find("assert%s*%([^%)]*type%s*%([^%)]*" .. boundary)
		)
	then
		guarantees.number = true
	end

	local hasBlockingGuard = lower:find("assert", 1, true) ~= nil
		or lower:find("return", 1, true) ~= nil
		or lower:find("error", 1, true) ~= nil
		or lower:find("continue", 1, true) ~= nil
		or lower:find("break", 1, true) ~= nil

	if lower:find("if", 1, true)
		and hasBlockingGuard
		and (
			code:find("typeof%s*%([^%)]*" .. boundary)
			or code:find("type%s*%([^%)]*" .. boundary)
			or code:find(boundary .. "[^;]+==")
			or code:find(boundary .. "[^;]+~=")
			or code:find(boundary .. "[^;]+<")
			or code:find(boundary .. "[^;]+>")
		)
	then
		guarantees.number = true
	end

	if next(guarantees) == nil then
		return nil
	end

	return guarantees
end

local function validationGuaranteesForLine(line, taints, mode)
	local result = {}
	for name in pairs(taints or {}) do
		local guarantees = inferValidationGuaranteesForName(line, name, mode)
		if guarantees then
			result[name] = guarantees
		end
	end

	return result
end

local function lineValidationTaint(line, taints)
	local guaranteesByName = validationGuaranteesForLine(line, taints, "barrier")
	for name in pairs(guaranteesByName) do
		return name
	end

	return nil
end

local function hasFocusedValidation(source, argName)
	local taints = {}
	if argName and argName ~= "" then
		taints[argName] = true
	end

	for line in (source or ""):gmatch("[^\n]+") do
		if lineValidationTaint(line, taints) then
			return true
		end
	end

	return false
end

local function parseSimpleAssignment(line)
	local name, expr = line:match("^%s*local%s+([%w_]+)%s*:%s*[^=]+=%s*(.+)$")
	if name then
		return name, expr
	end

	name, expr = line:match("^%s*local%s+([%w_]+)%s*=%s*(.+)$")
	if name then
		return name, expr
	end

	name, expr = line:match("^%s*([%w_]+)%s*=%s*(.+)$")
	if name and expr and ConfigModule.trim(expr):sub(1, 1) ~= "=" then
		return name, expr
	end

	return nil, nil
end

local function parseFieldAssignment(line)
	local root, field, expr = line:match("^%s*([%w_]+)%.([%w_]+)%s*=%s*(.+)$")
	if root and field and expr then
		return root, root .. "." .. field, expr
	end

	root, field, expr = line:match('^%s*([%w_]+)%["([^"]+)"%]%s*=%s*(.+)$')
	if root and field and expr then
		return root, root .. "." .. field, expr
	end

	root, field, expr = line:match("^%s*([%w_]+)%['([^']+)'%]%s*=%s*(.+)$")
	if root and field and expr then
		return root, root .. "." .. field, expr
	end

	return nil, nil, nil
end

local function parseAssignmentStatement(line)
	local raw = line or ""
	local code = TextModule.stripStringsForAnalysis(raw)
	local depth = 0
	local index = 1

	while index <= #code do
		local char = code:sub(index, index)
		if char == "(" or char == "{" or char == "[" then
			depth += 1
		elseif char == ")" or char == "}" or char == "]" then
			depth = math.max(0, depth - 1)
		elseif char == "=" and depth == 0 then
			local previousChar = index > 1 and code:sub(index - 1, index - 1) or ""
			local nextChar = code:sub(index + 1, index + 1)
			if previousChar ~= "="
				and previousChar ~= "~"
				and previousChar ~= "<"
				and previousChar ~= ">"
				and nextChar ~= "="
			then
				local operatorStart = index
				if previousChar == "+"
					or previousChar == "-"
					or previousChar == "*"
					or previousChar == "/"
					or previousChar == "%"
				then
					operatorStart = index - 1
				end

				local analysisLhs = ConfigModule.trim(code:sub(1, operatorStart - 1))
				local operator = code:sub(operatorStart, index)
				local analysisRhs = ConfigModule.trim(code:sub(index + 1))
				local rawLhs = ConfigModule.trim(raw:sub(1, operatorStart - 1))
				local rawRhs = ConfigModule.trim(raw:sub(index + 1))
				if analysisLhs ~= "" and analysisRhs ~= "" then
					return analysisLhs, operator, analysisRhs, {
						rawLhs = rawLhs,
						analysisLhs = analysisLhs,
						operator = operator,
						rawRhs = rawRhs,
						analysisRhs = analysisRhs,
					}
				end
			end
		end

		index += 1
	end

	return nil, nil, nil
end

return {
	classifyAssignmentSink = classifyAssignmentSink,
	classifySensitiveSink = classifySensitiveSink,
	classifySinkTrust = classifySinkTrust,
	hasFocusedValidation = hasFocusedValidation,
	hasHealthFieldTarget = hasHealthFieldTarget,
	hasProfileDataReference = hasProfileDataReference,
	inferValidationGuaranteesForName = inferValidationGuaranteesForName,
	lineHasSensitiveSink = lineHasSensitiveSink,
	lineValidationTaint = lineValidationTaint,
	parseAssignmentStatement = parseAssignmentStatement,
	parseFieldAssignment = parseFieldAssignment,
	parseSimpleAssignment = parseSimpleAssignment,
	validationGuaranteesForLine = validationGuaranteesForLine,
}
