local AnalyzerModule = require(script.Parent.Parent.Analysis.ProjectAnalyzer)
local TextModule = require(script.Parent.Parent.Shared.Text)

local PRIVATE_PROFILE_FIELDS = {
	"AdminFlags",
	"PurchaseReceipts",
	"Receipts",
	"BanReason",
	"AntiCheatData",
	"TradeHistory",
	"Moderation",
	"Session",
	"SessionLock",
	"OperationLedger",
	"ReceiptsLedger",
}

local function expressionHasAlias(expression, aliases)
	for alias, reason in pairs(aliases) do
		local pattern = "%f[%w_]" .. TextModule.escapePattern(alias) .. "%f[^%w_]"
		if expression:find(pattern) then
			return true, reason
		end
	end

	return false, nil
end

local function expressionPrivacyEvidence(expression, aliases)
	local expr = expression or ""
	local lowerExpr = TextModule.stripStringsForAnalysis(expr):lower()
	local memberExpr = TextModule.stripStringsPreservingBracketKeys(expr):lower()

	local function containsPrivateField(text)
		for _, field in ipairs(PRIVATE_PROFILE_FIELDS) do
			if text:find(field:lower(), 1, true) then
				return field
			end
		end
		return nil
	end

	local aliasHit, aliasReason = expressionHasAlias(expr, aliases or {})
	if aliasHit then
		return true, aliasReason
	end

	local hasProfileData = lowerExpr:find("profile.data", 1, true) ~= nil
		or memberExpr:find("profile%s*%[%s*[\"']data[\"']%s*%]") ~= nil
	local fullProfileData = lowerExpr:find("profile%.data%s*$") ~= nil
		or lowerExpr:find("profile%.data[,%)%}]") ~= nil
		or memberExpr:find("profile%s*%[%s*[\"']data[\"']%s*%]%s*$") ~= nil
		or memberExpr:find("profile%s*%[%s*[\"']data[\"']%s*%][,%)%}]") ~= nil

	if fullProfileData then
		return true, "Full profile.Data appears in client payload."
	end

	if hasProfileData then
		local field = containsPrivateField(memberExpr)
		if field then
			return true, "Private profile field appears in client payload: " .. field
		end
	end

	local field = containsPrivateField(memberExpr)
	if field
		and (TextModule.hasAnyPlain(lowerExpr, { "profile.data", "data." })
			or memberExpr:find("profile%s*%[%s*[\"']data[\"']%s*%]") ~= nil)
	then
		return true, "Private-looking field appears in replicated expression: " .. field
	end

	return false, nil
end

local function buildPrivacyAliases(source)
	local aliases = {}
	local changed = true

	while changed do
		changed = false

		for name, expr in source:gmatch("local%s+([%w_]+)%s*=%s*([^\n]+)") do
			if not aliases[name] then
				local hit, reason = expressionPrivacyEvidence(expr, aliases)
				if hit then
					aliases[name] = "Alias `" .. name .. "` points at private profile data. " .. tostring(reason)
					changed = true
				end
			end
		end

		for name, expr in source:gmatch("\n%s*([%w_]+)%s*=%s*([^\n]+)") do
			if not aliases[name] and not expr:find("^=") then
				local hit, reason = expressionPrivacyEvidence(expr, aliases)
				if hit then
					aliases[name] = "Alias `" .. name .. "` points at private profile data. " .. tostring(reason)
					changed = true
				end
			end
		end
	end

	return aliases
end

function AnalyzerModule.Analyzer.scanPrivacy(context, doc)
	local source = doc.analysisSource or doc.source
	local aliases = buildPrivacyAliases(source)
	local reported = {}

	local function reportPrivacyIssue(callName, call, payload, reason)
		local key = callName .. ":" .. tostring(call.line) .. ":" .. TextModule.stableHash(payload)
		if reported[key] then
			return
		end
		reported[key] = true

		local lowerPayload = TextModule.stripStringsForAnalysis(payload):lower()
		local memberPayload = TextModule.stripStringsPreservingBracketKeys(payload):lower()
		local fullProfile = lowerPayload:find("profile%.data%s*$") ~= nil
			or lowerPayload:find("^profile%.data$") ~= nil
			or memberPayload:find("profile%s*%[%s*[\"']data[\"']%s*%]%s*$") ~= nil

		AnalyzerModule.Analyzer.addIssue(context, doc, {
			category = "Security",
			severity = fullProfile and "Critical" or "High",
			title = fullProfile and "Full profile data may be replicated to client" or "Private profile data may be replicated to client",
			line = call.line,
			problem = "A client replication call appears to send full profile data, private profile fields, or an alias/table containing private data.",
			suggestion = "Build an explicit public view model and whitelist fields. Keep receipts, moderation, anti-cheat, session, and ledger data server-only.",
			confidence = "High",
			reason = reason,
			evidence = callName .. " payload: " .. payload,
			review = "Trace the payload construction and confirm every replicated field is intentionally public.",
		})
	end

	for _, callName in ipairs({ "FireClient", "FireAllClients", "InvokeClient" }) do
		for _, call in ipairs(TextModule.extractFunctionCalls(source, callName)) do
			local args = TextModule.splitTopLevelArgs(call.expression)
			local payloadIndex = callName == "FireAllClients" and 1 or 2
			local payload = args[payloadIndex]

			if payload then
				local hit, reason = expressionPrivacyEvidence(payload, aliases)
				if hit then
					reportPrivacyIssue(callName, call, payload, reason)
				end
			end
		end
	end

	if next(aliases) ~= nil and TextModule.hasAnyPlain(source, { "FireClient", "FireAllClients", "InvokeClient" }) then
		for alias, reason in pairs(aliases) do
			if source:find(alias, 1, true) then
				AnalyzerModule.Analyzer.addIssue(context, doc, {
					category = "Security",
					severity = "Medium",
					title = "Private profile alias exists near client replication",
					problem = "A local variable aliases profile data and the script also performs client replication. This may be safe, but it deserves manual review.",
					suggestion = "Prefer names such as publicProfile/publicReplica for whitelisted payloads and avoid passing raw profile aliases to remotes.",
					confidence = "Low",
					reason = reason,
					evidence = "Alias `" .. alias .. "` and client replication markers exist in the same script.",
				})
				break
			end
		end
	end
end

return {
	buildPrivacyAliases = buildPrivacyAliases,
	expressionHasAlias = expressionHasAlias,
	expressionPrivacyEvidence = expressionPrivacyEvidence,
	PRIVATE_PROFILE_FIELDS = PRIVATE_PROFILE_FIELDS,
}
