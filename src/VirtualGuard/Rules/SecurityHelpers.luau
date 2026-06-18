local CallResolverModule = require(script.Parent.Parent.Analysis.Resolution.CallResolver)
local SemanticsModule = require(script.Parent.Parent.Rules.Semantics)
local TextModule = require(script.Parent.Parent.Shared.Text)

local function detectSensitiveSinks(source)
	local sinks = {}
	local code = TextModule.stripStringsForAnalysis(source or "")
	local lower = code:lower()

	if SemanticsModule.hasProfileDataReference(source) or lower:find("leaderstats", 1, true)
		or lower:find("addcoins", 1, true) or lower:find("addcurrency", 1, true)
		or lower:find("grantcurrency", 1, true) or lower:find("setcoins", 1, true) then
		table.insert(sinks, "player economy/data mutation")
	end

	if lower:find("takedamage", 1, true) or lower:find("dealdamage", 1, true)
		or lower:find("%.health%s*[%+%-]?=")
		or TextModule.stripStringsPreservingBracketKeys(source or ""):lower():find("%[%s*[\"']health[\"']%s*%]%s*[%+%-]?=") then
		table.insert(sinks, "combat/health mutation")
	end

	if lower:find("setasync", 1, true) or lower:find("updateasync", 1, true)
		or lower:find("removeasync", 1, true) or lower:find("incrementasync", 1, true) then
		table.insert(sinks, "DataStore write/read")
	end

	if lower:find("teleportservice", 1, true) or lower:find(":kick%(", 1, false)
		or lower:find("ban", 1, true) then
		table.insert(sinks, "admin/teleport/player control")
	end

	return sinks
end
local function suspiciousRemoteArgs(args)
	local result = {}
	local riskyNames = {
		"amount",
		"coin",
		"coins",
		"cash",
		"money",
		"currency",
		"reward",
		"damage",
		"health",
		"target",
		"item",
		"itemid",
		"price",
		"xp",
		"exp",
		"level",
		"admin",
		"rank",
	}

	for index, arg in ipairs(args) do
		if index > 1 then
			local lower = arg:lower()
			for _, risky in ipairs(riskyNames) do
				if lower:find(risky, 1, true) then
					table.insert(result, arg)
					break
				end
			end
		end
	end

	return result
end
local function findModuleCallWithArg(doc, argName)
	local source = doc.analysisSource or doc.source
	local code = TextModule.stripStringsForAnalysis(source or "")

	for alias, target in pairs(doc.aliasTargets) do
		if CallResolverModule.extractAliasMethodCalls then
			for _, methodCall in ipairs(CallResolverModule.extractAliasMethodCalls(code, alias)) do
				if methodCall.argsText:find(argName, 1, true) then
					return alias .. ":" .. methodCall.method, target
				end
			end
		end
	end

	return nil, nil
end

return {
	detectSensitiveSinks = detectSensitiveSinks,
	findModuleCallWithArg = findModuleCallWithArg,
	suspiciousRemoteArgs = suspiciousRemoteArgs,
}
