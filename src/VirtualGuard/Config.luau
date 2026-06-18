local plugin

local function initialize(pluginObject)
	plugin = assert(pluginObject, "VirtualGuard requires a plugin object")
end

local function getPlugin()
	return assert(plugin, "VirtualGuard plugin context is not initialized")
end
local ENABLE_LEGACY_FLOW_FALLBACK = true

local HttpService = game:GetService("HttpService")
local ServerScriptService = game:GetService("ServerScriptService")
local ServerStorage = game:GetService("ServerStorage")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local scriptEditorOk, ScriptEditorService = pcall(function()
	return game:GetService("ScriptEditorService")
end)
if not scriptEditorOk then
	ScriptEditorService = nil
end

local TOOLBAR_NAME = "VirtualGuard"
local WIDGET_ID = "VirtualGuardDockWidget"
local LONG_LIVED_SETTING = "VirtualGuardLongLivedPathsV1"
local FALSE_POSITIVE_SETTING = "VirtualGuardFalsePositiveIssuesV1"
local TRUSTED_VALIDATORS_SETTING = "VirtualGuardTrustedValidatorsV1"
local SCAN_MODE_SETTING = "VirtualGuardScanModeV1"
local ENABLE_CFG_ANALYZER = true
local COMPARE_OLD_AND_NEW_FLOW = false
local LEGACY_FLOW_FALLBACK_LIMIT = 120
local SCAN_YIELD_INTERVAL = 0.015

local SCAN_MODE_BUDGETS = {
	Fast = {
		maxHandlerChars = 6000,
		maxTokens = 950,
		maxBlocks = 140,
		maxWorklistIterations = 260,
		maxAnalysesPerRoot = 8,
		maxAnalysesPerScan = 100,
		maxTotalTime = 1.5,
		maxDepth = 3,
	},
	Deep = {
		maxHandlerChars = 20000,
		maxTokens = 3500,
		maxBlocks = 450,
		maxWorklistIterations = 1800,
		maxAnalysesPerRoot = 20,
		maxAnalysesPerScan = 500,
		maxSummaryCacheEntries = 350,
		maxTotalTime = 6,
		maxDepth = 5,
	},
}

local THEME = {
	bg = Color3.fromRGB(12, 14, 15),
	panel = Color3.fromRGB(22, 24, 25),
	panel2 = Color3.fromRGB(17, 19, 20),
	panel3 = Color3.fromRGB(13, 48, 62),
	border = Color3.fromRGB(76, 79, 80),
	borderSoft = Color3.fromRGB(49, 52, 53),
	text = Color3.fromRGB(224, 224, 218),
	muted = Color3.fromRGB(164, 165, 160),
	accent = Color3.fromRGB(0, 194, 224),
	accent2 = Color3.fromRGB(55, 142, 162),
	brand = Color3.fromRGB(0, 198, 226),
	brandSoft = Color3.fromRGB(12, 73, 94),
}

local SEVERITY_COLORS = {
	Critical = Color3.fromRGB(198, 73, 68),
	High = Color3.fromRGB(203, 126, 69),
	Medium = Color3.fromRGB(202, 171, 86),
	Low = Color3.fromRGB(112, 145, 176),
	Info = Color3.fromRGB(110, 158, 117),
}

local FONT = {
	Body = Enum.Font.Code,
	Strong = Enum.Font.Code,
	Title = Enum.Font.Code,
	Code = Enum.Font.Code,
}

local SEVERITY_ORDER = {
	Critical = 1,
	High = 2,
	Medium = 3,
	Low = 4,
	Info = 5,
}

local TABS = { "All", "Security", "Performance", "Data", "Memory", "Modules", "Watch", "Ignored", "Settings", "Report" }

local DEFAULT_TRUSTED_VALIDATORS = {}

local ALLOWED_TRUSTED_VALIDATOR_GRANTS = {
	economyAuthorized = true,
	damageAuthorized = true,
	distanceChecked = true,
}

local TRUSTED_VALIDATOR_GRANT_OPTIONS = {
	{ id = "economyAuthorized", label = "Economy" },
	{ id = "damageAuthorized", label = "Damage" },
	{ id = "distanceChecked", label = "Distance" },
}

local RATE_LIMIT_MARKERS = {
	"ratelimit",
	"rate limit",
	"rate_limit",
	"rate-limit",
	"cooldown",
	"throttle",
	"limiter",
	"requestbudget",
	"request budget",
	"tokenbucket",
	"token bucket",
	"maxrequests",
	"requestsper",
	"persecond",
	"per second",
	"burst",
	"windowseconds",
}

local VIRTUALNET_MARKERS = {
	"virtualnet",
	"vnet",
}

local function trim(value)
	return (value:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function normalizePathKey(path)
	return tostring(path or "")
end

local function loadBooleanMap(settingName)
	local ok, raw = pcall(function()
		return plugin:GetSetting(settingName)
	end)

	if not ok or raw == nil then
		return {}
	end

	if typeof(raw) == "string" then
		local decodeOk, decoded = pcall(function()
			return HttpService:JSONDecode(raw)
		end)

		if decodeOk and typeof(decoded) == "table" then
			raw = decoded
		else
			return {}
		end
	end

	local map = {}
	if typeof(raw) == "table" then
		for key, value in pairs(raw) do
			if value == true then
				map[normalizePathKey(key)] = true
			elseif typeof(value) == "string" then
				map[normalizePathKey(value)] = true
			end
		end
	end

	return map
end

local function saveBooleanMap(settingName, map)
	local ok, err = pcall(function()
		plugin:SetSetting(settingName, HttpService:JSONEncode(map))
	end)

	return ok, err
end

local function loadLongLivedMap()
	return loadBooleanMap(LONG_LIVED_SETTING)
end

local function saveLongLivedMap(map)
	return saveBooleanMap(LONG_LIVED_SETTING, map)
end

local function loadFalsePositiveMap()
	return loadBooleanMap(FALSE_POSITIVE_SETTING)
end

local function saveFalsePositiveMap(map)
	return saveBooleanMap(FALSE_POSITIVE_SETTING, map)
end

local function normalizeTrustedValidatorName(name)
	return trim(tostring(name or "")):gsub(":", "."):gsub("%s+", "")
end

local function cloneTrustedValidators(source)
	local result = {}
	for callName, grants in pairs(source or {}) do
		local normalizedName = normalizeTrustedValidatorName(callName)
		if normalizedName ~= "" and typeof(grants) == "table" then
			local grantSet = {}
			for grant, value in pairs(grants) do
				if value == true and ALLOWED_TRUSTED_VALIDATOR_GRANTS[grant] then
					grantSet[grant] = true
				end
			end
			if next(grantSet) ~= nil then
				result[normalizedName] = grantSet
			end
		end
	end
	return result
end

local function loadTrustedValidators()
	local validators = cloneTrustedValidators(DEFAULT_TRUSTED_VALIDATORS)
	local ok, raw = pcall(function()
		return plugin:GetSetting(TRUSTED_VALIDATORS_SETTING)
	end)

	if not ok or raw == nil then
		return validators
	end

	if typeof(raw) == "string" then
		local decodeOk, decoded = pcall(function()
			return HttpService:JSONDecode(raw)
		end)
		if decodeOk and typeof(decoded) == "table" then
			raw = decoded
		else
			return validators
		end
	end

	if typeof(raw) == "table" then
		for callName, grants in pairs(cloneTrustedValidators(raw)) do
			validators[callName] = grants
		end
	end

	return validators
end

local function saveTrustedValidators(validators)
	local clean = cloneTrustedValidators(validators)
	local ok, err = pcall(function()
		plugin:SetSetting(TRUSTED_VALIDATORS_SETTING, HttpService:JSONEncode(clean))
	end)

	return ok, err
end

local function loadScanMode()
	local ok, value = pcall(function()
		return plugin:GetSetting(SCAN_MODE_SETTING)
	end)
	if ok and (value == "Automatic" or value == "Fast" or value == "Deep") then
		return value
	end
	return "Automatic"
end

local function saveScanMode(mode)
	if mode ~= "Automatic" and mode ~= "Fast" and mode ~= "Deep" then
		return false, "Invalid scan mode"
	end
	return pcall(function()
		plugin:SetSetting(SCAN_MODE_SETTING, mode)
	end)
end

return {
	ALLOWED_TRUSTED_VALIDATOR_GRANTS = ALLOWED_TRUSTED_VALIDATOR_GRANTS,
	cloneTrustedValidators = cloneTrustedValidators,
	COMPARE_OLD_AND_NEW_FLOW = COMPARE_OLD_AND_NEW_FLOW,
	DEFAULT_TRUSTED_VALIDATORS = DEFAULT_TRUSTED_VALIDATORS,
	ENABLE_CFG_ANALYZER = ENABLE_CFG_ANALYZER,
	ENABLE_LEGACY_FLOW_FALLBACK = ENABLE_LEGACY_FLOW_FALLBACK,
	FALSE_POSITIVE_SETTING = FALSE_POSITIVE_SETTING,
	FONT = FONT,
	getPlugin = getPlugin,
	HttpService = HttpService,
	initialize = initialize,
	loadBooleanMap = loadBooleanMap,
	loadFalsePositiveMap = loadFalsePositiveMap,
	loadLongLivedMap = loadLongLivedMap,
	loadScanMode = loadScanMode,
	loadTrustedValidators = loadTrustedValidators,
	LONG_LIVED_SETTING = LONG_LIVED_SETTING,
	LEGACY_FLOW_FALLBACK_LIMIT = LEGACY_FLOW_FALLBACK_LIMIT,
	normalizePathKey = normalizePathKey,
	normalizeTrustedValidatorName = normalizeTrustedValidatorName,
	RATE_LIMIT_MARKERS = RATE_LIMIT_MARKERS,
	ReplicatedStorage = ReplicatedStorage,
	saveBooleanMap = saveBooleanMap,
	saveFalsePositiveMap = saveFalsePositiveMap,
	saveLongLivedMap = saveLongLivedMap,
	saveScanMode = saveScanMode,
	saveTrustedValidators = saveTrustedValidators,
	SCAN_MODE_BUDGETS = SCAN_MODE_BUDGETS,
	SCAN_MODE_SETTING = SCAN_MODE_SETTING,
	SCAN_YIELD_INTERVAL = SCAN_YIELD_INTERVAL,
	ScriptEditorService = ScriptEditorService,
	ServerScriptService = ServerScriptService,
	ServerStorage = ServerStorage,
	SEVERITY_COLORS = SEVERITY_COLORS,
	SEVERITY_ORDER = SEVERITY_ORDER,
	TABS = TABS,
	THEME = THEME,
	TOOLBAR_NAME = TOOLBAR_NAME,
	trim = trim,
	TRUSTED_VALIDATOR_GRANT_OPTIONS = TRUSTED_VALIDATOR_GRANT_OPTIONS,
	TRUSTED_VALIDATORS_SETTING = TRUSTED_VALIDATORS_SETTING,
	VIRTUALNET_MARKERS = VIRTUALNET_MARKERS,
	WIDGET_ID = WIDGET_ID,
}
