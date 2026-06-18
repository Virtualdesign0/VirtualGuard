local function normalizeName(value)
	return tostring(value or ""):gsub("%s+", ""):gsub(":", ".")
end

local function functionNameMatches(foundName, requestedName)
	return normalizeName(foundName) == normalizeName(requestedName)
end

local function findExactQualifiedFunction(source, requestedName)
	local normalizedName = normalizeName(requestedName)
	local requestedRoot, requestedMethod = normalizedName:match("^(.*)%.([%w_]+)$")
	if not requestedRoot or not requestedMethod then
		return nil
	end

	for fullName in source:gmatch("function%s+([%w_%.:]+)%s*%(") do
		if functionNameMatches(fullName, normalizedName) then
			return fullName
		end
	end

	for fullName in source:gmatch("([%w_%.:]+)%s*=%s*function%s*%(") do
		if functionNameMatches(fullName, normalizedName) then
			return fullName
		end
	end

	for rootPath, key in source:gmatch('([%w_%.:]+)%s*%[%s*"([%w_]+)"%s*%]%s*=%s*function%s*%(') do
		if functionNameMatches(rootPath, requestedRoot) and key == requestedMethod then
			return rootPath .. "." .. key
		end
	end

	return nil
end

local function findExactDirectFunction(source, requestedName)
	for name in source:gmatch("local%s+function%s+([%w_]+)%s*%(") do
		if name == requestedName then
			return name
		end
	end
	for name in source:gmatch("function%s+([%w_]+)%s*%(") do
		if name == requestedName then
			return name
		end
	end
	for startIndex, name in source:gmatch("()([%w_]+)%s*=%s*function%s*%(") do
		local previousChar = startIndex > 1 and source:sub(startIndex - 1, startIndex - 1) or ""
		if name == requestedName and not previousChar:match("[%w_%.:]") then
			return name
		end
	end
	return nil
end

local function normalizeRobloxApiRoot(doc, rootPath)
	local first, rest = rootPath:match("^([%w_]+)%.?(.*)$")
	local normalizedFirst = first == "workspace" and "Workspace" or first
	if doc.serviceAliases[first] then
		normalizedFirst = doc.serviceAliases[first]
	elseif doc.pathAliases[first] then
		local aliasRoot, aliasRest = doc.pathAliases[first]:match("^([^%.]+)%.?(.*)$")
		normalizedFirst = aliasRoot
		rest = aliasRest ~= "" and (aliasRest .. (rest ~= "" and ("." .. rest) or "")) or rest
	end
	return normalizedFirst .. (rest ~= "" and ("." .. rest) or "")
end

local function canonicalizeRoot(doc, rootPath)
	local first, rest = rootPath:match("^([%w_]+)%.?(.*)$")
	local visited = {}
	for _ = 1, 8 do
		if doc.ambiguousSymbolAliases and doc.ambiguousSymbolAliases[first] then
			break
		end
		if (doc.serviceAliases and doc.serviceAliases[first])
			or (doc.pathAliases and doc.pathAliases[first])
			or (doc.aliasTargets and doc.aliasTargets[first])
		then
			break
		end
		if visited[first] or not (doc.symbolAliases and doc.symbolAliases[first]) then
			break
		end
		visited[first] = true
		local aliasFirst, aliasRest = doc.symbolAliases[first]:match("^([%w_]+)%.?(.*)$")
		if doc.ambiguousSymbolAliases and doc.ambiguousSymbolAliases[aliasFirst] then
			break
		end
		first = aliasFirst
		if aliasRest ~= "" then
			rest = aliasRest .. (rest ~= "" and ("." .. rest) or "")
		end
	end
	return first .. (rest ~= "" and ("." .. rest) or "")
end

local function callOpenIndex(source, name)
	local startIndex = assert(source:find(name, 1, true))
	return assert(source:find("(", startIndex + #name, true))
end

local function mapFunctionAliasArgs(args, implicitSelf)
	local mapped = {}
	for index, value in ipairs(args) do
		if implicitSelf and index == 1 then
			mapped.self = value
		else
			local parameterIndex = implicitSelf and (index - 1) or index
			mapped[parameterIndex] = value
		end
	end
	return mapped
end

local function referencesFreeNameByBlock(body, name)
	local scopes = { {} }
	local pendingLocal = nil
	local functionDepth = 0
	for line in (body .. "\n"):gmatch("(.-)\n") do
		local code = line:gsub("%-%-.*$", "")
		if code:find("%f[%w_]function%s*%(") then
			functionDepth += 1
		end
		if code:find("%f[%w_]end%f[^%w_]") then
			functionDepth = math.max(0, functionDepth - 1)
			if #scopes > 1 then
				table.remove(scopes)
			end
		end
		if code:find("%f[%w_]then%f[^%w_]") or code:find("%f[%w_]do%f[^%w_]") then
			table.insert(scopes, {})
		end
		local localName, initializer = code:match("%f[%w_]local%s+([%w_]+)%s*=%s*(.*)")
		local searchable = localName and initializer or code
		if searchable:find("%f[%w_]" .. name .. "%f[^%w_]") then
			local shadowed = false
			for index = #scopes, 1, -1 do
				shadowed = shadowed or scopes[index][name] == true
			end
			if not shadowed then
				return true
			end
		end
		if localName and functionDepth > 0 then
			pendingLocal = localName
		elseif localName then
			scopes[#scopes][localName] = true
		end
		if pendingLocal and functionDepth == 0 then
			scopes[#scopes][pendingLocal] = true
			pendingLocal = nil
		end
	end
	return false
end

local function classifyCallable(doc, resolvedName, effectMethods)
	local root, method = resolvedName:match("^(.*)%.([%w_]+)$")
	if not root then
		return "direct"
	end
	local first = root:match("^([%w_]+)")
	if doc.aliasTargets and doc.aliasTargets[first] then
		return "module-method"
	end
	if effectMethods[method] then
		return "roblox-method"
	end
	return "same-file-function"
end

local function classifyCallableResolution(hasHelper, hasModule, effectResolution)
	if hasHelper then
		return "same-file-function"
	end
	if hasModule then
		return "module-method"
	end
	if effectResolution == "exact" then
		return "roblox-method"
	end
	if effectResolution == "method" then
		return "roblox-method-hint"
	end
	return "unresolved"
end

local function returnPropagationName(call)
	return call.invokedName
		or (call.direct and call.alias or (call.alias .. tostring(call.separator or ".") .. tostring(call.method)))
end

local unrelated = [[
local Raycast = function(payload)
	return payload
end
workspace:Raycast(origin, direction)
]]
assert(findExactQualifiedFunction(unrelated, "workspace:Raycast") == nil)

assert(findExactQualifiedFunction("function Controller:Destroy(target) end", "Controller:Destroy") == "Controller:Destroy")
assert(findExactQualifiedFunction("function Controller.Destroy(target) end", "Controller:Destroy") == "Controller.Destroy")
assert(findExactQualifiedFunction("Controller.Destroy = function(target) end", "Controller:Destroy") == "Controller.Destroy")
assert(findExactQualifiedFunction('Controller["Destroy"] = function(target) end', "Controller:Destroy") == "Controller.Destroy")
assert(findExactDirectFunction("Controller.DealDamage = function(amount) end", "DealDamage") == nil)
assert(findExactDirectFunction("local function DealDamage(amount) end", "DealDamage") == "DealDamage")
assert(findExactDirectFunction("DealDamage = function(amount) end", "DealDamage") == "DealDamage")

local serviceDoc = {
	serviceAliases = { Workspace = "Workspace", World = "Workspace" },
	pathAliases = { WorkspacePath = "Workspace" },
	symbolAliases = { Workspace = "game.GetService", World = "game.GetService" },
}
assert(normalizeRobloxApiRoot(serviceDoc, "Workspace") == "Workspace")
assert(normalizeRobloxApiRoot(serviceDoc, "World") == "Workspace")
assert(normalizeRobloxApiRoot(serviceDoc, "WorkspacePath") == "Workspace")
assert(canonicalizeRoot(serviceDoc, "Workspace") == "Workspace")
assert(canonicalizeRoot(serviceDoc, "World") == "World")

local aliasDoc = {
	symbolAliases = {
		ControllerAlias = "Controller",
		SecondAlias = "ControllerAlias",
	},
}
assert(canonicalizeRoot(aliasDoc, "ControllerAlias") == "Controller")
assert(canonicalizeRoot(aliasDoc, "SecondAlias") == "Controller")

local moduleDoc = {
	symbolAliases = {
		Combat = "CombatService",
	},
	aliasTargets = {
		CombatService = "ModuleScript",
	},
}
assert(moduleDoc.aliasTargets[canonicalizeRoot(moduleDoc, "Combat")] == "ModuleScript")

local builtinDoc = {
	symbolAliases = {
		M = "math",
	},
}
assert(canonicalizeRoot(builtinDoc, "M") == "math")

local ambiguousDoc = {
	symbolAliases = {
		Service = "CombatService",
		ServiceAlias = "Service",
	},
	ambiguousSymbolAliases = {
		Service = true,
	},
}
assert(canonicalizeRoot(ambiguousDoc, "Service") == "Service")
assert(canonicalizeRoot(ambiguousDoc, "ServiceAlias") == "ServiceAlias")

local functionAliasDoc = {
	symbolAliases = {
		Apply = "Controller.Apply",
	},
}
local functionAliasTarget = canonicalizeRoot(functionAliasDoc, "Apply")
assert(functionAliasTarget == "Controller.Apply")
assert(findExactQualifiedFunction("function Controller.Apply(amount) end", functionAliasTarget) == "Controller.Apply")
local colonAliasArgs = mapFunctionAliasArgs({ "controller", "clientAmount" }, true)
assert(colonAliasArgs.self == "controller")
assert(colonAliasArgs[1] == "clientAmount")
local pcallForwarded = { "controller", "clientAmount" }
local pcallAliasArgs = mapFunctionAliasArgs(pcallForwarded, true)
assert(pcallAliasArgs.self == "controller")
assert(pcallAliasArgs[1] == "clientAmount")
assert(classifyCallable(moduleDoc, "CombatService.Apply", { Destroy = true }) == "module-method")
assert(classifyCallable({}, "target.Destroy", { Destroy = true }) == "roblox-method")
assert(classifyCallableResolution(false, false, "method") == "roblox-method-hint")
assert(classifyCallableResolution(false, false, "exact") == "roblox-method")
assert(classifyCallableResolution(true, true, "exact") == "same-file-function")
assert(classifyCallableResolution(false, true, "exact") == "module-method")
assert(returnPropagationName({
	invokedName = "GetAmount",
	alias = "DataModule",
	method = "GetAmount",
	functionAlias = true,
}) == "GetAmount")

local customDamage = "Controller:DealDamage(clientDamage)"
assert(callOpenIndex(customDamage, "DealDamage") == callOpenIndex(customDamage, "Controller:DealDamage"))
assert(findExactQualifiedFunction("function Controller:DealDamage(amount) end", "Controller:DealDamage") ~= nil)

local helperBody = [[
if condition then
	local amount = 0
end
AddCoins(amount)
]]
assert(referencesFreeNameByBlock(helperBody, "amount"))
assert(not referencesFreeNameByBlock("local amount = 0\nAddCoins(amount)", "amount"))
assert(referencesFreeNameByBlock("local amount = amount\nAddCoins(amount)", "amount"))
assert(referencesFreeNameByBlock([[
local callback = function()
	return callback
end
]], "callback"))

local fieldTaints = { ["object.Value"] = true, object = true }
local rootFieldSources = { object = { ["object.Value"] = true } }
rootFieldSources.object["object.Value"] = nil
fieldTaints["object.Value"] = nil
if next(rootFieldSources.object) == nil then
	fieldTaints.object = nil
end
assert(fieldTaints["object.Value"] == nil)
assert(fieldTaints.object == nil)

print("resolver regressions passed")
