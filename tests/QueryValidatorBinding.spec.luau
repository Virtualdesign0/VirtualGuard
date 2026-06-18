local function unionSets(a, b)
	local result = {}
	for key in pairs(a or {}) do
		result[key] = true
	end
	for key in pairs(b or {}) do
		result[key] = true
	end
	return result
end

local function intersectSets(a, b)
	local result = {}
	for key in pairs(a or {}) do
		if b and b[key] then
			result[key] = true
		end
	end
	return result
end

local function cloneBinding(binding)
	if type(binding) ~= "table" then
		return binding
	end
	return {
		kind = binding.kind,
		target = binding.target,
	}
end

local function newState()
	return {
		bindings = {},
		bindingScopes = {
			{
				id = 0,
				previous = {},
				previouslyAbsent = {},
			},
		},
		pathGuarantees = {},
	}
end

local function enterScope(state, scopeId)
	table.insert(state.bindingScopes, {
		id = scopeId,
		previous = {},
		previouslyAbsent = {},
	})
end

local function exitScope(state, scopeId)
	local scope = state.bindingScopes[#state.bindingScopes]
	assert(scope and scope.id == scopeId)
	for name, binding in pairs(scope.previous) do
		state.bindings[name] = cloneBinding(binding)
	end
	for name in pairs(scope.previouslyAbsent) do
		state.bindings[name] = nil
	end
	table.remove(state.bindingScopes)
end

local function assignBinding(state, name, target, isLocal)
	local scope = state.bindingScopes[#state.bindingScopes]
	if isLocal and scope.previous[name] == nil and not scope.previouslyAbsent[name] then
		if state.bindings[name] == nil then
			scope.previouslyAbsent[name] = true
		else
			scope.previous[name] = cloneBinding(state.bindings[name])
		end
	end
	state.bindings[name] = target and {
		kind = "symbol",
		target = target,
	} or {
		kind = "unknown",
	}
end

local function canonicalize(state, path)
	local current = path
	local visited = {}
	for _ = 1, 8 do
		local first, rest = current:match("^([%w_]+)%.?(.*)$")
		if not first or visited[first] then
			break
		end
		visited[first] = true
		local binding = state.bindings[first]
		if not binding then
			break
		end
		if binding.kind == "unknown" or not binding.target then
			return path
		end
		current = binding.target .. (rest ~= "" and ("." .. rest) or "")
	end
	return current
end

local function derivedReturnFact(receiverFact, argumentFacts)
	local result = {
		sources = unionSets(receiverFact and receiverFact.sources),
	}
	for _, fact in ipairs(argumentFacts) do
		result.sources = unionSets(result.sources, fact.sources)
	end
	return result
end

local queryFact = derivedReturnFact(
	{ sources = { clientReceiver = true } },
	{
		{ sources = { clientOrigin = true } },
		{ sources = { clientDirection = true } },
	}
)
assert(queryFact.sources.clientReceiver)
assert(queryFact.sources.clientOrigin)
assert(queryFact.sources.clientDirection)

local multilineName, multilineExpression = ([[
local result =
	Cast(
		Workspace,
		clientOrigin,
		clientDirection
	)
]]):match("^%s*local%s+([%w_]+)%s*=%s*(.+)$")
assert(multilineName == "result")
assert(multilineExpression:find("Cast", 1, true))

local pathA = {
	descendants = {
		target = {
			["workspace.Enemies"] = true,
		},
	},
}
local pathB = {
	descendants = {
		target = {
			["workspace.Enemies"] = true,
			["workspace.All"] = true,
		},
	},
}
local sharedAncestors = intersectSets(pathA.descendants.target, pathB.descendants.target)
assert(sharedAncestors["workspace.Enemies"])
assert(not sharedAncestors["workspace.All"])
assert(next(intersectSets(pathA.descendants.target, nil)) == nil)

local state = newState()
assignBinding(state, "Service", "CombatService", true)
assert(canonicalize(state, "Service.Apply") == "CombatService.Apply")
assignBinding(state, "Service", "SafeService", false)
assert(canonicalize(state, "Service.Apply") == "SafeService.Apply")

assignBinding(state, "Service", "CombatService", false)
enterScope(state, 1)
assignBinding(state, "Service", "SafeService", true)
assert(canonicalize(state, "Service.Apply") == "SafeService.Apply")
exitScope(state, 1)
assert(canonicalize(state, "Service.Apply") == "CombatService.Apply")

enterScope(state, 2)
assignBinding(state, "Cast", "Workspace.Raycast", true)
assert(canonicalize(state, "Cast") == "Workspace.Raycast")
exitScope(state, 2)
assert(state.bindings.Cast == nil)

print("query, validator, and binding regressions passed")
