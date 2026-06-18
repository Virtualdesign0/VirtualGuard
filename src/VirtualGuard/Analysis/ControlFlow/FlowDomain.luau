local SetModule = require(script.Parent.Parent.Parent.Shared.Set)

local FlowDomain = {}
local function cloneBinding(binding)
	if type(binding) ~= "table" then
		return binding
	end
	return {
		kind = binding.kind,
		target = binding.target,
	}
end

local function bindingsEqual(a, b)
	if a == b then
		return true
	end
	if type(a) ~= "table" or type(b) ~= "table" then
		return false
	end
	return a.kind == b.kind and a.target == b.target
end

local function cloneBindings(bindings)
	local result = {}
	for name, binding in pairs(bindings or {}) do
		result[name] = cloneBinding(binding)
	end
	return result
end

local function bindingMapsEqual(a, b)
	for name, binding in pairs(a or {}) do
		if not bindingsEqual(binding, b and b[name]) then
			return false
		end
	end
	for name, binding in pairs(b or {}) do
		if not bindingsEqual(binding, a and a[name]) then
			return false
		end
	end
	return true
end

local function cloneBindingScopes(scopes)
	local result = {}
	for _, scope in ipairs(scopes or {}) do
		table.insert(result, {
			id = scope.id,
			previous = cloneBindings(scope.previous),
			previouslyAbsent = SetModule.unionSets(scope.previouslyAbsent),
		})
	end
	return result
end

local function bindingScopesEqual(a, b)
	if #(a or {}) ~= #(b or {}) then
		return false
	end
	for index, scope in ipairs(a or {}) do
		local other = b[index]
		if not other
			or scope.id ~= other.id
			or not bindingMapsEqual(scope.previous, other.previous)
			or not SetModule.setsEqual(scope.previouslyAbsent, other.previouslyAbsent)
		then
			return false
		end
	end
	return true
end

local function clonePathGuarantees(pathGuarantees)
	local result = {}
	for guarantee, value in pairs(pathGuarantees or {}) do
		if guarantee == "descendants" and type(value) == "table" then
			local descendants = {}
			for subject, ancestors in pairs(value) do
				descendants[subject] = SetModule.unionSets(ancestors)
			end
			result.descendants = descendants
		elseif value == true then
			result[guarantee] = true
		end
	end
	return result
end

local function intersectPathGuarantees(a, b)
	local result = {}
	for guarantee, value in pairs(a or {}) do
		if guarantee == "descendants" and type(value) == "table" then
			local descendants = {}
			local otherDescendants = b and b.descendants
			for subject, ancestors in pairs(value) do
				local shared = SetModule.intersectSets(ancestors, otherDescendants and otherDescendants[subject])
				if next(shared) ~= nil then
					descendants[subject] = shared
				end
			end
			if next(descendants) ~= nil then
				result.descendants = descendants
			end
		elseif value == true and b and b[guarantee] == true then
			result[guarantee] = true
		end
	end
	return result
end

local function pathGuaranteesEqual(a, b)
	local flatA = {}
	local flatB = {}
	for guarantee, value in pairs(a or {}) do
		if guarantee ~= "descendants" and value == true then
			flatA[guarantee] = true
		end
	end
	for guarantee, value in pairs(b or {}) do
		if guarantee ~= "descendants" and value == true then
			flatB[guarantee] = true
		end
	end
	if not SetModule.setsEqual(flatA, flatB) then
		return false
	end
	local descendantsA = (a and a.descendants) or {}
	local descendantsB = (b and b.descendants) or {}
	for subject, ancestors in pairs(descendantsA) do
		if not SetModule.setsEqual(ancestors, descendantsB[subject]) then
			return false
		end
	end
	for subject, ancestors in pairs(descendantsB) do
		if not SetModule.setsEqual(ancestors, descendantsA[subject]) then
			return false
		end
	end
	return true
end

function FlowDomain.emptyFact()
	return {
		sources = {},
		guarantees = {},
	}
end

function FlowDomain.newState()
	return {
		reachable = true,
		variables = {},
		pathGuarantees = {},
		bindings = {},
		bindingScopes = {
			{
				id = 0,
				previous = {},
				previouslyAbsent = {},
			},
		},
	}
end

function FlowDomain.cloneFact(fact)
	return {
		sources = SetModule.unionSets((fact or FlowDomain.emptyFact()).sources),
		guarantees = SetModule.unionSets((fact or FlowDomain.emptyFact()).guarantees),
	}
end

function FlowDomain.cloneState(state)
	local result = FlowDomain.newState()
	result.reachable = state and state.reachable == true or false
	for name, fact in pairs((state and state.variables) or {}) do
		result.variables[name] = FlowDomain.cloneFact(fact)
	end
	result.pathGuarantees = clonePathGuarantees((state and state.pathGuarantees) or {})
	result.bindings = cloneBindings((state and state.bindings) or {})
	result.bindingScopes = cloneBindingScopes((state and state.bindingScopes) or result.bindingScopes)
	return result
end

function FlowDomain.enterBindingScope(state, scopeId)
	state.bindingScopes = state.bindingScopes or {}
	table.insert(state.bindingScopes, {
		id = scopeId,
		previous = {},
		previouslyAbsent = {},
	})
end

function FlowDomain.exitBindingScope(state, scopeId)
	local scopes = state.bindingScopes or {}
	local scope = scopes[#scopes]
	if not scope or scope.id ~= scopeId then
		return
	end
	for name, binding in pairs(scope.previous or {}) do
		state.bindings[name] = cloneBinding(binding)
	end
	for name in pairs(scope.previouslyAbsent or {}) do
		state.bindings[name] = nil
	end
	table.remove(scopes)
end

function FlowDomain.assignBinding(state, name, binding, isLocal)
	state.bindings = state.bindings or {}
	state.bindingScopes = state.bindingScopes or {}
	local nextBinding = binding or {
		kind = "unknown",
	}
	if isLocal then
		local scope = state.bindingScopes[#state.bindingScopes]
		if not scope then
			FlowDomain.enterBindingScope(state, 0)
			scope = state.bindingScopes[#state.bindingScopes]
		end
		if scope.previous[name] == nil and not scope.previouslyAbsent[name] then
			if state.bindings[name] == nil then
				scope.previouslyAbsent[name] = true
			else
				scope.previous[name] = cloneBinding(state.bindings[name])
			end
		end
	end
	state.bindings[name] = cloneBinding(nextBinding)
end

function FlowDomain.joinFact(a, b)
	return {
		sources = SetModule.unionSets((a or FlowDomain.emptyFact()).sources, (b or FlowDomain.emptyFact()).sources),
		guarantees = SetModule.intersectSets((a or FlowDomain.emptyFact()).guarantees, (b or FlowDomain.emptyFact()).guarantees),
	}
end

function FlowDomain.factEquals(a, b)
	return SetModule.setsEqual((a or FlowDomain.emptyFact()).sources, (b or FlowDomain.emptyFact()).sources)
		and SetModule.setsEqual((a or FlowDomain.emptyFact()).guarantees, (b or FlowDomain.emptyFact()).guarantees)
end

function FlowDomain.stateEquals(a, b)
	if (a and a.reachable == true) ~= (b and b.reachable == true) then
		return false
	end
	local seen = {}
	for name in pairs((a and a.variables) or {}) do
		seen[name] = true
	end
	for name in pairs((b and b.variables) or {}) do
		seen[name] = true
	end
	for name in pairs(seen) do
		if not FlowDomain.factEquals(a and a.variables[name], b and b.variables[name]) then
			return false
		end
	end
	return pathGuaranteesEqual((a and a.pathGuarantees) or {}, (b and b.pathGuarantees) or {})
		and bindingMapsEqual((a and a.bindings) or {}, (b and b.bindings) or {})
		and bindingScopesEqual((a and a.bindingScopes) or {}, (b and b.bindingScopes) or {})
end

function FlowDomain.mergeState(existing, incoming)
	if not incoming or not incoming.reachable then
		return existing, false
	end
	if not existing or not existing.reachable then
		return FlowDomain.cloneState(incoming), true
	end
	local merged = FlowDomain.cloneState(existing)
	merged.reachable = true
	local seen = {}
	for name in pairs(existing.variables or {}) do
		seen[name] = true
	end
	for name in pairs(incoming.variables or {}) do
		seen[name] = true
	end
	for name in pairs(seen) do
		merged.variables[name] = FlowDomain.joinFact(existing.variables[name], incoming.variables[name])
	end
	merged.pathGuarantees = intersectPathGuarantees(existing.pathGuarantees, incoming.pathGuarantees)
	local bindingNames = {}
	for name in pairs(existing.bindings or {}) do
		bindingNames[name] = true
	end
	for name in pairs(incoming.bindings or {}) do
		bindingNames[name] = true
	end
	merged.bindings = {}
	for name in pairs(bindingNames) do
		local existingBinding = existing.bindings and existing.bindings[name]
		local incomingBinding = incoming.bindings and incoming.bindings[name]
		if bindingsEqual(existingBinding, incomingBinding) then
			merged.bindings[name] = cloneBinding(existingBinding)
		else
			merged.bindings[name] = {
				kind = "unknown",
			}
		end
	end
	if bindingScopesEqual(existing.bindingScopes, incoming.bindingScopes) then
		merged.bindingScopes = cloneBindingScopes(existing.bindingScopes)
	else
		merged.bindingScopes = cloneBindingScopes(existing.bindingScopes)
		for _, scope in ipairs(merged.bindingScopes) do
			for name in pairs(scope.previous or {}) do
				scope.previous[name] = {
					kind = "unknown",
				}
			end
		end
	end
	return merged, not FlowDomain.stateEquals(existing, merged)
end

return {
	bindingMapsEqual = bindingMapsEqual,
	bindingScopesEqual = bindingScopesEqual,
	bindingsEqual = bindingsEqual,
	cloneBinding = cloneBinding,
	cloneBindings = cloneBindings,
	cloneBindingScopes = cloneBindingScopes,
	clonePathGuarantees = clonePathGuarantees,
	FlowDomain = FlowDomain,
	intersectPathGuarantees = intersectPathGuarantees,
	pathGuaranteesEqual = pathGuaranteesEqual,
}
