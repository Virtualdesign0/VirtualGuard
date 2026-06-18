local function cloneSet(source)
	local result = {}
	for key in pairs(source or {}) do
		result[key] = true
	end
	return result
end

local function evaluateClampReturn(inputFact, minimum, maximum)
	local result = {
		sources = cloneSet(inputFact.sources),
		guarantees = {},
	}
	result.guarantees.number = true
	if type(minimum) == "number" and type(maximum) == "number" then
		result.guarantees.bounded = true
	end
	return result
end

local function joinFact(left, right)
	local result = {
		sources = cloneSet(left.sources),
		guarantees = {},
	}
	for source in pairs(right.sources or {}) do
		result.sources[source] = true
	end
	for guarantee in pairs(left.guarantees or {}) do
		if right.guarantees and right.guarantees[guarantee] then
			result.guarantees[guarantee] = true
		end
	end
	return result
end

local input = {
	sources = {
		["OnServerEvent:clientAmount"] = true,
	},
	guarantees = {},
}

local returnFact = evaluateClampReturn(input, 0, 100)

assert(returnFact.sources["OnServerEvent:clientAmount"] == true)
assert(returnFact.guarantees.number == true)
assert(returnFact.guarantees.bounded == true)
assert(input.guarantees.number == nil)
assert(input.guarantees.bounded == nil)

local emptyFact = {
	sources = {},
	guarantees = {},
}
local safeOrBareReturn = joinFact(returnFact, emptyFact)
assert(safeOrBareReturn.sources["OnServerEvent:clientAmount"] == true)
assert(safeOrBareReturn.guarantees.number == nil)
assert(safeOrBareReturn.guarantees.bounded == nil)

local safeOrImplicitNil = joinFact(returnFact, emptyFact)
assert(safeOrImplicitNil.sources["OnServerEvent:clientAmount"] == true)
assert(safeOrImplicitNil.guarantees.bounded == nil)

local innerReturn = evaluateClampReturn(input, 0, 100)
local outerReturn = {
	sources = cloneSet(innerReturn.sources),
	guarantees = cloneSet(innerReturn.guarantees),
}
assert(outerReturn.guarantees.number == true)
assert(outerReturn.guarantees.bounded == true)

print("ReturnFact regression test passed")
