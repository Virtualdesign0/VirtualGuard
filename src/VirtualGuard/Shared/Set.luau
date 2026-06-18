local function hasSetValues(set)
	for _ in pairs(set or {}) do
		return true
	end
	return false
end

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

local function setsEqual(a, b)
	for key in pairs(a or {}) do
		if not (b and b[key]) then
			return false
		end
	end
	for key in pairs(b or {}) do
		if not (a and a[key]) then
			return false
		end
	end
	return true
end

return {
	hasSetValues = hasSetValues,
	intersectSets = intersectSets,
	setsEqual = setsEqual,
	unionSets = unionSets,
}
