local function findMatchingParen(source, openIndex)
	local depth = 0
	for index = openIndex, #source do
		local char = source:sub(index, index)
		if char == "(" then
			depth += 1
		elseif char == ")" then
			depth -= 1
			if depth == 0 then
				return index
			end
		end
	end
	return nil
end

local function extractQualifiedCalls(source)
	local calls = {}
	local searchIndex = 1

	while searchIndex <= #source do
		local startIndex, openIndex, rootPath, separator, method =
			source:find("([%a_][%w_%.:]*)%s*([%.:])%s*([%a_][%w_]*)%s*%(", searchIndex)
		if not startIndex then
			break
		end

		local closeIndex = findMatchingParen(source, openIndex)
		if closeIndex then
			local root = rootPath:match("^([%a_][%w_]*)") or rootPath
			table.insert(calls, {
				root = root,
				rootPath = rootPath,
				separator = separator,
				method = method,
				name = rootPath .. separator .. method,
				argsText = source:sub(openIndex + 1, closeIndex - 1),
			})
		end
		searchIndex = startIndex + #rootPath
	end

	for _, pattern in ipairs({
		"()([%a_][%w_]*)%s*%[%s*\"([%a_][%w_]*)\"%s*%]%s*%(()",
		"()([%a_][%w_]*)%s*%[%s*'([%a_][%w_]*)'%s*%]%s*%(()",
	}) do
		for startIndex, root, method, afterOpenIndex in source:gmatch(pattern) do
			local openIndex = afterOpenIndex - 1
			local closeIndex = findMatchingParen(source, openIndex)
			if closeIndex then
				table.insert(calls, {
					root = root,
					rootPath = root,
					separator = ".",
					method = method,
					name = root .. "." .. method,
					argsText = source:sub(openIndex + 1, closeIndex - 1),
					startIndex = startIndex,
				})
			end
		end
	end

	return calls
end

local calls = extractQualifiedCalls([[
Helpers.ApplyDamage(target, damage)
self:ApplyDamage(target, damage)
Controller:Purchase(player, payload)
self.Services.Combat:ApplyDamage(clientDamage)
Controllers.Combat.ApplyDamage(clientDamage)
Helpers["ApplyDamage"](target, math.clamp(damage, 1, 100))
]])

local byName = {}
for _, call in ipairs(calls) do
	byName[call.name] = call
end

assert(byName["Helpers.ApplyDamage"].root == "Helpers")
assert(byName["Helpers.ApplyDamage"].separator == ".")
assert(byName["self:ApplyDamage"].root == "self")
assert(byName["Controller:Purchase"].method == "Purchase")
assert(byName["self.Services.Combat:ApplyDamage"].rootPath == "self.Services.Combat")
assert(byName["Controllers.Combat.ApplyDamage"].rootPath == "Controllers.Combat")
assert(byName["math.clamp"].argsText == "damage, 1, 100")

local bracketCallFound = false
for _, call in ipairs(calls) do
	if call.name == "Helpers.ApplyDamage"
		and call.argsText == "target, math.clamp(damage, 1, 100)" then
		bracketCallFound = true
	end
end
assert(bracketCallFound)

local helperBody = "humanoid:TakeDamage(damage)"
local callerTaints = {
	damage = true,
	unusedPayload = true,
}
local captures = {}
for name in pairs(callerTaints) do
	if helperBody:find("%f[%w_]" .. name .. "%f[^%w_]") then
		captures[name] = true
	end
end

assert(captures.damage == true)
assert(captures.unusedPayload == nil)

local dealDamageArgs = { "clientTarget", "20" }
local inspected = {}
for _, arg in ipairs(dealDamageArgs) do
	inspected[arg] = true
end
assert(inspected.clientTarget == true)
assert(inspected["20"] == true)

print("QualifiedCalls regression test passed")
