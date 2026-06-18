local function findMatchingParen(source, openIndex)
	local quote = nil
	local escaped = false
	local depth = 0
	local index = openIndex

	while index <= #source do
		local char = source:sub(index, index)

		if quote then
			if escaped then
				escaped = false
			elseif char == "\\" then
				escaped = true
			elseif char == quote then
				quote = nil
			end
			index += 1
		else
			if char == '"' or char == "'" or char == "`" then
				quote = char
				index += 1
			elseif char == "(" then
				depth += 1
				index += 1
			elseif char == ")" then
				depth -= 1
				if depth == 0 then
					return index
				end
				index += 1
			else
				index += 1
			end
		end
	end

	return nil
end

local function extractIdentifierCalls(source)
	local calls = {}
	local searchIndex = 1
	local callKeywords = {
		["if"] = true,
		["for"] = true,
		["while"] = true,
		["return"] = true,
		["function"] = true,
		["local"] = true,
		["elseif"] = true,
	}

	while searchIndex <= #source do
		local nameStart, openIndex, name = source:find("([%a_][%w_]*)%s*%(", searchIndex)
		if not nameStart then
			break
		end

		local nameEnd = nameStart + #name - 1
		local prevChar = nameStart > 1 and source:sub(nameStart - 1, nameStart - 1) or ""
		local isMethodLike = prevChar == "." or prevChar == ":" or prevChar:match("[%w_]")
		local closeIndex = findMatchingParen(source, openIndex)

		if not isMethodLike and closeIndex and not callKeywords[name] then
			table.insert(calls, {
				name = name,
				argsText = source:sub(openIndex + 1, closeIndex - 1),
			})
			searchIndex = nameEnd + 1
		else
			searchIndex = (openIndex or nameEnd) + 1
		end
	end

	return calls
end

local source = [[
applyDamage(target, damage)
validate(payload)
Sanitize(amount)
Validator(payload, math.clamp(amount, 1, 100))
assert(validateNested(clientPayload))
DamageService:DealDamage(target, damage)
object.method(payload)
if allowed(payload) then
	return
end
]]

local calls = extractIdentifierCalls(source)
local names = {}
for _, call in ipairs(calls) do
	names[call.name] = call.argsText
end

assert(names.applyDamage == "target, damage")
assert(names.validate == "payload")
assert(names.Sanitize == "amount")
assert(names.Validator == "payload, math.clamp(amount, 1, 100)")
assert(names.allowed == "payload")
assert(names.validateNested == "clientPayload")
assert(names.DealDamage == nil)
assert(names.method == nil)

print("IdentifierCalls regression test passed")
