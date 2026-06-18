local ConfigModule = require(script.Parent.Parent.Parent.Config)
local TextModule = require(script.Parent.Parent.Parent.Shared.Text)

local function nextCodeWord(source, startIndex)
	local index = startIndex
	local quote = nil
	local escaped = false
	local template = false

	while index <= #source do
		local char = source:sub(index, index)

		if quote then
			if escaped then
				escaped = false
			elseif char == "\\" then
				escaped = true
			elseif char == quote then
				quote = nil
				template = false
			end
			index += 1
		else
			if char == '"' or char == "'" or char == "`" then
				quote = char
				template = char == "`"
				index += 1
			elseif char == "[" then
				local equals = source:sub(index):match("^%[(=*)%[")
				if equals then
					local closeToken = "]" .. equals .. "]"
					local closeIndex = source:find(closeToken, index + 2 + #equals, true)
					index = closeIndex and (closeIndex + #closeToken) or (#source + 1)
				else
					index += 1
				end
			elseif char:match("[%a_]") then
				local wordStart = index
				index += 1
				while index <= #source and source:sub(index, index):match("[%w_]") do
					index += 1
				end
				return source:sub(wordStart, index - 1), wordStart, index - 1
			else
				index += 1
			end
		end
	end

	return nil, nil, nil
end

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
			elseif char == "[" then
				local equals = source:sub(index):match("^%[(=*)%[")
				if equals then
					local closeToken = "]" .. equals .. "]"
					local closeIndex = source:find(closeToken, index + 2 + #equals, true)
					index = closeIndex and (closeIndex + #closeToken) or (#source + 1)
				else
					index += 1
				end
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

local function isDirectCallExpression(expression, callPattern)
	local code = ConfigModule.trim(TextModule.stripStringsForAnalysis(expression or ""))
	if not code:find("^" .. callPattern .. "%s*%(") then
		return false
	end

	local openIndex = code:find("(", 1, true)
	local closeIndex = openIndex and findMatchingParen(code, openIndex)
	return closeIndex ~= nil and ConfigModule.trim(code:sub(closeIndex + 1)) == ""
end

local function getDirectCallArgs(expression, callPattern)
	local code = ConfigModule.trim(TextModule.stripStringsForAnalysis(expression or ""))
	if not code:find("^" .. callPattern .. "%s*%(") then
		return nil
	end

	local openIndex = code:find("(", 1, true)
	local closeIndex = openIndex and findMatchingParen(code, openIndex)
	if not closeIndex or ConfigModule.trim(code:sub(closeIndex + 1)) ~= "" then
		return nil
	end

	return TextModule.splitTopLevelArgs(code:sub(openIndex + 1, closeIndex - 1))
end

local function isTrustedNumericBound(expression)
	local clean = ConfigModule.trim(expression or ""):gsub("_", "")
	if clean:match("^%-?%d+%.?%d*$") then
		return true
	end
	if clean:match("^%-?%d*%.%d+$") then
		return true
	end
	return false
end

local function hasArithmeticOrConcat(expression)
	local code = TextModule.stripStringsForAnalysis(expression or "")
	return code:find("%.%.", 1, true) ~= nil
		or code:find("[%+%-%*/%%%^]") ~= nil
end

local function hasConcat(expression)
	return TextModule.stripStringsForAnalysis(expression or ""):find("%.%.", 1, true) ~= nil
end

local function balanceDelta(source)
	local quote = nil
	local escaped = false
	local delta = 0
	local index = 1

	while index <= #(source or "") do
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
			elseif char == "[" then
				local equals = source:sub(index):match("^%[(=*)%[")
				if equals then
					local closeToken = "]" .. equals .. "]"
					local closeIndex = source:find(closeToken, index + 2 + #equals, true)
					index = closeIndex and (closeIndex + #closeToken) or (#source + 1)
				else
					delta += 1
					index += 1
				end
			elseif char == "(" or char == "{" then
				delta += 1
				index += 1
			elseif char == ")" or char == "}" or char == "]" then
				delta -= 1
				index += 1
			else
				index += 1
			end
		end
	end

	return delta
end

local function shouldContinueStatement(line, depth)
	local cleaned = ConfigModule.trim(line or "")
	return depth > 0
		or cleaned:match("=%s*$") ~= nil
		or cleaned:match(",%s*$") ~= nil
		or cleaned:match("%(%s*$") ~= nil
		or cleaned:match("{%s*$") ~= nil
end

return {
	nextCodeWord = nextCodeWord,
	findMatchingParen = findMatchingParen,
	isDirectCallExpression = isDirectCallExpression,
	getDirectCallArgs = getDirectCallArgs,
	isTrustedNumericBound = isTrustedNumericBound,
	hasArithmeticOrConcat = hasArithmeticOrConcat,
	hasConcat = hasConcat,
	balanceDelta = balanceDelta,
	shouldContinueStatement = shouldContinueStatement,
}
