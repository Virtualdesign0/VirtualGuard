local FlowLexer = {}
local FLOW_KEYWORDS = {
	["local"] = true,
	["function"] = true,
	["if"] = true,
	["then"] = true,
	["elseif"] = true,
	["else"] = true,
	["end"] = true,
	["while"] = true,
	["do"] = true,
	["repeat"] = true,
	["until"] = true,
	["for"] = true,
	["in"] = true,
	["return"] = true,
	["break"] = true,
	["continue"] = true,
	["and"] = true,
	["or"] = true,
	["not"] = true,
	["true"] = true,
	["false"] = true,
	["nil"] = true,
}

function FlowLexer.lex(source)
	local tokens = {}
	local index = 1
	local line = 1
	local column = 1

	local function push(kind, value, startOffset, endOffset, startLine, startColumn)
		table.insert(tokens, {
			kind = kind,
			value = value,
			startOffset = startOffset,
			endOffset = endOffset,
			line = startLine,
			column = startColumn,
		})
	end

	local function advanceChar()
		local char = source:sub(index, index)
		index += 1
		if char == "\n" then
			line += 1
			column = 1
		else
			column += 1
		end
		return char
	end

	while index <= #source do
		local char = source:sub(index, index)

		if char:match("%s") then
			advanceChar()
		elseif char == '"' or char == "'" or char == "`" then
			local startOffset = index
			local startLine = line
			local startColumn = column
			local quote = char
			local escaped = false
			advanceChar()
			while index <= #source do
				local current = advanceChar()
				if escaped then
					escaped = false
				elseif current == "\\" then
					escaped = true
				elseif current == quote then
					break
				end
			end
			push("string", source:sub(startOffset, index - 1), startOffset, index - 1, startLine, startColumn)
		elseif char == "[" and source:sub(index):match("^%[(=*)%[") then
			local startOffset = index
			local startLine = line
			local startColumn = column
			local equals = source:sub(index):match("^%[(=*)%[")
			local closeToken = "]" .. equals .. "]"
			for _ = 1, 2 + #equals do
				advanceChar()
			end
			while index <= #source and source:sub(index, index + #closeToken - 1) ~= closeToken do
				advanceChar()
			end
			for _ = 1, #closeToken do
				if index <= #source then
					advanceChar()
				end
			end
			push("string", source:sub(startOffset, index - 1), startOffset, index - 1, startLine, startColumn)
		elseif char:match("[%a_]") then
			local startOffset = index
			local startLine = line
			local startColumn = column
			advanceChar()
			while index <= #source and source:sub(index, index):match("[%w_]") do
				advanceChar()
			end
			local value = source:sub(startOffset, index - 1)
			push(FLOW_KEYWORDS[value] and "keyword" or "identifier", value, startOffset, index - 1, startLine, startColumn)
		elseif char:match("%d") then
			local startOffset = index
			local startLine = line
			local startColumn = column
			advanceChar()
			while index <= #source and source:sub(index, index):match("[%w_%.]") do
				advanceChar()
			end
			push("number", source:sub(startOffset, index - 1), startOffset, index - 1, startLine, startColumn)
		else
			local startOffset = index
			local startLine = line
			local startColumn = column
			local two = source:sub(index, index + 1)
			if two == "+=" or two == "-=" or two == "*=" or two == "/=" or two == "==" or two == "~=" or two == "<=" or two == ">=" or two == ".." or two == "::" or two == "->" then
				advanceChar()
				advanceChar()
				push("operator", two, startOffset, index - 1, startLine, startColumn)
			else
				advanceChar()
				local kind = (char == "(" or char == ")" or char == "[" or char == "]" or char == "{" or char == "}" or char == "," or char == "." or char == ":" or char == ";") and "punctuation" or "operator"
				push(kind, char, startOffset, index - 1, startLine, startColumn)
			end
		end
	end

	push("eof", "", #source + 1, #source + 1, line, column)
	return tokens
end

return {
	FLOW_KEYWORDS = FLOW_KEYWORDS,
	FlowLexer = FlowLexer,
}
