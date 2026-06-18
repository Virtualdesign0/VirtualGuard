local function preserveNewlines(text)
	local _, count = text:gsub("\n", "\n")
	return string.rep("\n", count)
end

local function maskNonNewlineChars(text)
	local masked = (text or ""):gsub("[^\n]", " ")
	return masked
end

local function appendMasked(output, text)
	table.insert(output, maskNonNewlineChars(text))
end

local function stripComments(source)
	local output = {}
	local index = 1
	local quote = nil
	local escaped = false
	local longCommentClose = nil
	local longStringClose = nil

	source = source or ""

	while index <= #source do
		local char = source:sub(index, index)
		local nextChar = source:sub(index + 1, index + 1)

		if longCommentClose then
			if source:sub(index, index + #longCommentClose - 1) == longCommentClose then
				appendMasked(output, longCommentClose)
				index += #longCommentClose
				longCommentClose = nil
			else
				table.insert(output, char == "\n" and "\n" or " ")
				index += 1
			end
		elseif longStringClose then
			if source:sub(index, index + #longStringClose - 1) == longStringClose then
				table.insert(output, longStringClose)
				index += #longStringClose
				longStringClose = nil
			else
				table.insert(output, char)
				index += 1
			end
		elseif quote then
			table.insert(output, char)
			if escaped then
				escaped = false
			elseif char == "\\" then
				escaped = true
			elseif char == quote then
				quote = nil
			end
			index += 1
		elseif char == '"' or char == "'" or char == "`" then
			quote = char
			table.insert(output, char)
			index += 1
		elseif char == "[" then
			local equals = source:sub(index):match("^%[(=*)%[")
			if equals then
				local openToken = "[" .. equals .. "["
				longStringClose = "]" .. equals .. "]"
				table.insert(output, openToken)
				index += #openToken
			else
				table.insert(output, char)
				index += 1
			end
		elseif char == "-" and nextChar == "-" then
			local equals = source:sub(index + 2):match("^%[(=*)%[")
			if equals then
				local openToken = "--[" .. equals .. "["
				longCommentClose = "]" .. equals .. "]"
				appendMasked(output, openToken)
				index += #openToken
			else
				while index <= #source and source:sub(index, index) ~= "\n" do
					table.insert(output, " ")
					index += 1
				end
			end
		else
			table.insert(output, char)
			index += 1
		end
	end

	return table.concat(output)
end

local function stripStringsForAnalysis(source)
	local output = {}
	local index = 1
	local quote = nil
	local escaped = false
	local longStringClose = nil
	local longCommentClose = nil

	source = source or ""

	while index <= #source do
		local char = source:sub(index, index)
		local nextChar = source:sub(index + 1, index + 1)

		if longCommentClose then
			if source:sub(index, index + #longCommentClose - 1) == longCommentClose then
				appendMasked(output, longCommentClose)
				index += #longCommentClose
				longCommentClose = nil
			else
				table.insert(output, char == "\n" and "\n" or " ")
				index += 1
			end
		elseif longStringClose then
			if source:sub(index, index + #longStringClose - 1) == longStringClose then
				appendMasked(output, longStringClose)
				index += #longStringClose
				longStringClose = nil
			else
				table.insert(output, char == "\n" and "\n" or " ")
				index += 1
			end
		elseif quote then
			table.insert(output, char == "\n" and "\n" or " ")
			if escaped then
				escaped = false
			elseif char == "\\" then
				escaped = true
			elseif char == quote then
				quote = nil
			end
			index += 1
		elseif char == '"' or char == "'" or char == "`" then
			quote = char
			table.insert(output, " ")
			index += 1
		elseif char == "[" then
			local equals = source:sub(index):match("^%[(=*)%[")
			if equals then
				local openToken = "[" .. equals .. "["
				longStringClose = "]" .. equals .. "]"
				appendMasked(output, openToken)
				index += #openToken
			else
				table.insert(output, char)
				index += 1
			end
		elseif char == "-" and nextChar == "-" then
			local equals = source:sub(index + 2):match("^%[(=*)%[")
			if equals then
				local openToken = "--[" .. equals .. "["
				longCommentClose = "]" .. equals .. "]"
				appendMasked(output, openToken)
				index += #openToken
			else
				while index <= #source and source:sub(index, index) ~= "\n" do
					table.insert(output, " ")
					index += 1
				end
			end
		else
			table.insert(output, char)
			index += 1
		end
	end

	return table.concat(output)
end

local stripStringsPreservingBracketKeys

stripStringsPreservingBracketKeys = function(source)
	local clean = stripComments(source or "")
	local output = {}
	local index = 1

	local function previousNonSpaceIndex(cursor)
		while cursor >= 1 do
			if not clean:sub(cursor, cursor):match("%s") then
				return cursor
			end
			cursor -= 1
		end
		return nil
	end

	local function nextNonSpaceIndex(cursor)
		while cursor <= #clean do
			if not clean:sub(cursor, cursor):match("%s") then
				return cursor
			end
			cursor += 1
		end
		return nil
	end

	while index <= #clean do
		local char = clean:sub(index, index)
		if char == '"' or char == "'" then
			local quote = char
			local escaped = false
			local closeIndex = nil
			local scan = index + 1
			while scan <= #clean do
				local scanChar = clean:sub(scan, scan)
				if escaped then
					escaped = false
				elseif scanChar == "\\" then
					escaped = true
				elseif scanChar == quote then
					closeIndex = scan
					break
				end
				scan += 1
			end

			local before = previousNonSpaceIndex(index - 1)
			local after = closeIndex and nextNonSpaceIndex(closeIndex + 1) or nil
			local isBracketKey = before and after
				and clean:sub(before, before) == "["
				and clean:sub(after, after) == "]"

			local literal = closeIndex and clean:sub(index, closeIndex) or clean:sub(index)
			if isBracketKey then
				table.insert(output, literal)
			else
				appendMasked(output, literal)
			end
			index = (closeIndex or #clean) + 1
		elseif char == "[" then
			local equals = clean:sub(index):match("^%[(=*)%[")
			if equals then
				local closeToken = "]" .. equals .. "]"
				local closeIndex = clean:find(closeToken, index + 2 + #equals, true)
				local literal = closeIndex and clean:sub(index, closeIndex + #closeToken - 1) or clean:sub(index)
				appendMasked(output, literal)
				index = closeIndex and (closeIndex + #closeToken) or (#clean + 1)
			else
				table.insert(output, char)
				index += 1
			end
		else
			table.insert(output, char)
			index += 1
		end
	end

	return table.concat(output)
end

return {
	appendMasked = appendMasked,
	maskNonNewlineChars = maskNonNewlineChars,
	preserveNewlines = preserveNewlines,
	stripComments = stripComments,
	stripStringsForAnalysis = stripStringsForAnalysis,
	stripStringsPreservingBracketKeys = stripStringsPreservingBracketKeys,
}
