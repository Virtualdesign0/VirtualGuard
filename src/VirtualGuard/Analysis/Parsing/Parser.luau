local ConfigModule = require(script.Parent.Parent.Parent.Config)
local LexerModule = require(script.Parent.Lexer)
local TextModule = require(script.Parent.Parent.Parent.Shared.Text)

local FlowParser = {}
local FlowCursor = {}
FlowCursor.__index = FlowCursor

function FlowCursor.new(tokens, source)
	return setmetatable({
		tokens = tokens,
		source = source,
		index = 1,
	}, FlowCursor)
end

function FlowCursor:peek(offset)
	return self.tokens[self.index + (offset or 0)] or self.tokens[#self.tokens]
end

function FlowCursor:advance()
	local token = self:peek()
	if token.kind ~= "eof" then
		self.index += 1
	end
	return token
end

function FlowCursor:isAtEnd()
	return self:peek().kind == "eof"
end

function FlowCursor:expect(value)
	local token = self:peek()
	if token.value ~= value then
		error("Expected `" .. tostring(value) .. "` near line " .. tostring(token.line))
	end
	self:advance()
	return token
end

function FlowCursor:readSourceUntilKeyword(keyword)
	local startToken = self:peek()
	local startOffset = startToken.startOffset
	local depth = 0
	while not self:isAtEnd() do
		local token = self:peek()
		if depth == 0 and token.kind == "keyword" and token.value == keyword then
			local endOffset = math.max(startOffset, token.startOffset - 1)
			return ConfigModule.trim(self.source:sub(startOffset, endOffset))
		end
		if token.value == "(" or token.value == "{" or token.value == "[" then
			depth += 1
		elseif token.value == ")" or token.value == "}" or token.value == "]" then
			depth = math.max(0, depth - 1)
		end
		self:advance()
	end
	return ConfigModule.trim(self.source:sub(startOffset))
end

function FlowParser.parseSimple(cursor)
	local startToken = cursor:peek()
	local startOffset = startToken.startOffset
	local startLine = startToken.line
	local depth = 0
	local lastToken = startToken
	local continuationTokens = {
		["="] = true,
		[","] = true,
		["."] = true,
		[":"] = true,
		["+"] = true,
		["-"] = true,
		["*"] = true,
		["/"] = true,
		["%"] = true,
		[".."] = true,
		["and"] = true,
		["or"] = true,
	}

	while not cursor:isAtEnd() do
		local token = cursor:peek()
		if depth == 0 and token.kind == "keyword" and (token.value == "elseif" or token.value == "else" or token.value == "end" or token.value == "until") then
			break
		end
		if token ~= startToken
			and depth == 0
			and token.line > lastToken.line
			and not continuationTokens[lastToken.value]
		then
			break
		end

		if token.value == "(" or token.value == "{" or token.value == "[" then
			depth += 1
		elseif token.value == ")" or token.value == "}" or token.value == "]" then
			depth = math.max(0, depth - 1)
		end

		lastToken = token
		cursor:advance()
	end

	return {
		kind = "Simple",
		text = ConfigModule.trim(cursor.source:sub(startOffset, lastToken.endOffset)),
		line = startLine,
	}
end

function FlowParser.parseReturn(cursor)
	local token = cursor:expect("return")
	local startOffset = token.startOffset
	local lastToken = token
	while not cursor:isAtEnd() do
		local nextToken = cursor:peek()
		if nextToken.line > token.line then
			break
		end
		lastToken = nextToken
		cursor:advance()
	end
	return {
		kind = "Return",
		text = ConfigModule.trim(cursor.source:sub(startOffset, lastToken.endOffset)),
		line = token.line,
	}
end

function FlowParser.parseFunctionDeclaration(cursor)
	local firstToken = cursor:peek()
	local startOffset = firstToken.startOffset
	local startLine = firstToken.line
	if firstToken.value == "local" then
		cursor:advance()
		cursor:expect("function")
	else
		cursor:expect("function")
	end

	local depth = 1
	local lastToken = firstToken
	while not cursor:isAtEnd() do
		local token = cursor:advance()
		lastToken = token
		if token.value == "function" or token.value == "if" or token.value == "while" or token.value == "for" or token.value == "repeat" then
			depth += 1
		elseif token.value == "do" then

		elseif token.value == "end" or token.value == "until" then
			depth -= 1
			if depth == 0 then
				break
			end
		end
	end

	return {
		kind = "FunctionDeclaration",
		text = ConfigModule.trim(cursor.source:sub(startOffset, lastToken.endOffset)),
		line = startLine,
	}
end

function FlowParser.parseIf(cursor)
	local ifToken = cursor:expect("if")
	local condition = cursor:readSourceUntilKeyword("then")
	cursor:expect("then")
	local thenBody, stop = FlowParser.parseBlock(cursor, {
		["elseif"] = true,
		["else"] = true,
		["end"] = true,
	})
	local elseifBranches = {}

	while stop == "elseif" do
		cursor:expect("elseif")
		local elseifCondition = cursor:readSourceUntilKeyword("then")
		cursor:expect("then")
		local body
		body, stop = FlowParser.parseBlock(cursor, {
			["elseif"] = true,
			["else"] = true,
			["end"] = true,
		})
		table.insert(elseifBranches, {
			condition = elseifCondition,
			body = body,
		})
	end

	local elseBody = nil
	if stop == "else" then
		cursor:expect("else")
		elseBody, stop = FlowParser.parseBlock(cursor, {
			["end"] = true,
		})
	end
	cursor:expect("end")

	return {
		kind = "If",
		condition = condition,
		thenBody = thenBody,
		elseifBranches = elseifBranches,
		elseBody = elseBody,
		line = ifToken.line,
	}
end

function FlowParser.parseWhile(cursor)
	local token = cursor:expect("while")
	local condition = cursor:readSourceUntilKeyword("do")
	cursor:expect("do")
	local body = FlowParser.parseBlock(cursor, {
		["end"] = true,
	})
	cursor:expect("end")
	return {
		kind = "While",
		condition = condition,
		body = body,
		line = token.line,
	}
end

function FlowParser.parseFor(cursor)
	local token = cursor:expect("for")
	local condition = cursor:readSourceUntilKeyword("do")
	cursor:expect("do")
	local body = FlowParser.parseBlock(cursor, {
		["end"] = true,
	})
	cursor:expect("end")
	return {
		kind = "While",
		condition = "for " .. condition,
		body = body,
		line = token.line,
	}
end

function FlowParser.parseRepeat(cursor)
	local token = cursor:expect("repeat")
	local body = FlowParser.parseBlock(cursor, {
		["until"] = true,
	})
	cursor:expect("until")
	local condition = FlowParser.parseSimple(cursor).text
	return {
		kind = "Repeat",
		condition = condition,
		body = body,
		line = token.line,
	}
end

function FlowParser.parseDo(cursor)
	local token = cursor:expect("do")
	local body = FlowParser.parseBlock(cursor, {
		["end"] = true,
	})
	cursor:expect("end")
	return {
		kind = "Do",
		body = body,
		line = token.line,
	}
end

function FlowParser.parseBlock(cursor, stopKeywords)
	local statements = {}
	stopKeywords = stopKeywords or {}
	while not cursor:isAtEnd() do
		local token = cursor:peek()
		if token.kind == "keyword" and stopKeywords[token.value] then
			return statements, token.value
		end
		if token.kind == "keyword" and (token.value == "elseif" or token.value == "else" or token.value == "end" or token.value == "until") then
			error("Unsupported or unmatched block terminator near line " .. tostring(token.line))
		end

		local previousIndex = cursor.index
		if token.value == "local" and cursor:peek(1).value == "function" then
			table.insert(statements, FlowParser.parseFunctionDeclaration(cursor))
		elseif token.value == "function" then
			table.insert(statements, FlowParser.parseFunctionDeclaration(cursor))
		elseif token.value == "if" then
			table.insert(statements, FlowParser.parseIf(cursor))
		elseif token.value == "while" then
			table.insert(statements, FlowParser.parseWhile(cursor))
		elseif token.value == "for" then
			table.insert(statements, FlowParser.parseFor(cursor))
		elseif token.value == "repeat" then
			table.insert(statements, FlowParser.parseRepeat(cursor))
		elseif token.value == "do" then
			table.insert(statements, FlowParser.parseDo(cursor))
		elseif token.value == "return" then
			table.insert(statements, FlowParser.parseReturn(cursor))
		elseif token.value == "break" then
			table.insert(statements, {
				kind = "Break",
				line = token.line,
			})
			cursor:advance()
		elseif token.value == "continue" then
			table.insert(statements, {
				kind = "Continue",
				line = token.line,
			})
			cursor:advance()
		else
			table.insert(statements, FlowParser.parseSimple(cursor))
		end

		if cursor.index == previousIndex then
			error("Parser made no progress near line " .. tostring(token.line) .. " at token " .. tostring(token.value))
		end
	end
	return statements, nil
end

function FlowParser.parse(source, budgets, context)
	if TextModule.hasExceededCfgDeadline(context) then
		error("CFG deadline exceeded")
	end
	local tokens = LexerModule.FlowLexer.lex(source)
	if TextModule.hasExceededCfgDeadline(context) then
		error("CFG deadline exceeded")
	end
	if #tokens > budgets.maxTokens then
		error("CFG token budget exceeded")
	end
	local cursor = FlowCursor.new(tokens, source)
	local statements = FlowParser.parseBlock(cursor, {})
	return statements
end

local function detectUnsupportedFlowSyntax(source)
	local unsupported = {}
	local function add(kind)
		for _, existing in ipairs(unsupported) do
			if existing == kind then
				return
			end
		end
		table.insert(unsupported, kind)
	end

	source = TextModule.stripStringsForAnalysis(TextModule.stripComments(source or ""))

	if source:find("function%s*%(") then
		add("FunctionExpression")
	end
	if source:find("local%s+[%w_]+%s*,") or source:find("\n%s*[%w_]+%s*,[%w_,%s]*=") then
		add("MultiAssignment")
	end
	if source:find("=%s*if%s+") then
		add("IfExpression")
	end

	return unsupported
end

return {
	detectUnsupportedFlowSyntax = detectUnsupportedFlowSyntax,
	FlowCursor = FlowCursor,
	FlowParser = FlowParser,
}
