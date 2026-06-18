local CallSyntaxModule = require(script.Parent.Parent.Parsing.CallSyntax)
local TextModule = require(script.Parent.Parent.Parent.Shared.Text)

local findMatchingParen = CallSyntaxModule.findMatchingParen
local nextCodeWord = CallSyntaxModule.nextCodeWord
local shouldContinueStatement = CallSyntaxModule.shouldContinueStatement

local function extractLuaFunctionHeader(source, startIndex)
	local headerOpen = source:find("(", startIndex, true)
	local headerEnd = headerOpen and findMatchingParen(source, headerOpen) or nil
	if not headerEnd then
		return nil, nil, nil
	end

	return source:sub(headerOpen + 1, headerEnd - 1), headerOpen, headerEnd
end

local function extractLuaFunctionArgs(source, startIndex)
	local argsText = extractLuaFunctionHeader(source, startIndex)
	return argsText
end

local function extractLuaFunctionBody(source, startIndex)
	local _, _, headerEnd = extractLuaFunctionHeader(source, startIndex)
	if not headerEnd then
		return nil
	end

	local bodyStart = headerEnd + 1
	local searchIndex = bodyStart
	local depth = 1

	while searchIndex <= #source do
		local token, tokenStart, tokenEnd = nextCodeWord(source, searchIndex)

		if not token then
			break
		end

		if token == "function" or token == "if" or token == "for" or token == "while" or token == "repeat" then
			depth += 1
		elseif token == "do" then
			local lineStart = TextModule.getLineStartIndex(source, tokenStart)
			local before = source:sub(lineStart, tokenStart - 1)
			if not before:find("%f[%a_]for%f[^%w_]") and not before:find("%f[%a_]while%f[^%w_]") then
				depth += 1
			end
		elseif token == "end" or token == "until" then
			depth -= 1
			if depth == 0 then
				return source:sub(bodyStart, tokenStart - 1)
			end
		end

		searchIndex = tokenEnd + 1
	end

	return source:sub(bodyStart, math.min(#source, bodyStart + 3000))
end

local function functionNameMatches(foundName, requestedName)
	local found = TextModule.normalizeRequireExpression(foundName or ""):gsub(":", ".")
	local requested = TextModule.normalizeRequireExpression(requestedName or ""):gsub(":", ".")
	return found == requested
end

local function findNamedFunctionBody(source, requestedName, visited)
	local normalizedName = TextModule.normalizeRequireExpression(requestedName or "")
	if normalizedName == "" then
		return nil
	end

	visited = visited or {}
	if visited[normalizedName] then
		return nil
	end
	visited[normalizedName] = true

	for startIndex, fullName, argsText in source:gmatch("()local%s+function%s+([%w_%.:]+)%s*%(([^%)]*)%)") do
		if functionNameMatches(fullName, normalizedName) then
			return {
				args = TextModule.splitArgs(extractLuaFunctionArgs(source, startIndex) or argsText),
				body = extractLuaFunctionBody(source, startIndex) or "",
				line = TextModule.lineNumber(source, startIndex),
				name = fullName,
			}
		end
	end

	for startIndex, fullName, argsText in source:gmatch("()function%s+([%w_%.:]+)%s*%(([^%)]*)%)") do
		if functionNameMatches(fullName, normalizedName) then
			return {
				args = TextModule.splitArgs(extractLuaFunctionArgs(source, startIndex) or argsText),
				body = extractLuaFunctionBody(source, startIndex) or "",
				line = TextModule.lineNumber(source, startIndex),
				name = fullName,
			}
		end
	end

	for startIndex, fullName, argsText in source:gmatch("()([%w_%.:]+)%s*=%s*function%s*%(([^%)]*)%)") do
		if functionNameMatches(fullName, normalizedName) then
			return {
				args = TextModule.splitArgs(extractLuaFunctionArgs(source, startIndex) or argsText),
				body = extractLuaFunctionBody(source, startIndex) or "",
				line = TextModule.lineNumber(source, startIndex),
				name = fullName,
			}
		end
	end

	local requestedLast = normalizedName:match("([%w_]+)$")
	if requestedLast then
		for startIndex, key, argsText in source:gmatch("()([%w_]+)%s*=%s*function%s*%(([^%)]*)%)") do
			if key == requestedLast then
				return {
					args = TextModule.splitArgs(extractLuaFunctionArgs(source, startIndex) or argsText),
					body = extractLuaFunctionBody(source, startIndex) or "",
					line = TextModule.lineNumber(source, startIndex),
					name = key,
				}
			end
		end

		for startIndex, key, argsText in source:gmatch('()%["([%w_]+)"%]%s*=%s*function%s*%(([^%)]*)%)') do
			if key == requestedLast then
				return {
					args = TextModule.splitArgs(extractLuaFunctionArgs(source, startIndex) or argsText),
					body = extractLuaFunctionBody(source, startIndex) or "",
					line = TextModule.lineNumber(source, startIndex),
					name = key,
				}
			end
		end

		for startIndex, key, argsText in source:gmatch("()%['([%w_]+)'%]%s*=%s*function%s*%(([^%)]*)%)") do
			if key == requestedLast then
				return {
					args = TextModule.splitArgs(extractLuaFunctionArgs(source, startIndex) or argsText),
					body = extractLuaFunctionBody(source, startIndex) or "",
					line = TextModule.lineNumber(source, startIndex),
					name = key,
				}
			end
		end
	end

	for fullName, localName in source:gmatch("([%w_%.:]+)%s*=%s*([%w_]+)") do
		if functionNameMatches(fullName, normalizedName) then
			local resolved = findNamedFunctionBody(source, localName, visited)
			if resolved then
				resolved.name = fullName .. " -> " .. tostring(resolved.name or localName)
				return resolved
			end
		end
	end

	for aliasName, qualifiedName in source:gmatch("local%s+([%w_]+)%s*=%s*([%a_][%w_%.:]+)") do
		if functionNameMatches(aliasName, normalizedName) and not functionNameMatches(aliasName, qualifiedName) then
			local resolved = findNamedFunctionBody(source, qualifiedName, visited)
			if resolved then
				resolved.name = aliasName .. " -> " .. tostring(resolved.name or qualifiedName)
				return resolved
			end
		end
	end

	return nil
end

local function findExactQualifiedFunctionBody(source, requestedName)
	local normalizedName = TextModule.normalizeRequireExpression(requestedName or ""):gsub(":", ".")
	local requestedRoot, requestedMethod = normalizedName:match("^(.*)%.([%w_]+)$")
	if not requestedRoot or not requestedMethod then
		return nil
	end

	local function buildCandidate(startIndex, argsText, name, implicitSelf)
		return {
			args = TextModule.splitArgs(extractLuaFunctionArgs(source, startIndex) or argsText),
			body = extractLuaFunctionBody(source, startIndex) or "",
			line = TextModule.lineNumber(source, startIndex),
			name = name,
			implicitSelf = implicitSelf == true,
		}
	end

	for startIndex, fullName, argsText in source:gmatch("()local%s+function%s+([%w_%.:]+)%s*%(([^%)]*)%)") do
		if functionNameMatches(fullName, normalizedName) then
			return buildCandidate(startIndex, argsText, fullName, fullName:find(":", 1, true) ~= nil)
		end
	end

	for startIndex, fullName, argsText in source:gmatch("()function%s+([%w_%.:]+)%s*%(([^%)]*)%)") do
		if functionNameMatches(fullName, normalizedName) then
			return buildCandidate(startIndex, argsText, fullName, fullName:find(":", 1, true) ~= nil)
		end
	end

	for startIndex, fullName, argsText in source:gmatch("()([%w_%.:]+)%s*=%s*function%s*%(([^%)]*)%)") do
		if functionNameMatches(fullName, normalizedName) then
			return buildCandidate(startIndex, argsText, fullName, false)
		end
	end

	for startIndex, rootPath, key, argsText in source:gmatch(
		'()([%w_%.:]+)%s*%[%s*"([%w_]+)"%s*%]%s*=%s*function%s*%(([^%)]*)%)'
	) do
		if functionNameMatches(rootPath, requestedRoot) and key == requestedMethod then
			return buildCandidate(startIndex, argsText, rootPath .. '["' .. key .. '"]', false)
		end
	end

	for startIndex, rootPath, key, argsText in source:gmatch(
		"()([%w_%.:]+)%s*%[%s*'([%w_]+)'%s*%]%s*=%s*function%s*%(([^%)]*)%)"
	) do
		if functionNameMatches(rootPath, requestedRoot) and key == requestedMethod then
			return buildCandidate(startIndex, argsText, rootPath .. "['" .. key .. "']", false)
		end
	end

	for fullName, localName in source:gmatch("([%w_%.:]+)%s*=%s*([%w_]+)") do
		if functionNameMatches(fullName, normalizedName) then
			local resolved = findNamedFunctionBody(source, localName)
			if resolved then
				resolved.name = fullName .. " -> " .. tostring(resolved.name or localName)
				return resolved
			end
		end
	end

	return nil
end

local function findExactDirectFunctionBody(source, requestedName)
	local normalizedName = TextModule.normalizeRequireExpression(requestedName or "")
	if normalizedName == "" or normalizedName:find("[%.:]") then
		return nil
	end

	local function buildCandidate(startIndex, argsText, name)
		return {
			args = TextModule.splitArgs(extractLuaFunctionArgs(source, startIndex) or argsText),
			body = extractLuaFunctionBody(source, startIndex) or "",
			line = TextModule.lineNumber(source, startIndex),
			name = name,
			implicitSelf = false,
		}
	end

	for startIndex, name, argsText in source:gmatch("()local%s+function%s+([%w_]+)%s*%(([^%)]*)%)") do
		if name == normalizedName then
			return buildCandidate(startIndex, argsText, name)
		end
	end

	for startIndex, name, argsText in source:gmatch("()function%s+([%w_]+)%s*%(([^%)]*)%)") do
		if name == normalizedName then
			return buildCandidate(startIndex, argsText, name)
		end
	end

	for startIndex, name, argsText in source:gmatch("()([%w_]+)%s*=%s*function%s*%(([^%)]*)%)") do
		local previousChar = startIndex > 1 and source:sub(startIndex - 1, startIndex - 1) or ""
		if name == normalizedName and not previousChar:match("[%w_%.:]") then
			return buildCandidate(startIndex, argsText, name)
		end
	end

	return nil
end

local function countMethodDefinitions(source, methodName)
	local count = 0
	local escaped = TextModule.escapePattern(methodName or "")
	for _ in tostring(source or ""):gmatch("function%s+[%w_%.:]+[:%.]" .. escaped .. "%s*%(") do
		count += 1
	end
	for _ in tostring(source or ""):gmatch("[%w_%.:]+[:%.]" .. escaped .. "%s*=%s*function%s*%(") do
		count += 1
	end
	return count
end

local function inferModuleReturnNames(source)
	local names = {}
	local depth = 0
	local index = 1

	while index <= #(source or "") do
		local word, wordStart, wordEnd = nextCodeWord(source, index)
		if not word then
			break
		end

		if word == "return" and depth == 0 then
			local name = source:sub(wordEnd + 1):match("^%s*([%w_%.]+)")
			if name and name ~= "function" and name ~= "nil" and name ~= "true" and name ~= "false" then
				names[name] = true
				local last = name:match("([%w_]+)$")
				if last then
					names[last] = true
				end
			end
		elseif word == "function" or word == "if" or word == "for" or word == "while" or word == "repeat" then
			depth += 1
		elseif word == "do" then
			local lineStart = TextModule.getLineStartIndex(source, wordStart)
			local before = source:sub(lineStart, wordStart - 1)
			if not before:find("%f[%a_]for%f[^%w_]") and not before:find("%f[%a_]while%f[^%w_]") then
				depth += 1
			end
		elseif word == "end" or word == "until" then
			depth = math.max(0, depth - 1)
		end

		index = wordEnd + 1
	end

	if next(names) == nil then
		for name in source:gmatch("return%s+([%w_%.]+)") do
			if name ~= "function"
				and name ~= "nil"
				and name ~= "true"
				and name ~= "false"
			then
				names[name] = true

				local last = name:match("([%w_]+)$")
				if last then
					names[last] = true
				end
			end
		end
	end

	return names
end

local function findMethodBody(source, methodName, preferredNames)
	local fallback = nil
	local function buildCandidate(startIndex, argsText, name)
		return {
			args = TextModule.splitArgs(extractLuaFunctionArgs(source, startIndex) or argsText),
			body = extractLuaFunctionBody(source, startIndex) or "",
			line = TextModule.lineNumber(source, startIndex),
			name = name,
		}
	end

	local function preferOrStore(candidate, tableName)
		if tableName and preferredNames and preferredNames[tableName] then
			return candidate
		end
		fallback = fallback or candidate
		return nil
	end

	for startIndex, fullName, argsText in source:gmatch("()function%s+([%w_%.:]+)%s*%(([^%)]*)%)") do
		local foundMethod = fullName:match("[:%.]([%w_]+)$") or fullName
		if foundMethod == methodName then
			local tableName = fullName:match("^(.*)[:%.][%w_]+$")
			local preferred = preferOrStore(buildCandidate(startIndex, argsText, fullName), tableName)
			if preferred then
				return preferred
			end
		end
	end

	for startIndex, fullName, argsText in source:gmatch("()([%w_%.:]+)%s*=%s*function%s*%(([^%)]*)%)") do
		local foundMethod = fullName:match("[:%.]([%w_]+)$") or fullName
		if foundMethod == methodName then
			local tableName = fullName:match("^(.*)[:%.][%w_]+$")
			local preferred = preferOrStore(buildCandidate(startIndex, argsText, fullName), tableName)
			if preferred then
				return preferred
			end
		end
	end

	for startIndex, key, argsText in source:gmatch('()%["([%w_]+)"%]%s*=%s*function%s*%(([^%)]*)%)') do
		if key == methodName then
			fallback = fallback or buildCandidate(startIndex, argsText, key)
		end
	end

	for startIndex, key, argsText in source:gmatch("()%['([%w_]+)'%]%s*=%s*function%s*%(([^%)]*)%)") do
		if key == methodName then
			fallback = fallback or buildCandidate(startIndex, argsText, key)
		end
	end

	for fullName, localName in source:gmatch("([%w_%.:]+)%s*=%s*([%w_]+)") do
		local foundMethod = fullName:match("[:%.]([%w_]+)$") or fullName
		if foundMethod == methodName then
			local resolved = findNamedFunctionBody(source, localName)
			if resolved then
				resolved.name = fullName .. " -> " .. tostring(resolved.name or localName)
				local tableName = fullName:match("^(.*)[:%.][%w_]+$")
				local preferred = preferOrStore(resolved, tableName)
				if preferred then
					return preferred
				end
			end
		end
	end

	return fallback
end

return {
	extractLuaFunctionHeader = extractLuaFunctionHeader,
	extractLuaFunctionArgs = extractLuaFunctionArgs,
	extractLuaFunctionBody = extractLuaFunctionBody,
	functionNameMatches = functionNameMatches,
	findNamedFunctionBody = findNamedFunctionBody,
	findExactQualifiedFunctionBody = findExactQualifiedFunctionBody,
	findExactDirectFunctionBody = findExactDirectFunctionBody,
	countMethodDefinitions = countMethodDefinitions,
	inferModuleReturnNames = inferModuleReturnNames,
	findMethodBody = findMethodBody,
}
