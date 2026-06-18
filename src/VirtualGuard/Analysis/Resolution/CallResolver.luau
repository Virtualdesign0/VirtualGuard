local ApiEffectsModule = require(script.Parent.Parent.ApiEffects)
local ConfigModule = require(script.Parent.Parent.Parent.Config)
local LexerModule = require(script.Parent.Parent.Parsing.Lexer)
local TextModule = require(script.Parent.Parent.Parent.Shared.Text)

local CallSyntaxModule = require(script.Parent.Parent.Parsing.CallSyntax)
local FunctionResolverModule = require(script.Parent.FunctionResolver)

local nextCodeWord = CallSyntaxModule.nextCodeWord
local findMatchingParen = CallSyntaxModule.findMatchingParen
local isDirectCallExpression = CallSyntaxModule.isDirectCallExpression
local getDirectCallArgs = CallSyntaxModule.getDirectCallArgs
local isTrustedNumericBound = CallSyntaxModule.isTrustedNumericBound
local hasArithmeticOrConcat = CallSyntaxModule.hasArithmeticOrConcat
local hasConcat = CallSyntaxModule.hasConcat
local balanceDelta = CallSyntaxModule.balanceDelta
local shouldContinueStatement = CallSyntaxModule.shouldContinueStatement
local extractLuaFunctionHeader = FunctionResolverModule.extractLuaFunctionHeader
local extractLuaFunctionArgs = FunctionResolverModule.extractLuaFunctionArgs
local extractLuaFunctionBody = FunctionResolverModule.extractLuaFunctionBody
local functionNameMatches = FunctionResolverModule.functionNameMatches
local findNamedFunctionBody = FunctionResolverModule.findNamedFunctionBody
local findExactQualifiedFunctionBody = FunctionResolverModule.findExactQualifiedFunctionBody
local findExactDirectFunctionBody = FunctionResolverModule.findExactDirectFunctionBody
local countMethodDefinitions = FunctionResolverModule.countMethodDefinitions
local inferModuleReturnNames = FunctionResolverModule.inferModuleReturnNames
local findMethodBody = FunctionResolverModule.findMethodBody

local extractAliasMethodCalls

extractAliasMethodCalls = function(source, alias)
	local calls = {}
	local searchIndex = 1
	local aliasPattern = "%f[%w_]" .. TextModule.escapePattern(alias) .. "%f[^%w_]"
	source = source or ""

	while true do
		local aliasStart, aliasEnd = source:find(aliasPattern, searchIndex)
		if not aliasStart then
			break
		end

		local index = aliasEnd + 1
		while index <= #source and source:sub(index, index):match("%s") do
			index += 1
		end

		local separator = source:sub(index, index)
		if separator ~= ":" and separator ~= "." then
			searchIndex = aliasEnd + 1
			continue
		end

		local methodStart = index + 1
		local method = source:sub(methodStart):match("^([%w_]+)")
		if not method then
			searchIndex = index + 1
			continue
		end

		index = methodStart + #method
		while index <= #source and source:sub(index, index):match("%s") do
			index += 1
		end

		if source:sub(index, index) ~= "(" then
			searchIndex = index
			continue
		end

		local closeIndex = findMatchingParen(source, index)
		if closeIndex then
			table.insert(calls, {
				alias = alias,
				separator = separator,
				method = method,
				argsText = source:sub(index + 1, closeIndex - 1),
				startIndex = aliasStart,
				openIndex = index,
				closeIndex = closeIndex,
			})
			searchIndex = closeIndex + 1
		else
			searchIndex = index + 1
		end
	end

	return calls
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
	source = source or ""

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
				startIndex = nameStart,
				openIndex = openIndex,
				closeIndex = closeIndex,
			})
			searchIndex = nameEnd + 1
		else
			searchIndex = (openIndex or nameEnd) + 1
		end
	end

	return calls
end

local function extractQualifiedCalls(source)
	local calls = {}
	local searchIndex = 1
	source = source or ""

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
				startIndex = startIndex,
				openIndex = openIndex,
				closeIndex = closeIndex,
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
					openIndex = openIndex,
					closeIndex = closeIndex,
				})
			end
		end
	end

	return calls
end

local function canonicalizeStateBindingPath(state, path)
	local current = tostring(path or "")
	local visited = {}
	for _ = 1, 8 do
		local first, rest = current:match("^([%w_]+)%.?(.*)$")
		if not first or visited[first] then
			break
		end
		visited[first] = true
		local binding = state and state.bindings and state.bindings[first]
		if not binding then
			break
		end
		if binding.kind == "unknown" or not binding.target then
			return current, true
		end
		current = tostring(binding.target) .. (rest ~= "" and ("." .. rest) or "")
	end
	return current, false
end

local function normalizeRobloxApiRoot(doc, call, state)
	local rootPath = tostring(call and (call.rootPath or call.root) or "")
	local statePath, stateBlocked = canonicalizeStateBindingPath(state, rootPath)
	if stateBlocked then
		return rootPath
	end
	rootPath = statePath
	local first, rest = rootPath:match("^([%w_]+)%.?(.*)$")
	if not first then
		return rootPath
	end

	local normalizedFirst = first == "workspace" and "Workspace" or first
	if doc and doc.serviceAliases and doc.serviceAliases[first] then
		normalizedFirst = doc.serviceAliases[first]
	elseif doc and doc.pathAliases and doc.pathAliases[first] then
		local aliasTarget = doc.pathAliases[first]
		if typeof(aliasTarget) == "string" then
			local aliasRoot, aliasRest = aliasTarget:match("^([^%.]+)%.?(.*)$")
			if aliasRoot then
				normalizedFirst = aliasRoot
				rest = aliasRest ~= "" and (aliasRest .. (rest ~= "" and ("." .. rest) or "")) or rest
			end
		elseif typeof(aliasTarget) == "Instance" then
			normalizedFirst = aliasTarget.ClassName
		end
	end

	return normalizedFirst .. (rest ~= "" and ("." .. rest) or "")
end

local function getRobloxApiEffect(call, doc, state)
	if not call then
		return nil
	end
	local normalizedRoot = normalizeRobloxApiRoot(doc, call, state)
	local exact = ApiEffectsModule.ROBLOX_API_EFFECTS[normalizedRoot .. "." .. tostring(call.method or "")]
	if exact then
		return exact, "exact"
	end

	local fallback = ApiEffectsModule.ROBLOX_API_EFFECTS_BY_METHOD[call.method]
	return fallback, fallback and "method" or nil
end

local function sourceShadowsRoot(source, root)
	root = tostring(root or "")
	if root == "" then
		return false
	end
	local escaped = TextModule.escapePattern(root)
	local code = TextModule.stripStringsForAnalysis(TextModule.stripComments(source or ""))
	if code:find("%f[%w_]local%s+" .. escaped .. "%f[^%w_]") then
		return true
	end
	if code:find("%f[%w_]function%s+[%w_%.:]*%s*%([^%)]*%f[%w_]" .. escaped .. "%f[^%w_][^%)]*%)") then
		return true
	end
	for line in code:gmatch("[^\r\n]+") do
		if line:find("^%s*" .. escaped .. "%s*=")
			or line:find("^%s*" .. escaped .. "%s*:%s*[^=]+=") then
			return true
		end
	end
	return false
end

local function canonicalizeSymbolName(doc, name, state)
	local canonicalName, stateBlocked = canonicalizeStateBindingPath(state, name)
	if stateBlocked then
		return tostring(name or "")
	end
	local visited = {}
	for _ = 1, 8 do
		if doc and doc.ambiguousSymbolAliases and doc.ambiguousSymbolAliases[canonicalName] then
			break
		end
		if doc and (
			(doc.serviceAliases and doc.serviceAliases[canonicalName])
			or (doc.pathAliases and doc.pathAliases[canonicalName])
			or (doc.aliasTargets and doc.aliasTargets[canonicalName])
		) then
			break
		end
		if visited[canonicalName] then
			break
		end
		visited[canonicalName] = true
		local aliasTarget = doc and doc.symbolAliases and doc.symbolAliases[canonicalName]
		if not aliasTarget then
			break
		end
		local aliasRoot = tostring(aliasTarget):match("^([%w_]+)")
		if aliasRoot and doc and doc.ambiguousSymbolAliases and doc.ambiguousSymbolAliases[aliasRoot] then
			break
		end
		canonicalName = tostring(aliasTarget)
	end
	return canonicalName
end

local function canonicalizeCall(doc, call, state)
	if not call then
		return call
	end

	local originalRootPath = tostring(call.rootPath or call.root or "")
	local rootPath, stateBlocked = canonicalizeStateBindingPath(state, originalRootPath)
	if stateBlocked then
		return call
	end
	local first, rest = rootPath:match("^([%w_]+)%.?(.*)$")
	if not first then
		return call
	end

	local canonicalFirst = first
	local visited = {}
	for _ = 1, 8 do
		if doc and doc.ambiguousSymbolAliases and doc.ambiguousSymbolAliases[canonicalFirst] then
			break
		end
		if doc and (
			(doc.serviceAliases and doc.serviceAliases[canonicalFirst])
			or (doc.pathAliases and doc.pathAliases[canonicalFirst])
			or (doc.aliasTargets and doc.aliasTargets[canonicalFirst])
		) then
			break
		end
		if visited[canonicalFirst] then
			break
		end
		visited[canonicalFirst] = true
		local aliasTarget = doc and doc.symbolAliases and doc.symbolAliases[canonicalFirst]
		if not aliasTarget then
			break
		end
		local aliasFirst, aliasRest = tostring(aliasTarget):match("^([%w_]+)%.?(.*)$")
		if not aliasFirst then
			break
		end
		if doc and doc.ambiguousSymbolAliases and doc.ambiguousSymbolAliases[aliasFirst] then
			break
		end
		canonicalFirst = aliasFirst
		if aliasRest ~= "" then
			rest = aliasRest .. (rest ~= "" and ("." .. rest) or "")
		end
	end

	if canonicalFirst == first and rootPath == originalRootPath then
		return call
	end

	local canonicalRootPath = canonicalFirst .. (rest ~= "" and ("." .. rest) or "")
	local canonicalCall = {}
	for key, value in pairs(call) do
		canonicalCall[key] = value
	end
	canonicalCall.root = canonicalFirst
	canonicalCall.rootPath = canonicalRootPath
	canonicalCall.name = canonicalRootPath .. tostring(call.separator or ".") .. tostring(call.method or "")
	return canonicalCall
end

local function resolveCustomMethod(source, call)
	if not call then
		return nil
	end

	local helper = findExactQualifiedFunctionBody(source or "", call.name)
	if not helper and call.root == "self" then
		if countMethodDefinitions(source or "", call.method) == 1 then
			helper = findMethodBody(source or "", call.method, nil)
		end
	end
	return helper
end

local resolveRobloxApiEffect

local function resolveDirectCallable(source, doc, name, state)
	local resolvedName = canonicalizeSymbolName(doc, name, state)
	local rootPath, method = resolvedName:match("^(.*)%.([%w_]+)$")
	if rootPath and method then
		local root = rootPath:match("^([%w_]+)") or rootPath
		local helper = findExactQualifiedFunctionBody(source or "", resolvedName)
		if helper then
			return {
				kind = "same-file-function",
				name = name,
				resolvedName = resolvedName,
				helper = helper,
				functionAlias = true,
			}
		end

		local moduleTarget = doc and doc.aliasTargets and doc.aliasTargets[root]
		if moduleTarget then
			return {
				kind = "module-method",
				name = name,
				resolvedName = resolvedName,
				root = root,
				rootPath = rootPath,
				method = method,
				target = moduleTarget,
			}
		end

		local syntheticCall = {
			root = root,
			rootPath = rootPath,
			separator = ".",
			method = method,
			name = resolvedName,
		}
		local effect, effectResolution = resolveRobloxApiEffect(source, doc, syntheticCall, nil, state)
		if effect and effectResolution == "exact" then
			return {
				kind = "roblox-method",
				name = name,
				resolvedName = resolvedName,
				root = root,
				rootPath = rootPath,
				method = method,
				effect = effect,
				effectResolution = effectResolution,
			}
		end
		if effect then
			return {
				kind = "roblox-method-hint",
				name = name,
				resolvedName = resolvedName,
				root = root,
				rootPath = rootPath,
				method = method,
				effect = effect,
				effectResolution = effectResolution,
			}
		end

		return {
			kind = "unresolved",
			name = name,
			resolvedName = resolvedName,
		}
	end

	local helper = findExactDirectFunctionBody(source or "", resolvedName)
	return {
		kind = helper and "same-file-function" or "unresolved",
		name = name,
		resolvedName = resolvedName,
		helper = helper,
		functionAlias = false,
	}
end

local function resolveDirectFunctionValue(source, doc, name, state)
	local callable = resolveDirectCallable(source, doc, name, state)
	if callable.kind == "same-file-function" then
		return callable.helper, callable.resolvedName, callable.functionAlias
	end
	return nil, callable.resolvedName, false
end

resolveRobloxApiEffect = function(source, doc, call, customHelper, state)

	if customHelper then
		return nil, "custom"
	end
	if doc and doc.aliasTargets and doc.aliasTargets[call.root] then
		return nil, "module"
	end
	local effect, resolution = getRobloxApiEffect(call, doc, state)
	local knownServiceAlias = doc
		and doc.serviceAliases
		and doc.serviceAliases[call.root] ~= nil
	local knownPathAlias = doc
		and doc.pathAliases
		and doc.pathAliases[call.root] ~= nil
	if resolution == "exact"
		and sourceShadowsRoot(source, call.root)
		and not knownServiceAlias
		and not knownPathAlias
	then
		effect = ApiEffectsModule.ROBLOX_API_EFFECTS_BY_METHOD[call.method]
		resolution = effect and "method" or nil
	end
	return effect, resolution
end

local function findQualifiedCallForNameFallback(code, callName, nameCall)
	for _, qualifiedCall in ipairs(extractQualifiedCalls(code or "")) do
		if qualifiedCall.method == callName and qualifiedCall.openIndex == nameCall.openIndex then
			return qualifiedCall
		end
	end
	return nil
end

local function shouldApplyNameBasedSinkFallback(source, doc, code, callName, nameCall)
	local qualifiedCall = findQualifiedCallForNameFallback(code, callName, nameCall)
	if qualifiedCall then
		local resolvedCall = canonicalizeCall(doc, qualifiedCall)
		local helper = resolveCustomMethod(source, resolvedCall)
		if helper then
			return false
		end
		if doc and doc.aliasTargets and doc.aliasTargets[resolvedCall.root] then
			return false
		end
		local _, resolution = resolveRobloxApiEffect(source, doc, resolvedCall, helper)
		return resolution ~= "exact"
	end

	local callable = resolveDirectCallable(source, doc, callName)
	if callable.kind ~= "unresolved" then
		return false
	end
	return true
end

local function findReturnedFunctionBody(source)
	source = source or ""
	local startIndex = source:find("return%s+function%s*%(")
	if not startIndex then
		return nil
	end
	local functionIndex = source:find("function", startIndex, true)
	if not functionIndex then
		return nil
	end
	return {
		args = TextModule.splitArgs(extractLuaFunctionArgs(source, functionIndex) or ""),
		body = extractLuaFunctionBody(source, functionIndex) or "",
		line = TextModule.lineNumber(source, functionIndex),
		name = "return function",
	}
end

local function helperBodyReferencesFreeName(body, name)
	local tokens = LexerModule.FlowLexer.lex(body or "")
	local scopes = {
		{ locals = {} },
	}
	local declarationTokens = {}
	local pendingForLocals = nil
	local pendingDeclarations = {}
	local pendingUntilEndIndex = nil

	local function currentScope()
		return scopes[#scopes]
	end

	local function pushScope(locals)
		table.insert(scopes, {
			locals = locals or {},
		})
	end

	local function popScope()
		if #scopes > 1 then
			table.remove(scopes)
		end
	end

	local function isShadowed()
		for index = #scopes, 1, -1 do
			if scopes[index].locals[name] then
				return true
			end
		end
		return false
	end

	local function tokenContinuesStatement(previous, current)
		if not previous or not current then
			return false
		end
		local continuationValues = {
			["("] = true,
			["["] = true,
			["{"] = true,
			[","] = true,
			["."] = true,
			[":"] = true,
			["="] = true,
			["+="] = true,
			["-="] = true,
			["*="] = true,
			["/="] = true,
			["+"] = true,
			["-"] = true,
			["*"] = true,
			["/"] = true,
			["%"] = true,
			[".."] = true,
			["and"] = true,
			["or"] = true,
			["not"] = true,
		}
		return continuationValues[previous.value] == true
			or continuationValues[current.value] == true
			or previous.kind == "operator"
			or current.kind == "operator"
	end

	local function findStatementEndIndex(startIndex)
		local depth = 0
		local blockStack = {}
		local pendingLoopDo = 0
		local previous = nil
		local function isIfExpression(cursor)
			local before = tokens[cursor - 1]
			if not before then
				return false
			end
			return before.value == "="
				or before.value == "return"
				or before.value == "("
				or before.value == "["
				or before.value == "{"
				or before.value == ","
				or before.value == "then"
				or before.value == "else"
				or before.value == "and"
				or before.value == "or"
				or before.kind == "operator"
		end
		for cursor = startIndex, #tokens do
			local current = tokens[cursor]
			if current.kind == "eof" then
				return cursor - 1
			end
			if cursor > startIndex
				and depth == 0
				and #blockStack == 0
				and current.value == ";"
			then
				return cursor
			end
			if cursor > startIndex
				and depth == 0
				and #blockStack == 0
				and previous
				and current.line > previous.line
				and not tokenContinuesStatement(previous, current)
			then
				return cursor - 1
			end
			if current.value == "(" or current.value == "[" or current.value == "{" then
				depth += 1
			elseif current.value == ")" or current.value == "]" or current.value == "}" then
				depth = math.max(0, depth - 1)
			elseif current.kind == "keyword" then
				if current.value == "function" then
					table.insert(blockStack, current.value)
				elseif current.value == "if" and not isIfExpression(cursor) then
					table.insert(blockStack, current.value)
				elseif current.value == "for" or current.value == "while" then
					table.insert(blockStack, current.value)
					pendingLoopDo += 1
				elseif current.value == "repeat" then
					table.insert(blockStack, current.value)
				elseif current.value == "do" then
					if pendingLoopDo > 0 then
						pendingLoopDo -= 1
					else
						table.insert(blockStack, current.value)
					end
				elseif current.value == "end" then
					if #blockStack > 0 and blockStack[#blockStack] ~= "repeat" then
						table.remove(blockStack)
					end
				elseif current.value == "until" then
					if #blockStack > 0 and blockStack[#blockStack] == "repeat" then
						table.remove(blockStack)
					end
				end
			end
			previous = current
		end
		return #tokens
	end

	local function activatePendingDeclarations(index)
		for pendingIndex = #pendingDeclarations, 1, -1 do
			local pending = pendingDeclarations[pendingIndex]
			if index > pending.endIndex then
				for localName in pairs(pending.names) do
					pending.scope.locals[localName] = true
				end
				table.remove(pendingDeclarations, pendingIndex)
			end
		end
	end

	local index = 1
	while index <= #tokens do
		local token = tokens[index]
		local value = token.value
		activatePendingDeclarations(index)
		if pendingUntilEndIndex and index > pendingUntilEndIndex then
			popScope()
			pendingUntilEndIndex = nil
		end

		if token.kind == "keyword" and value == "local" then
			local cursor = index + 1
			if tokens[cursor] and tokens[cursor].value == "function" then
				cursor += 1
				if tokens[cursor] and tokens[cursor].kind == "identifier" then
					declarationTokens[cursor] = true
					currentScope().locals[tokens[cursor].value] = true
				end
			else
				local declaredNames = {}
				while tokens[cursor] and tokens[cursor].kind == "identifier" do
					declarationTokens[cursor] = true
					declaredNames[tokens[cursor].value] = true
					cursor += 1
					if not (tokens[cursor] and tokens[cursor].value == ",") then
						break
					end
					cursor += 1
				end
				local statementEnd = findStatementEndIndex(cursor)
				table.insert(pendingDeclarations, {
					names = declaredNames,
					scope = currentScope(),
					endIndex = statementEnd,
				})
			end
		elseif token.kind == "keyword" and value == "for" then
			pendingForLocals = {}
			local cursor = index + 1
			while tokens[cursor]
				and tokens[cursor].value ~= "="
				and tokens[cursor].value ~= "in"
				and tokens[cursor].kind ~= "eof"
			do
				if tokens[cursor].kind == "identifier" then
					pendingForLocals[tokens[cursor].value] = true
					declarationTokens[cursor] = true
				end
				cursor += 1
			end
		elseif token.kind == "keyword" and value == "function" then
			local functionLocals = {}
			local cursor = index + 1
			while tokens[cursor] and tokens[cursor].value ~= "(" and tokens[cursor].kind ~= "eof" do
				if tokens[cursor].kind == "identifier" then
					declarationTokens[cursor] = true
				end
				cursor += 1
			end
			cursor += 1
			while tokens[cursor] and tokens[cursor].value ~= ")" and tokens[cursor].kind ~= "eof" do
				if tokens[cursor].kind == "identifier" then
					functionLocals[tokens[cursor].value] = true
					declarationTokens[cursor] = true
				end
				cursor += 1
			end
			pushScope(functionLocals)
		elseif token.kind == "keyword" and (value == "then" or value == "do" or value == "repeat") then
			if value == "do" and pendingForLocals then
				pushScope(pendingForLocals)
				pendingForLocals = nil
			else
				pushScope()
			end
		elseif token.kind == "keyword" and value == "else" then
			popScope()
			pushScope()
		elseif token.kind == "keyword" and value == "elseif" then
			popScope()
		elseif token.kind == "keyword" and value == "end" then
			popScope()
		elseif token.kind == "keyword" and value == "until" then
			pendingUntilEndIndex = findStatementEndIndex(index + 1)
		elseif token.kind == "identifier" and value == name and not declarationTokens[index] then
			local previous = tokens[index - 1]
			if not (previous and (previous.value == "." or previous.value == ":")) and not isShadowed() then
				return true
			end
		end

		index += 1
	end

	return false
end

return {
	balanceDelta = balanceDelta,
	canonicalizeCall = canonicalizeCall,
	canonicalizeStateBindingPath = canonicalizeStateBindingPath,
	canonicalizeSymbolName = canonicalizeSymbolName,
	countMethodDefinitions = countMethodDefinitions,
	extractAliasMethodCalls = extractAliasMethodCalls,
	extractIdentifierCalls = extractIdentifierCalls,
	extractLuaFunctionArgs = extractLuaFunctionArgs,
	extractLuaFunctionBody = extractLuaFunctionBody,
	extractLuaFunctionHeader = extractLuaFunctionHeader,
	extractQualifiedCalls = extractQualifiedCalls,
	findExactDirectFunctionBody = findExactDirectFunctionBody,
	findExactQualifiedFunctionBody = findExactQualifiedFunctionBody,
	findMatchingParen = findMatchingParen,
	findMethodBody = findMethodBody,
	findNamedFunctionBody = findNamedFunctionBody,
	findQualifiedCallForNameFallback = findQualifiedCallForNameFallback,
	findReturnedFunctionBody = findReturnedFunctionBody,
	functionNameMatches = functionNameMatches,
	getDirectCallArgs = getDirectCallArgs,
	getRobloxApiEffect = getRobloxApiEffect,
	hasArithmeticOrConcat = hasArithmeticOrConcat,
	hasConcat = hasConcat,
	helperBodyReferencesFreeName = helperBodyReferencesFreeName,
	inferModuleReturnNames = inferModuleReturnNames,
	isDirectCallExpression = isDirectCallExpression,
	isTrustedNumericBound = isTrustedNumericBound,
	nextCodeWord = nextCodeWord,
	normalizeRobloxApiRoot = normalizeRobloxApiRoot,
	resolveCustomMethod = resolveCustomMethod,
	resolveDirectCallable = resolveDirectCallable,
	resolveDirectFunctionValue = resolveDirectFunctionValue,
	resolveRobloxApiEffect = resolveRobloxApiEffect,
	shouldApplyNameBasedSinkFallback = shouldApplyNameBasedSinkFallback,
	shouldContinueStatement = shouldContinueStatement,
	sourceShadowsRoot = sourceShadowsRoot,
}
