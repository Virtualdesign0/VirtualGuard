local TextModule = require(script.Parent.Parent.Parent.Shared.Text)

local CFGBuilder = {}
function CFGBuilder.new(budgets, context)
	return setmetatable({
		nextId = 0,
		nextScopeId = 0,
		blocks = {},
		budgets = budgets,
		context = context,
	}, {
		__index = CFGBuilder,
	})
end

function CFGBuilder:createBlock()
	if TextModule.hasExceededCfgDeadline(self.context) then
		error("CFG deadline exceeded")
	end
	self.nextId += 1
	if self.nextId > self.budgets.maxBlocks then
		error("CFG block budget exceeded")
	end
	self.blocks[self.nextId] = {
		id = self.nextId,
		statements = {},
		successors = {},
		predecessors = {},
	}
	return self.nextId
end

function CFGBuilder:createScope()
	self.nextScopeId += 1
	return self.nextScopeId
end

local function appendScope(scopeStack, scopeId)
	local result = {}
	for _, existing in ipairs(scopeStack or {}) do
		table.insert(result, existing)
	end
	table.insert(result, scopeId)
	return result
end

local function scopesAfterDepth(scopeStack, depth)
	local result = {}
	for index = #(scopeStack or {}), (depth or 0) + 1, -1 do
		table.insert(result, scopeStack[index])
	end
	return result
end

function CFGBuilder:addEdge(fromId, toId, kind, condition, scopeChanges)
	if not fromId or not toId or not self.blocks[fromId] or not self.blocks[toId] then
		return
	end
	table.insert(self.blocks[fromId].successors, {
		to = toId,
		kind = kind or "normal",
		condition = condition,
		scopeEnters = scopeChanges and scopeChanges.enters or nil,
		scopeExits = scopeChanges and scopeChanges.exits or nil,
	})
	table.insert(self.blocks[toId].predecessors, fromId)
end

function CFGBuilder:buildSequence(statements, startBlockId, exitBlockId, loopContext, scopeStack)
	local currentId = startBlockId
	scopeStack = scopeStack or {}
	for _, statement in ipairs(statements or {}) do
		if statement.kind == "Simple" then
			table.insert(self.blocks[currentId].statements, statement)
		elseif statement.kind == "FunctionDeclaration" then

		elseif statement.kind == "If" then
			currentId = self:buildIf(statement, currentId, exitBlockId, loopContext, scopeStack)
		elseif statement.kind == "While" then
			currentId = self:buildWhile(statement, currentId, exitBlockId, loopContext, scopeStack)
		elseif statement.kind == "Repeat" then
			currentId = self:buildRepeat(statement, currentId, exitBlockId, loopContext, scopeStack)
		elseif statement.kind == "Do" then
			currentId = self:buildDo(statement, currentId, exitBlockId, loopContext, scopeStack)
		elseif statement.kind == "Return" then
			table.insert(self.blocks[currentId].statements, statement)
			self:addEdge(currentId, exitBlockId, "return")
			currentId = self:createBlock()
		elseif statement.kind == "Break" then
			if loopContext then
				self:addEdge(currentId, loopContext.breakTarget, "break", nil, {
					exits = scopesAfterDepth(scopeStack, loopContext.scopeDepth),
				})
			end
			currentId = self:createBlock()
		elseif statement.kind == "Continue" then
			if loopContext then
				self:addEdge(currentId, loopContext.continueTarget, "continue", nil, {
					exits = scopesAfterDepth(scopeStack, loopContext.continueScopeDepth or loopContext.scopeDepth),
				})
			end
			currentId = self:createBlock()
		end
	end
	return currentId
end

function CFGBuilder:buildIf(statement, currentId, exitId, loopContext, scopeStack)
	local thenEntry = self:createBlock()
	local joinId = self:createBlock()
	local falseTarget = (#statement.elseifBranches > 0 or statement.elseBody) and self:createBlock() or joinId
	local thenScope = self:createScope()
	self:addEdge(currentId, thenEntry, "true", statement.condition, {
		enters = { thenScope },
	})
	self:addEdge(currentId, falseTarget, "false", statement.condition)
	local thenEnd = self:buildSequence(statement.thenBody, thenEntry, exitId, loopContext, appendScope(scopeStack, thenScope))
	self:addEdge(thenEnd, joinId, "normal", nil, {
		exits = { thenScope },
	})

	local branchCursor = falseTarget
	for _, branch in ipairs(statement.elseifBranches) do
		local branchEntry = self:createBlock()
		local nextFalse = self:createBlock()
		local branchScope = self:createScope()
		self:addEdge(branchCursor, branchEntry, "true", branch.condition, {
			enters = { branchScope },
		})
		self:addEdge(branchCursor, nextFalse, "false", branch.condition)
		local branchEnd = self:buildSequence(branch.body, branchEntry, exitId, loopContext, appendScope(scopeStack, branchScope))
		self:addEdge(branchEnd, joinId, "normal", nil, {
			exits = { branchScope },
		})
		branchCursor = nextFalse
	end

	if statement.elseBody then
		local elseEntry = self:createBlock()
		local elseScope = self:createScope()
		self:addEdge(branchCursor, elseEntry, "normal", nil, {
			enters = { elseScope },
		})
		local elseEnd = self:buildSequence(statement.elseBody, elseEntry, exitId, loopContext, appendScope(scopeStack, elseScope))
		self:addEdge(elseEnd, joinId, "normal", nil, {
			exits = { elseScope },
		})
	elseif branchCursor ~= joinId then
		self:addEdge(branchCursor, joinId, "normal")
	end
	return joinId
end

function CFGBuilder:buildWhile(statement, currentId, exitId, outerLoop, scopeStack)
	local conditionId = self:createBlock()
	local bodyId = self:createBlock()
	local afterId = self:createBlock()
	local bodyScope = self:createScope()
	self:addEdge(currentId, conditionId, "normal")
	self:addEdge(conditionId, bodyId, "true", statement.condition, {
		enters = { bodyScope },
	})
	self:addEdge(conditionId, afterId, "false", statement.condition)
	local bodyEnd = self:buildSequence(statement.body, bodyId, exitId, {
		breakTarget = afterId,
		continueTarget = conditionId,
		parent = outerLoop,
		scopeDepth = #(scopeStack or {}),
		continueScopeDepth = #(scopeStack or {}),
	}, appendScope(scopeStack, bodyScope))
	self:addEdge(bodyEnd, conditionId, "loop", nil, {
		exits = { bodyScope },
	})
	return afterId
end

function CFGBuilder:buildRepeat(statement, currentId, exitId, outerLoop, scopeStack)
	local bodyId = self:createBlock()
	local conditionId = self:createBlock()
	local afterId = self:createBlock()
	local bodyScope = self:createScope()
	self:addEdge(currentId, bodyId, "normal", nil, {
		enters = { bodyScope },
	})
	local bodyEnd = self:buildSequence(statement.body, bodyId, exitId, {
		breakTarget = afterId,
		continueTarget = conditionId,
		parent = outerLoop,
		scopeDepth = #(scopeStack or {}),
		continueScopeDepth = #(scopeStack or {}) + 1,
	}, appendScope(scopeStack, bodyScope))
	self:addEdge(bodyEnd, conditionId, "normal")
	self:addEdge(conditionId, afterId, "true", statement.condition, {
		exits = { bodyScope },
	})
	self:addEdge(conditionId, bodyId, "false", statement.condition, {
		exits = { bodyScope },
		enters = { bodyScope },
	})
	return afterId
end

function CFGBuilder:buildDo(statement, currentId, exitId, loopContext, scopeStack)
	local bodyId = self:createBlock()
	local afterId = self:createBlock()
	local bodyScope = self:createScope()
	self:addEdge(currentId, bodyId, "normal", nil, {
		enters = { bodyScope },
	})
	local bodyEnd = self:buildSequence(statement.body, bodyId, exitId, loopContext, appendScope(scopeStack, bodyScope))
	self:addEdge(bodyEnd, afterId, "normal", nil, {
		exits = { bodyScope },
	})
	return afterId
end

function CFGBuilder.build(statements, budgets, context)
	local builder = CFGBuilder.new(budgets, context)
	local entryId = builder:createBlock()
	local exitId = builder:createBlock()
	local endId = builder:buildSequence(statements, entryId, exitId, nil, {})
	builder:addEdge(endId, exitId, "normal")
	return {
		entry = entryId,
		exit = exitId,
		blocks = builder.blocks,
	}
end

return {
	appendScope = appendScope,
	CFGBuilder = CFGBuilder,
	scopesAfterDepth = scopesAfterDepth,
}
