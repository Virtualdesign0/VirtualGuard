local EFFECTS = {
	Destroy = {
		kind = "mutation",
		receiverSensitive = true,
		sinkKind = "InstanceMutation",
	},
	IsDescendantOf = {
		kind = "validator",
	},
	Raycast = {
		kind = "query",
	},
	SetAttribute = {
		kind = "mutation",
		receiverSensitive = true,
		sensitiveArguments = { 1, 2 },
		sinkKind = "InstanceMutation",
	},
	TakeDamage = {
		kind = "sensitive",
		receiverSensitive = true,
		sensitiveArguments = { 1 },
		sinkKind = "Damage",
	},
}

local function isTainted(expression, taints)
	for name in pairs(taints) do
		if expression:find("%f[%w_]" .. name .. "%f[^%w_]") then
			return true
		end
	end
	return false
end

local function inspectCall(receiver, method, args, taints)
	local effect = EFFECTS[method]
	if not effect or effect.kind == "query" or effect.kind == "validator" then
		return nil
	end
	if effect.receiverSensitive and isTainted(receiver, taints) then
		return effect.sinkKind, "receiver"
	end
	for _, index in ipairs(effect.sensitiveArguments or {}) do
		if isTainted(args[index] or "", taints) then
			return effect.sinkKind, "argument"
		end
	end
	return nil
end

local taints = {
	target = true,
	damage = true,
}

local kind, operand = inspectCall("target", "Destroy", {}, taints)
assert(kind == "InstanceMutation" and operand == "receiver")

kind, operand = inspectCall("serverTarget", "SetAttribute", { '"Owner"', "target" }, taints)
assert(kind == "InstanceMutation" and operand == "argument")

kind, operand = inspectCall("humanoid", "TakeDamage", { "damage" }, taints)
assert(kind == "Damage" and operand == "argument")

assert(inspectCall("workspace", "Raycast", { "origin", "direction" }, taints) == nil)
assert(inspectCall("target", "IsDescendantOf", { "folder" }, taints) == nil)

local function shadowsRoot(source, root)
	if source:find("%f[%w_]local%s+" .. root .. "%f[^%w_]") then
		return true
	end
	if source:find("%f[%w_]function%s+[%w_%.:]*%s*%([^%)]*%f[%w_]" .. root .. "%f[^%w_][^%)]*%)") then
		return true
	end
	for line in source:gmatch("[^\r\n]+") do
		if line:find("^%s*" .. root .. "%s*=") then
			return true
		end
	end
	return false
end

assert(shadowsRoot("local task = CustomController", "task"))
assert(shadowsRoot("local math: any = DamageController", "math"))
assert(shadowsRoot("math = DamageController", "math"))
assert(shadowsRoot("local function run(task)\n task:Execute(payload)\nend", "task"))
assert(not shadowsRoot("task.wait()", "task"))

local context = {
	cfgDeadline = os.clock() - 1,
}
assert(os.clock() >= context.cfgDeadline)

print("RobloxApiEffects regression test passed")
