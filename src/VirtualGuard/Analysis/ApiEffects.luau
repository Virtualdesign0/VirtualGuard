local ROBLOX_API_EFFECTS = {
	["Workspace.Raycast"] = {
		kind = "query",
		returnPolicy = "derived",
	},
	["Instance.IsDescendantOf"] = {
		kind = "validator",
	},
	["Instance.Destroy"] = {
		kind = "mutation",
		receiverSensitive = true,
		sinkKind = "InstanceMutation",
	},
	["Instance.ClearAllChildren"] = {
		kind = "mutation",
		receiverSensitive = true,
		sinkKind = "InstanceMutation",
	},
	["Instance.SetAttribute"] = {
		kind = "mutation",
		receiverSensitive = true,
		sensitiveArguments = { 1, 2 },
		sinkKind = "InstanceMutation",
	},
	["PVInstance.PivotTo"] = {
		kind = "mutation",
		receiverSensitive = true,
		sensitiveArguments = { 1 },
		sinkKind = "InstanceMutation",
	},
	["Model.BreakJoints"] = {
		kind = "mutation",
		receiverSensitive = true,
		sinkKind = "InstanceMutation",
	},
	["Humanoid.TakeDamage"] = {
		kind = "sensitive",
		receiverSensitive = true,
		sensitiveArguments = { 1 },
		sinkKind = "Damage",
	},
}

local ROBLOX_API_EFFECTS_BY_METHOD = {
	BreakJoints = ROBLOX_API_EFFECTS["Model.BreakJoints"],
	ClearAllChildren = ROBLOX_API_EFFECTS["Instance.ClearAllChildren"],
	Destroy = ROBLOX_API_EFFECTS["Instance.Destroy"],
	IsDescendantOf = ROBLOX_API_EFFECTS["Instance.IsDescendantOf"],
	PivotTo = ROBLOX_API_EFFECTS["PVInstance.PivotTo"],
	Raycast = ROBLOX_API_EFFECTS["Workspace.Raycast"],
	SetAttribute = ROBLOX_API_EFFECTS["Instance.SetAttribute"],
	TakeDamage = ROBLOX_API_EFFECTS["Humanoid.TakeDamage"],
}

return {
	ROBLOX_API_EFFECTS = ROBLOX_API_EFFECTS,
	ROBLOX_API_EFFECTS_BY_METHOD = ROBLOX_API_EFFECTS_BY_METHOD,
}
