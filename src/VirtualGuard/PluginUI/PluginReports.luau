local PluginReports = {}

function PluginReports.readWatchReport(ConfigModule)
	local rootFolder = ConfigModule.ReplicatedStorage:FindFirstChild("VirtualGuardWatch")
	if not rootFolder then
		return nil, "No VirtualGuardWatch folder found. Press Watch, start Play Solo, then let the monitor write a report."
	end

	local value = rootFolder:FindFirstChild("ReportJson")
	if not value or not value:IsA("StringValue") or value.Value == "" then
		return nil, "No watch report has been written yet. Keep Play Solo running for a few seconds, then check this tab again."
	end

	local ok, decoded = pcall(function()
		return ConfigModule.HttpService:JSONDecode(value.Value)
	end)

	if ok and typeof(decoded) == "table" then
		return decoded, nil
	end

	return nil, "Watch report exists, but JSON could not be decoded."
end

function PluginReports.formatWatchReport(ConfigModule)
	local report, err = PluginReports.readWatchReport(ConfigModule)
	if not report then
		return "# VirtualGuard Watch\n\n"
			.. err
			.. "\n\nThe monitor installs ServerScriptService._VirtualGuardPlaytestMonitor and ReplicatedStorage.VirtualGuardWatch.ReportJson while you test."
			.. "\nRemove these temporary objects before publishing."
	end

	local lines = {}
	table.insert(lines, "# VirtualGuard Watch")
	table.insert(lines, "")
	table.insert(lines, "Temporary objects: ServerScriptService._VirtualGuardPlaytestMonitor and ReplicatedStorage.VirtualGuardWatch.ReportJson")
	table.insert(lines, "Release note: remove the Watch monitor before publishing.")
	table.insert(lines, "")
	table.insert(lines, "Duration: " .. tostring(report.durationSeconds or 0) .. "s")
	table.insert(lines, "Samples: " .. tostring(report.samples or 0))
	table.insert(lines, "Average frame: " .. tostring(report.averageFrameMs or 0) .. " ms")
	table.insert(lines, "Max frame: " .. tostring(report.maxFrameMs or 0) .. " ms")
	table.insert(lines, "Heartbeat spikes: " .. tostring(report.spikes or 0))
	table.insert(lines, "Remote calls observed: " .. tostring(report.remoteCallCount or 0))
	table.insert(lines, "Instance delta: " .. tostring(report.instanceDelta or 0))
	table.insert(lines, "Lua memory delta: " .. tostring(report.luaMemoryDeltaKb or 0) .. " KB")
	table.insert(lines, "")
	table.insert(lines, "## Container Growth")
	for name, value in pairs(report.containerDeltas or {}) do
		table.insert(lines, "- " .. tostring(name) .. ": " .. tostring(value))
	end
	table.insert(lines, "")
	table.insert(lines, "Raw JSON is printed through the Output button and stored at ReplicatedStorage.VirtualGuardWatch.ReportJson.")

	return table.concat(lines, "\n")
end

function PluginReports.formatSettingsReport(ConfigModule)
	local validators = ConfigModule.loadTrustedValidators()
	local names = {}
	for name in pairs(validators) do
		table.insert(names, name)
	end
	table.sort(names)

	local lines = {}
	table.insert(lines, "# VirtualGuard Settings")
	table.insert(lines, "")
	table.insert(lines, "Scan mode setting: " .. tostring(ConfigModule.loadScanMode()))
	table.insert(lines, "Trusted validator setting: " .. ConfigModule.TRUSTED_VALIDATORS_SETTING)
	table.insert(lines, "Trusted validators: " .. tostring(#names))
	table.insert(lines, "Default trusted validators: 0")
	table.insert(lines, "")
	table.insert(lines, "## Active Trusted Validators")

	if #names == 0 then
		table.insert(lines, "No trusted validators configured.")
	else
		for _, name in ipairs(names) do
			local grants = {}
			for grant, value in pairs(validators[name] or {}) do
				if value == true then
					table.insert(grants, grant)
				end
			end
			table.sort(grants)
			table.insert(lines, "- " .. name .. " -> " .. table.concat(grants, ", "))
		end
	end

	table.insert(lines, "")
	table.insert(lines, "## Examples")
	table.insert(lines, "- PurchaseService.ValidateReceipt -> economyAuthorized")
	table.insert(lines, "- DamageService.CanDamage -> damageAuthorized")
	table.insert(lines, "- CombatService.CheckDistance -> distanceChecked")
	table.insert(lines, "")
	table.insert(lines, "Validator calls are only trusted when they are the positive root predicate of the branch. OR conditions, nested calls, and false comparisons do not grant trust.")
	table.insert(lines, "Economy and damage sinks use operation-specific grants. Bounded client values are treated as mitigated, not fully validated.")

	return table.concat(lines, "\n")
end

return PluginReports
