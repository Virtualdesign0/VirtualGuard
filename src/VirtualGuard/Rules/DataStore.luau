local AnalyzerModule = require(script.Parent.Parent.Analysis.ProjectAnalyzer)
local SemanticsModule = require(script.Parent.Parent.Rules.Semantics)
local TextModule = require(script.Parent.Parent.Shared.Text)

function AnalyzerModule.Analyzer.scanDataStore(context, doc)
	local source = doc.analysisSource or doc.source
	local lower = source:lower()
	local dataStoreApiMarkers = { "GetAsync", "SetAsync", "UpdateAsync", "RemoveAsync", "IncrementAsync" }
	local hasDataStoreCall = TextModule.hasAnyPlain(source, dataStoreApiMarkers)
	local hasUpdateAsync = lower:find("updateasync", 1, true) ~= nil
	local hasPcall = lower:find("pcall", 1, true) ~= nil
	local safetyFrameworkEvidence = TextModule.hasAnyPlain(source, {
		"VirtualStore",
		"ProfileService",
		"sessionlock",
		"session lock",
		"lease",
		"receipt",
		"OperationLedger",
		"migration",
		"reconcile",
		"retry",
	}) or (context.projectSignals.sourceBlob and (
		context.projectSignals.sourceBlob:find("virtualstore", 1, true) ~= nil
		or context.projectSignals.sourceBlob:find("profileservice", 1, true) ~= nil
	))
	local playerDataEvidence = TextModule.hasAnyPlain(source, {
		"player.UserId",
		"profile.Data",
		"PlayerData",
		"leaderstats",
		"Players.PlayerRemoving",
	}) or SemanticsModule.hasProfileDataReference(source)

	if lower:find("setasync", 1, true) then
		local severity = "Low"
		local confidence = "Low"
		local reason = "SetAsync exists, but no direct player-data overwrite pattern was proven."

		if playerDataEvidence and not hasUpdateAsync and not safetyFrameworkEvidence then
			severity = "Medium"
			confidence = "Medium"
			reason = "SetAsync appears near player-data markers without UpdateAsync or known session-lock/profile framework markers."
		elseif playerDataEvidence and not hasUpdateAsync then
			severity = "Low"
			confidence = "Low"
			reason = "SetAsync appears near player-data markers, but data-safety framework markers were found."
		elseif hasUpdateAsync then
			reason = "UpdateAsync also exists in this script; review the specific SetAsync call rather than treating it as unsafe by default."
		end

		AnalyzerModule.Analyzer.addIssue(context, doc, {
			category = "Data",
			severity = severity,
			title = "SetAsync usage needs data-safety review",
			line = TextModule.lineNumber(source, lower:find("setasync", 1, true)),
			problem = "SetAsync can overwrite newer data when used for shared/player keys, but this is context-dependent.",
			suggestion = "For player profiles, prefer UpdateAsync or a session-lock/profile system. For receipts, configuration, or internal framework writes, document the ownership model.",
			confidence = confidence,
			reason = reason,
		})
	end

	if hasDataStoreCall and not hasPcall then
		local severity = safetyFrameworkEvidence and "Low" or "Medium"
		local confidence = safetyFrameworkEvidence and "Low" or "Medium"

		AnalyzerModule.Analyzer.addIssue(context, doc, {
			category = "Data",
			severity = severity,
			title = "DataStore call without local pcall marker",
			problem = "DataStore operations can fail or throttle. Unhandled failures can lose data or break server flow.",
			suggestion = "Confirm the call is wrapped by a helper/framework that handles pcall, retry, and failure reporting.",
			confidence = confidence,
			reason = safetyFrameworkEvidence
				and "Data-safety framework markers were found, so this may be handled outside the local script."
				or "DataStore API marker found without a local pcall marker.",
		})
	end

	if hasDataStoreCall then
		local reported = false
		TextModule.forEachWhileTrue(source, function(startIndex, window)
			if not reported and TextModule.hasAnyPlain(window, dataStoreApiMarkers) then
				reported = true
				AnalyzerModule.Analyzer.addIssue(context, doc, {
					category = "Data",
					severity = TextModule.hasYieldEvidence(window) and "Low" or "Medium",
					title = "DataStore call appears inside a loop",
					line = TextModule.lineNumber(source, startIndex),
					problem = "DataStore calls inside loops can hit budgets or create save storms if not debounced or batched.",
					suggestion = "Confirm this loop has a budget, debounce, batching strategy, and failure backoff.",
					confidence = TextModule.hasYieldEvidence(window) and "Low" or "Medium",
					reason = TextModule.hasYieldEvidence(window)
						and "A yield marker exists in the loop window, but the DataStore budget behavior still needs review."
						or "DataStore marker found in a while true block without a yield marker in the local window.",
				})
			end
		end)
	end
end

return true
