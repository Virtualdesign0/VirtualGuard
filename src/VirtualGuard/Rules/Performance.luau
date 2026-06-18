local AnalyzerModule = require(script.Parent.Parent.Analysis.ProjectAnalyzer)
local TextModule = require(script.Parent.Parent.Shared.Text)

function AnalyzerModule.Analyzer.scanPerformance(context, doc)
	local source = doc.analysisSource or doc.source
	local reportedLoop = false

	TextModule.forEachWhileTrue(source, function(startIndex, window)
		if reportedLoop then
			return
		end

		if TextModule.hasYieldEvidence(window) then
			return
		end

		if TextModule.hasLoopExitEvidence(window) then
			return
		end

		reportedLoop = true
		AnalyzerModule.Analyzer.addIssue(context, doc, {
			category = "Performance",
			severity = doc.instance:IsA("ModuleScript") and "Medium" or "High",
			title = "Potential unbounded while true loop",
			line = TextModule.lineNumber(source, startIndex),
			problem = "This while true block has no yield or exit marker in the local analysis window.",
			suggestion = "Confirm the loop yields, exits deterministically, or is bounded by a scheduler. Add task.wait or a clear break/return path if it is long-running.",
			confidence = doc.instance:IsA("ModuleScript") and "Medium" or "High",
			reason = "No task.wait/wait/Heartbeat:Wait and no break/return marker were found near this loop.",
		})
	end)

	if TextModule.frameCallbackHasExpensiveScan(source) then
		AnalyzerModule.Analyzer.addIssue(context, doc, {
			category = "Performance",
			severity = "Medium",
			title = "Expensive scan appears inside frame loop",
			problem = "Frame-step connections that scan large instance sets can cause frame spikes.",
			suggestion = "Cache targets, use CollectionService tags, and update at a lower frequency.",
			confidence = "Medium",
			reason = "RunService frame callback and expensive scan marker were found in the same local callback window.",
		})
	elseif TextModule.hasAnyPlain(source, { "RenderStepped:Connect", "Heartbeat:Connect", "Stepped:Connect" })
		and TextModule.hasAnyPlain(source, { "GetDescendants", "GetChildren", "FindPartsInRegion", "GetPartBoundsInBox" }) then
		AnalyzerModule.Analyzer.addIssue(context, doc, {
			category = "Performance",
			severity = "Low",
			title = "Frame loop and broad scan both exist in script",
			problem = "A frame-step connection and broad instance scan are both present, but VirtualGuard did not prove they run in the same callback.",
			suggestion = "Review whether the broad scan is cached or kept outside per-frame work.",
			confidence = "Low",
			reason = "Markers were found in the same script, not in a proven call chain.",
		})
	end

	if TextModule.countPattern(source, "GetDescendants%s*%(") >= 3 then
		AnalyzerModule.Analyzer.addIssue(context, doc, {
			category = "Performance",
			severity = "Medium",
			title = "Frequent GetDescendants usage",
			problem = "Repeated broad tree scans can become expensive as the place grows.",
			suggestion = "Cache results, listen for descendants added/removed, or use CollectionService.",
			confidence = "Medium",
			reason = "GetDescendants appears 3 or more times.",
		})
	end

	if TextModule.hasAnyPlain(source, { "PathfindingService", "CreatePath" })
		and (source:find("while%s+true%s+do") or source:find("for%s+[%w_,%s]+%s+in%s+")) then
		AnalyzerModule.Analyzer.addIssue(context, doc, {
			category = "Performance",
			severity = "Low",
			title = "Pathfinding appears near a loop",
			problem = "Repeated path computation can create server spikes.",
			suggestion = "Throttle path requests, cache paths where possible, and stagger NPC updates.",
			confidence = "Low",
			reason = "Pathfinding marker and loop marker found in the same script; execution frequency was not proven.",
		})
	end
end

return true
