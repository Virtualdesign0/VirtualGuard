local TextModule = require(script.Parent.Shared.Text)

local function defaultImpact(category)
	if category == "Security" then
		return "This can become exploitable when client intent is treated as trusted server authority."
	elseif category == "Data" then
		return "This can affect save reliability, overwrite behavior, or shutdown consistency if the surrounding data layer does not handle it."
	elseif category == "Performance" then
		return "This can affect frame time or server step stability if it runs frequently or scales with instance/player count."
	elseif category == "Memory" then
		return "This can retain callbacks, instances, or owner objects when the source is shorter-lived than the connection."
	elseif category == "Modules" then
		return "This can make load order, dependency ownership, or client/server boundaries harder to reason about."
	end

	return "This is a static review signal. Confirm it against the runtime ownership and call path."
end

local function defaultReviewStep(category)
	if category == "Security" then
		return "Trace the server-owned validation path and confirm the client only sends intent, not authority."
	elseif category == "Data" then
		return "Confirm the write path has ownership, retry/failure handling, session locking or UpdateAsync-style conflict behavior."
	elseif category == "Performance" then
		return "Confirm frequency, input size, and whether expensive work is cached, batched, or scheduled away from frame-critical paths."
	elseif category == "Memory" then
		return "Confirm the source lifetime. Mark it long-lived if it is a persistent runtime/service module, or add cleanup if it is temporary."
	elseif category == "Modules" then
		return "Check whether the dependency is intentional, documented, and safe for the client/server boundary."
	end

	return "Review the source and decide whether the pattern is intentional for this code path."
end

local function makeIssueKey(fields)
	return table.concat({
		tostring(fields.category or ""),
		tostring(fields.title or ""),
		tostring(fields.sourcePath or ""),
		tostring(fields.snippetHash or fields.line or 0),
	}, "|")
end

local function decorateIssue(context, doc, fields)
	fields.key = fields.key or makeIssueKey(fields)
	fields.falsePositive = context.falsePositiveIssues and context.falsePositiveIssues[fields.key] == true or false
	fields.lifecycle = fields.lifecycle or TextModule.getLifecycleClass(doc)
	fields.longLived = fields.longLived or (doc and doc.longLived == true) or false
	fields.evidence = fields.evidence or fields.reason or "Pattern matched by static source review."
	fields.impact = fields.impact or defaultImpact(fields.category)
	fields.review = fields.review or defaultReviewStep(fields.category)

	if fields.longLived and (fields.category == "Memory" or fields.category == "Performance") then
		fields.review = fields.review .. " This source is marked long-lived, so lifecycle warnings are weighted lower."
	end

	if fields.falsePositive then
		fields.review = "Marked false-positive by reviewer. This finding is kept for traceability and excluded from score."
		fields.evidence = fields.evidence .. " Reviewer override: false-positive."
	end

	return fields
end

local function buildReport(result)
	local lines = {}
	table.insert(lines, "# VirtualGuard Report")
	table.insert(lines, "")
	table.insert(lines, "Score: " .. tostring(result.score) .. "/100")
	table.insert(lines, "Scripts scanned: " .. tostring(result.scriptCount))
	table.insert(lines, "Modules scanned: " .. tostring(result.moduleCount))
	table.insert(lines, "Long-lived overrides: " .. tostring(result.longLivedCount or 0))
	table.insert(lines, "False-positive overrides: " .. tostring(result.falsePositiveCount or 0))
	table.insert(lines, "Scan mode: " .. tostring(result.requestedScanMode or "Automatic")
		.. " -> " .. tostring(result.effectiveScanMode or "Fast"))
	table.insert(lines, "Analysis: evidence-weighted static review")
	table.insert(lines, "")

	if result.categoryScores then
		table.insert(lines, "## Category Scores")
		for _, category in ipairs({ "Security", "Data", "Performance", "Memory", "Modules" }) do
			table.insert(lines, "- " .. category .. ": " .. tostring(result.categoryScores[category] or 100) .. "/100")
		end
		table.insert(lines, "")
	end

	table.insert(lines, "## Severity")
	for _, severity in ipairs({ "Critical", "High", "Medium", "Low", "Info" }) do
		table.insert(lines, "- " .. severity .. ": " .. tostring(result.counts[severity] or 0))
	end

	if #result.integrations > 0 then
		table.insert(lines, "")
		table.insert(lines, "## Detected Integrations")
		for _, item in ipairs(result.integrations) do
			table.insert(lines, "- " .. item)
		end
	end

	if result.projectSignals then
		table.insert(lines, "")
		table.insert(lines, "## Project Signals")
		table.insert(lines, "- Rate-limit markers: " .. tostring(result.projectSignals.projectRateLimitDetected == true))
		table.insert(lines, "- VirtualNet markers: " .. tostring(result.projectSignals.virtualNetDetected == true))
		table.insert(lines, "- VirtualNet rate-limit markers: " .. tostring(result.projectSignals.virtualNetRateLimitDetected == true))
		table.insert(lines, "- Validation markers: " .. tostring(result.projectSignals.validationDetected == true))
		table.insert(lines, "- Trusted validators: " .. tostring(result.projectSignals.trustedValidatorCount or 0))
		table.insert(lines, "- Cleanup framework markers: " .. tostring(result.projectSignals.cleanupFrameworkDetected == true))
		table.insert(lines, "- Long-lived overrides: " .. tostring(result.projectSignals.longLivedCount or 0))
		table.insert(lines, "- RemoteEvent handlers: " .. tostring(result.projectSignals.remoteEventHandlers or 0))
		table.insert(lines, "- RemoteFunction handlers: " .. tostring(result.projectSignals.remoteFunctionHandlers or 0))
		table.insert(lines, "- DataStore calls: " .. tostring(result.projectSignals.dataStoreCalls or 0))
		table.insert(lines, "- Signal connections: " .. tostring(result.projectSignals.signalConnections or 0))
		table.insert(lines, "- Frame-step connections: " .. tostring(result.projectSignals.frameConnections or 0))
		table.insert(lines, "- Require calls: " .. tostring(result.projectSignals.requireCalls or 0))
		table.insert(lines, "- CFG completed handlers: " .. tostring(result.projectSignals.cfgCompleteHandlers or 0) .. " / " .. tostring(result.projectSignals.cfgRootHandlers or 0))
		table.insert(lines, "- CFG fallback handlers: " .. tostring(result.projectSignals.cfgFallbackHandlers or 0))
		table.insert(lines, "- CFG incomplete callees: " .. tostring(result.projectSignals.cfgIncompleteCallees or 0))
		if result.projectSignals.cfgIncompleteReasons and #result.projectSignals.cfgIncompleteReasons > 0 then
			table.insert(lines, "- CFG incomplete sample: " .. tostring(result.projectSignals.cfgIncompleteReasons[1]))
		end
	end

	table.insert(lines, "")
	table.insert(lines, "## Issues")

	if #result.activeIssues == 0 then
		table.insert(lines, "No issues found by the current rule set.")
	else
		for index, issue in ipairs(result.activeIssues) do
			table.insert(lines, "")
			table.insert(lines, "### " .. tostring(index) .. ". [" .. issue.severity .. "] " .. issue.title)
			table.insert(lines, "- Category: " .. issue.category)
			table.insert(lines, "- Source: " .. issue.sourcePath .. (issue.line and (":" .. tostring(issue.line)) or ""))
			table.insert(lines, "- Confidence: " .. issue.confidence)
			table.insert(lines, "- Lifecycle: " .. tostring(issue.lifecycle or "Unclassified"))
			table.insert(lines, "- Evidence: " .. tostring(issue.evidence or issue.reason or "Pattern matched"))
			table.insert(lines, "- Impact: " .. tostring(issue.impact or defaultImpact(issue.category)))
			table.insert(lines, "- Problem: " .. issue.problem)
			table.insert(lines, "- Suggestion: " .. issue.suggestion)
			table.insert(lines, "- Review: " .. tostring(issue.review or defaultReviewStep(issue.category)))
			if issue.reason and issue.reason ~= "" then
				table.insert(lines, "- Reason: " .. issue.reason)
			end
			if issue.flow and #issue.flow > 0 then
				table.insert(lines, "- Flow: " .. table.concat(issue.flow, " -> "))
			end
		end
	end

	if result.falsePositiveIssues and #result.falsePositiveIssues > 0 then
		table.insert(lines, "")
		table.insert(lines, "## Ignored False-Positive Findings")
		for index, issue in ipairs(result.falsePositiveIssues) do
			table.insert(lines, "")
			table.insert(lines, "### " .. tostring(index) .. ". " .. issue.title)
			table.insert(lines, "- Category: " .. issue.category)
			table.insert(lines, "- Source: " .. issue.sourcePath .. (issue.line and (":" .. tostring(issue.line)) or ""))
			table.insert(lines, "- Original severity: " .. issue.severity)
			table.insert(lines, "- Evidence: " .. tostring(issue.evidence or issue.reason or "Pattern matched"))
			table.insert(lines, "- Review: Marked false-positive by reviewer and excluded from score.")
		end
	end

	return table.concat(lines, "\n")
end

return {
	buildReport = buildReport,
	decorateIssue = decorateIssue,
	defaultImpact = defaultImpact,
	defaultReviewStep = defaultReviewStep,
	makeIssueKey = makeIssueKey,
}
