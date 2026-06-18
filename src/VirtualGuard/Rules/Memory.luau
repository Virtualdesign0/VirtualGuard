local AnalyzerModule = require(script.Parent.Parent.Analysis.ProjectAnalyzer)
local TextModule = require(script.Parent.Parent.Shared.Text)

function AnalyzerModule.Analyzer.scanMemory(context, doc)
	local source = doc.analysisSource or doc.source
	local connectionCount = TextModule.countPattern(source, ":Connect%s*%(")
	local hasFrameConnection = TextModule.hasAnyPlain(source, { "RenderStepped:Connect", "Heartbeat:Connect", "Stepped:Connect" })
	local hasCleanupEvidence = TextModule.hasCleanup(source)
	local runtimeLike = TextModule.isRuntimeLikeDocument(doc)
	local ephemeral = TextModule.isEphemeralDocument(doc)
	local lifecycleEvidence = TextModule.hasShutdownOrLifecycleEvidence(source)

	if connectionCount > 0 and not hasCleanupEvidence and (not hasFrameConnection or connectionCount >= 3) then
		local severity = "Low"
		local confidence = "Low"
		local reason = tostring(connectionCount) .. " connection marker(s) found without local cleanup markers."

		if ephemeral and not runtimeLike then
			severity = connectionCount >= 3 and "Medium" or "Low"
			confidence = "Medium"
			reason = reason .. " This file looks like a shorter-lived controller/tool/UI/character script."
		elseif runtimeLike then
			reason = reason .. " This file looks runtime/service-like, so persistent connections may be intentional."
		end

		AnalyzerModule.Analyzer.addIssue(context, doc, {
			category = "Memory",
			severity = severity,
			title = "Signal connections need lifecycle review",
			problem = "Connections can retain callbacks and owners if the object lifetime is shorter than the connection lifetime.",
			suggestion = "If this module is long-lived, this may be valid. If it owns temporary objects, store connections and clean them with Disconnect, Trove, Maid, Janitor, GarbageMan, or a destroy lifecycle.",
			confidence = confidence,
			reason = reason,
		})
	end

	if hasFrameConnection and not hasCleanupEvidence then
		local severity = "Low"
		local confidence = "Low"
		local reason = "Frame-step connection found without a local cleanup marker."

		if ephemeral and not runtimeLike then
			severity = "Medium"
			confidence = "Medium"
			reason = reason .. " The file path suggests a shorter-lived client/controller object."
		elseif runtimeLike or lifecycleEvidence then
			reason = reason .. " Runtime/service lifecycle evidence suggests this may be intentional."
		end

		AnalyzerModule.Analyzer.addIssue(context, doc, {
			category = "Memory",
			severity = severity,
			title = "Frame-step connection lifecycle needs review",
			problem = "Frame-step connections are safe for long-lived runtime modules, but risky in temporary controllers, tools, UI, character, or effect objects.",
			suggestion = "Confirm the owner lifetime. If the owner can be destroyed/recreated, attach the connection to a cleanup scope.",
			confidence = confidence,
			reason = reason,
		})
	end

	if TextModule.countPattern(source, "Instance%.new%s*%(") >= 3 and not TextModule.hasAnyPlain(source, { ":Destroy", "Debris:AddItem", "GarbageMan", "Trove", "Janitor", "Maid" }) then
		AnalyzerModule.Analyzer.addIssue(context, doc, {
			category = "Memory",
			severity = "Medium",
			title = "Instances created without obvious destroy path",
			problem = "Temporary instances may accumulate if they are not destroyed.",
			suggestion = "Use Debris, explicit Destroy, or a cleanup manager for temporary objects.",
			confidence = "Medium",
			reason = "Several Instance.new calls found without destroy/cleanup markers.",
		})
	end
end

return true
