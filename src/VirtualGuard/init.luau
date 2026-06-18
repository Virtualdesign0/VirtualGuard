local Config = require(script.Config)

local VirtualGuard = {}
local loaded = false

function VirtualGuard.start(pluginObject)
	if loaded then
		return
	end
	loaded = true
	Config.initialize(pluginObject)
	local AnalyzerModule = require(script.Analysis.ProjectAnalyzer)
	require(script.Rules.SecurityHelpers)
	require(script.Rules.RemoteSecurity)
	require(script.Rules.DataStore)
	require(script.Rules.Performance)
	require(script.Rules.Memory)
	require(script.Rules.Privacy)
	require(script.PluginUI)
	return AnalyzerModule.Analyzer
end

return table.freeze(VirtualGuard)
