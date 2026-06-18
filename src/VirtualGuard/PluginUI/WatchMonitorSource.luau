return [=[
local HttpService = game:GetService("HttpService")
local RunService = game:GetService("RunService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")

local watchFolder = ReplicatedStorage:FindFirstChild("VirtualGuardWatch")
if not watchFolder then
	watchFolder = Instance.new("Folder")
	watchFolder.Name = "VirtualGuardWatch"
	watchFolder.Parent = ReplicatedStorage
end

local reportValue = watchFolder:FindFirstChild("ReportJson")
if not reportValue then
	reportValue = Instance.new("StringValue")
	reportValue.Name = "ReportJson"
	reportValue.Parent = watchFolder
end

local started = os.clock()
local lastPublish = 0
local maxFrameMs = 0
local totalFrameMs = 0
local spikes = 0
local samples = 0
local remoteCalls = 0
local initialInstances = #game:GetDescendants()
local initialMemory = 0
pcall(function()
	initialMemory = collectgarbage("count")
end)

local function containerCounts()
	local result = {}
	for _, container in ipairs({
		workspace,
		game:GetService("ReplicatedStorage"),
		game:GetService("ServerStorage"),
		game:GetService("ServerScriptService"),
	}) do
		result[container.Name] = #container:GetDescendants()
	end
	return result
end

local initialContainers = containerCounts()

local remoteConnections = {}
for _, instance in ipairs(game:GetDescendants()) do
	if instance:IsA("RemoteEvent") then
		table.insert(remoteConnections, instance.OnServerEvent:Connect(function()
			remoteCalls += 1
		end))
	end
end

local function buildReport()
	local currentMemory = initialMemory
	pcall(function()
		currentMemory = collectgarbage("count")
	end)

	local currentContainers = containerCounts()
	local containerDeltas = {}
	for name, count in pairs(currentContainers) do
		containerDeltas[name] = count - (initialContainers[name] or 0)
	end

	return {
		durationSeconds = math.floor((os.clock() - started) * 10 + 0.5) / 10,
		samples = samples,
		averageFrameMs = samples > 0 and math.floor((totalFrameMs / samples) * 10 + 0.5) / 10 or 0,
		maxFrameMs = math.floor(maxFrameMs * 10 + 0.5) / 10,
		spikes = spikes,
		remoteCallCount = remoteCalls,
		instanceDelta = #game:GetDescendants() - initialInstances,
		luaMemoryDeltaKb = math.floor((currentMemory - initialMemory) * 10 + 0.5) / 10,
		containerDeltas = containerDeltas,
	}
end

local function publishReport()
	local ok, encoded = pcall(function()
		return HttpService:JSONEncode(buildReport())
	end)
	if ok then
		reportValue.Value = encoded
	end
end

local connection
connection = RunService.Heartbeat:Connect(function(dt)
	samples += 1
	local frameMs = dt * 1000
	totalFrameMs += frameMs
	if frameMs > maxFrameMs then
		maxFrameMs = frameMs
	end
	if frameMs >= 50 then
		spikes += 1
	end

	if os.clock() - lastPublish >= 1 then
		lastPublish = os.clock()
		publishReport()
	end
end)

game:BindToClose(function()
	if connection then
		connection:Disconnect()
	end
	for _, remoteConnection in ipairs(remoteConnections) do
		remoteConnection:Disconnect()
	end

	publishReport()
	print("[VirtualGuard Watch] " .. reportValue.Value)
end)
]=]
