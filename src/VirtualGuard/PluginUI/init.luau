local AnalyzerModule = require(script.Parent.Analysis.ProjectAnalyzer)
local ConfigModule = require(script.Parent.Config)
local ReportingModule = require(script.Parent.Reporting)
local Widgets = require(script.Widgets)
local WatchMonitorSource = require(script.WatchMonitorSource)
local PluginReports = require(script.PluginReports)

local plugin = ConfigModule.getPlugin()

local make = Widgets.make
local padding = Widgets.padding
local label = Widgets.label
local actionButton = Widgets.actionButton
local detailButton = Widgets.detailButton

local TAB_LABELS = {
	All = "All Findings",
	Security = "Security",
	Performance = "Performance",
	Data = "Data",
	Memory = "Memory",
	Modules = "Modules",
	Watch = "Watchlist",
	Ignored = "Ignored",
	Settings = "Settings",
	Report = "Report",
}

local TAB_PREFIXES = {
	All = "[+]",
	Security = "[S]",
	Performance = "[P]",
	Data = "[D]",
	Memory = "[M]",
	Modules = "[#]",
	Watch = "[W]",
	Ignored = "[-]",
	Settings = "[*]",
	Report = "[R]",
}

local CATEGORY_TABS = {
	Security = true,
	Performance = true,
	Data = true,
	Memory = true,
	Modules = true,
}

local function addDetailSection(parent, title, body, color)
	make("Frame", {
		BackgroundColor3 = ConfigModule.THEME.borderSoft,
		BorderSizePixel = 0,
		Size = UDim2.new(1, 0, 0, 1),
		Parent = parent,
	})
	label(title, 12, color or ConfigModule.THEME.accent, true).Parent = parent
	label(tostring(body or ""), 11, ConfigModule.THEME.text, false).Parent = parent
end

local function compactIssueTitle(title)
	local compact = tostring(title or "")
	compact = compact:gsub("Client%-controlled invoke data", "Untrusted invoke")
	compact = compact:gsub("Client%-controlled data", "Untrusted data")
	compact = compact:gsub("Client%-controlled value", "Untrusted value")
	compact = compact:gsub("appears to reach", "reaches")
	return compact
end

local function bootVirtualGuardUi()
	local toolbar = plugin:CreateToolbar(ConfigModule.TOOLBAR_NAME)
	local openButton = toolbar:CreateButton("OpenVirtualGuard", "Open VirtualGuard", "", "Open VirtualGuard")
	openButton.ClickableWhenViewportHidden = true

	local widgetInfo = DockWidgetPluginGuiInfo.new(
		Enum.InitialDockState.Right,
		false,
		false,
		980,
		720,
		700,
		460
	)

	local widget = plugin:CreateDockWidgetPluginGui(ConfigModule.WIDGET_ID, widgetInfo)
	widget.Title = "VirtualGuard"

	for _, child in ipairs(widget:GetChildren()) do
		child:Destroy()
	end

	local state = {
		selectedTab = "All",
		selectedIssue = nil,
		result = nil,
		status = "Ready to scan",
		longLivedPaths = ConfigModule.loadLongLivedMap(),
		falsePositiveIssues = ConfigModule.loadFalsePositiveMap(),
		trustedValidators = ConfigModule.loadTrustedValidators(),
		scanMode = ConfigModule.loadScanMode(),
		settingsGrant = "economyAuthorized",
		settingsNameDraft = "",
		pendingTrustedValidatorReset = false,
	}

	local root = make("Frame", {
		BackgroundColor3 = ConfigModule.THEME.bg,
		BorderSizePixel = 0,
		Size = UDim2.fromScale(1, 1),
		Parent = widget,
	})

	local mainPadding = padding(6)
	mainPadding.Parent = root

	make("UIListLayout", {
		FillDirection = Enum.FillDirection.Vertical,
		SortOrder = Enum.SortOrder.LayoutOrder,
		Padding = UDim.new(0, 5),
		Parent = root,
	})

	local header = make("Frame", {
		BackgroundColor3 = ConfigModule.THEME.panel,
		BorderColor3 = ConfigModule.THEME.border,
		BorderMode = Enum.BorderMode.Inset,
		BorderSizePixel = 1,
		Size = UDim2.new(1, 0, 0, 76),
		LayoutOrder = 1,
		Parent = root,
	})

	make("TextLabel", {
		BackgroundColor3 = Color3.fromRGB(10, 31, 37),
		BorderColor3 = ConfigModule.THEME.border,
		BorderMode = Enum.BorderMode.Inset,
		BorderSizePixel = 1,
		Font = ConfigModule.FONT.Strong,
		Text = "VG",
		TextColor3 = ConfigModule.THEME.accent,
		TextSize = 16,
		TextXAlignment = Enum.TextXAlignment.Center,
		TextYAlignment = Enum.TextYAlignment.Center,
		Position = UDim2.new(0, 8, 0, 8),
		Size = UDim2.new(0, 48, 0, 48),
		Parent = header,
	})

	make("TextLabel", {
		BackgroundTransparency = 1,
		Font = ConfigModule.FONT.Strong,
		Text = "VirtualGuard",
		TextColor3 = ConfigModule.THEME.text,
		TextSize = 17,
		TextXAlignment = Enum.TextXAlignment.Left,
		Position = UDim2.new(0, 68, 0, 7),
		Size = UDim2.new(0, 150, 0, 22),
		Parent = header,
	})

	make("TextLabel", {
		BackgroundTransparency = 1,
		Font = ConfigModule.FONT.Body,
		Text = "Static Code Analyzer",
		TextColor3 = ConfigModule.THEME.muted,
		TextSize = 12,
		TextXAlignment = Enum.TextXAlignment.Left,
		Position = UDim2.new(0, 218, 0, 9),
		Size = UDim2.new(0, 190, 0, 18),
		Parent = header,
	})

	local statusLabel = make("TextLabel", {
		BackgroundTransparency = 1,
		Font = ConfigModule.FONT.Strong,
		Text = state.status,
		TextColor3 = ConfigModule.THEME.accent,
		TextSize = 13,
		TextXAlignment = Enum.TextXAlignment.Left,
		TextYAlignment = Enum.TextYAlignment.Top,
		Position = UDim2.new(0, 68, 0, 34),
		Size = UDim2.new(1, -270, 0, 32),
		TextWrapped = true,
		Parent = header,
	})

	local scoreText = make("TextLabel", {
		BackgroundColor3 = ConfigModule.THEME.panel2,
		BorderColor3 = ConfigModule.THEME.border,
		BorderMode = Enum.BorderMode.Inset,
		BorderSizePixel = 1,
		Font = ConfigModule.FONT.Body,
		RichText = true,
		Text = "Score: <font color=\"#00C6E2\">N/A</font>",
		TextColor3 = ConfigModule.THEME.text,
		TextSize = 14,
		TextXAlignment = Enum.TextXAlignment.Center,
		TextYAlignment = Enum.TextYAlignment.Center,
		Position = UDim2.new(1, -190, 0, 18),
		Size = UDim2.new(0, 174, 0, 36),
		Parent = header,
	})

	local actions = make("Frame", {
		BackgroundColor3 = ConfigModule.THEME.panel,
		BorderColor3 = ConfigModule.THEME.borderSoft,
		BorderMode = Enum.BorderMode.Inset,
		BorderSizePixel = 1,
		Size = UDim2.new(1, 0, 0, 38),
		LayoutOrder = 2,
		Parent = root,
	}, {
		padding(3),
	})

	make("UIListLayout", {
		FillDirection = Enum.FillDirection.Horizontal,
		SortOrder = Enum.SortOrder.LayoutOrder,
		VerticalAlignment = Enum.VerticalAlignment.Center,
		Padding = UDim.new(0, 4),
		Parent = actions,
	})

	local scanButton = actionButton("SCAN", 160, true)
	scanButton.LayoutOrder = 1
	scanButton.Parent = actions

	local watchButton = actionButton("WATCH", 150, false)
	watchButton.LayoutOrder = 2
	watchButton.Parent = actions

	local printButton = actionButton("OUTPUT", 150, false)
	printButton.LayoutOrder = 3
	printButton.Parent = actions

	local summary = make("Frame", {
		BackgroundColor3 = ConfigModule.THEME.panel,
		BorderColor3 = ConfigModule.THEME.borderSoft,
		BorderMode = Enum.BorderMode.Inset,
		BorderSizePixel = 1,
		Size = UDim2.new(1, 0, 0, 44),
		LayoutOrder = 3,
		Parent = root,
	}, {
		padding(4),
	})

	make("UIListLayout", {
		FillDirection = Enum.FillDirection.Horizontal,
		SortOrder = Enum.SortOrder.LayoutOrder,
		Padding = UDim.new(0, 5),
		Parent = summary,
	})

	local summaryLabels = {}
	local function summaryCell(name, severity)
		local frame = make("Frame", {
			BackgroundColor3 = ConfigModule.THEME.panel2,
			BorderColor3 = ConfigModule.SEVERITY_COLORS[severity],
			BorderMode = Enum.BorderMode.Inset,
			BorderSizePixel = 1,
			Size = UDim2.new(0.2, -4, 1, 0),
		})

		local value = make("TextLabel", {
			BackgroundTransparency = 1,
			Font = ConfigModule.FONT.Strong,
			Text = "0",
			TextColor3 = ConfigModule.SEVERITY_COLORS[severity],
			TextSize = 19,
			TextXAlignment = Enum.TextXAlignment.Center,
			TextYAlignment = Enum.TextYAlignment.Center,
			Size = UDim2.new(1, 0, 0, 22),
			Position = UDim2.new(0, 0, 0, 0),
			Parent = frame,
		})

		make("TextLabel", {
			BackgroundTransparency = 1,
			Font = ConfigModule.FONT.Body,
			Text = name,
			TextColor3 = ConfigModule.SEVERITY_COLORS[severity],
			TextSize = 9,
			TextXAlignment = Enum.TextXAlignment.Center,
			TextYAlignment = Enum.TextYAlignment.Center,
			TextTruncate = Enum.TextTruncate.AtEnd,
			Size = UDim2.new(1, 0, 0, 12),
			Position = UDim2.new(0, 0, 0, 18),
			Parent = frame,
		})

		summaryLabels[severity] = value
		return frame
	end

	summaryCell("CRITICAL", "Critical").Parent = summary
	summaryCell("HIGH", "High").Parent = summary
	summaryCell("MEDIUM", "Medium").Parent = summary
	summaryCell("LOW", "Low").Parent = summary
	summaryCell("INFO", "Info").Parent = summary

	local workspacePanel = make("Frame", {
		BackgroundTransparency = 1,
		BorderSizePixel = 0,
		Size = UDim2.new(1, 0, 1, -177),
		LayoutOrder = 4,
		Parent = root,
	})

	make("UIListLayout", {
		FillDirection = Enum.FillDirection.Horizontal,
		SortOrder = Enum.SortOrder.LayoutOrder,
		Padding = UDim.new(0, 6),
		Parent = workspacePanel,
	})

	local tabBar = make("ScrollingFrame", {
		BackgroundColor3 = ConfigModule.THEME.panel,
		BorderColor3 = ConfigModule.THEME.borderSoft,
		BorderMode = Enum.BorderMode.Inset,
		BorderSizePixel = 1,
		CanvasSize = UDim2.fromScale(0, 0),
		AutomaticCanvasSize = Enum.AutomaticSize.Y,
		ScrollBarThickness = 0,
		Size = UDim2.new(0, 190, 1, 0),
		LayoutOrder = 1,
		Parent = workspacePanel,
	}, {
		padding(5),
	})

	make("UIListLayout", {
		FillDirection = Enum.FillDirection.Vertical,
		SortOrder = Enum.SortOrder.LayoutOrder,
		Padding = UDim.new(0, 2),
		Parent = tabBar,
	})

	local tabButtons = {}
	local tabCountLabels = {}
	local issueList = nil
	local detailPanel = nil
	local reportScroll = nil
	local reportText = nil
	local settingsPanel = nil

	local function setStatus(text)
		state.status = text
		statusLabel.Text = text
	end

	local render
	local runScan

	for index, tabName in ipairs(ConfigModule.TABS) do
		if index == 1 or index == 7 then
			make("TextLabel", {
				BackgroundTransparency = 1,
				Font = ConfigModule.FONT.Strong,
				Text = index == 1 and "Categories" or "Tools",
				TextColor3 = Color3.fromRGB(142, 144, 146),
				TextSize = 12,
				TextXAlignment = Enum.TextXAlignment.Left,
				TextYAlignment = Enum.TextYAlignment.Bottom,
				Size = UDim2.new(1, -4, 0, index == 1 and 26 or 32),
				Position = UDim2.new(0, 4, 0, 0),
				LayoutOrder = (index * 10) - 1,
				Parent = tabBar,
			})
		end

		local button = make("TextButton", {
			AutoButtonColor = true,
			BackgroundColor3 = tabName == state.selectedTab and ConfigModule.THEME.panel3 or ConfigModule.THEME.panel,
			BackgroundTransparency = tabName == state.selectedTab and 0 or 1,
			BorderColor3 = tabName == state.selectedTab and ConfigModule.THEME.accent or ConfigModule.THEME.borderSoft,
			BorderMode = Enum.BorderMode.Inset,
			BorderSizePixel = 1,
			Font = tabName == state.selectedTab and ConfigModule.FONT.Strong or ConfigModule.FONT.Body,
			Text = "  " .. (TAB_PREFIXES[tabName] or "[ ]") .. "  " .. (TAB_LABELS[tabName] or tabName),
			TextColor3 = tabName == state.selectedTab and Color3.fromRGB(235, 234, 230) or Color3.fromRGB(172, 174, 176),
			TextSize = 13,
			TextXAlignment = Enum.TextXAlignment.Left,
			Size = UDim2.new(1, 0, 0, 38),
			LayoutOrder = index * 10,
			Parent = tabBar,
		})

		tabButtons[tabName] = button
		tabCountLabels[tabName] = make("TextLabel", {
			BackgroundTransparency = 1,
			Font = ConfigModule.FONT.Body,
			Text = "",
			TextColor3 = ConfigModule.THEME.text,
			TextSize = 12,
			TextXAlignment = Enum.TextXAlignment.Right,
			TextYAlignment = Enum.TextYAlignment.Center,
			Position = UDim2.new(1, -52, 0, 0),
			Size = UDim2.new(0, 42, 1, 0),
			Parent = button,
		})
		button.MouseButton1Click:Connect(function()
			state.selectedTab = tabName
			state.selectedIssue = nil
			render()
		end)
		button.MouseEnter:Connect(function()
			if state.selectedTab ~= tabName then
				button.BackgroundColor3 = ConfigModule.THEME.panel2
				button.BackgroundTransparency = 0
			end
		end)
		button.MouseLeave:Connect(function()
			if state.selectedTab ~= tabName then
				button.BackgroundTransparency = 1
			end
		end)
	end

	local content = make("Frame", {
		BackgroundTransparency = 1,
		BorderSizePixel = 0,
		Size = UDim2.new(1, -196, 1, 0),
		LayoutOrder = 2,
		Parent = workspacePanel,
	})

	issueList = make("ScrollingFrame", {
		BackgroundColor3 = ConfigModule.THEME.panel,
		BorderColor3 = ConfigModule.THEME.borderSoft,
		BorderMode = Enum.BorderMode.Inset,
		BorderSizePixel = 1,
		CanvasSize = UDim2.fromScale(0, 0),
		AutomaticCanvasSize = Enum.AutomaticSize.Y,
		ScrollBarThickness = 4,
		ScrollBarImageColor3 = Color3.fromRGB(118, 122, 126),
		ScrollBarImageTransparency = 0.15,
		Size = UDim2.new(0.48, -5, 1, 0),
		Parent = content,
	}, {
		padding(6),
	})

	make("UIListLayout", {
		FillDirection = Enum.FillDirection.Vertical,
		SortOrder = Enum.SortOrder.LayoutOrder,
		Padding = UDim.new(0, 8),
		Parent = issueList,
	})

	detailPanel = make("ScrollingFrame", {
		BackgroundColor3 = ConfigModule.THEME.panel2,
		BorderColor3 = ConfigModule.THEME.borderSoft,
		BorderMode = Enum.BorderMode.Inset,
		BorderSizePixel = 1,
		CanvasSize = UDim2.fromScale(0, 0),
		AutomaticCanvasSize = Enum.AutomaticSize.Y,
		ScrollBarThickness = 4,
		ScrollBarImageColor3 = Color3.fromRGB(118, 122, 126),
		ScrollBarImageTransparency = 0.15,
		Position = UDim2.new(0.48, 5, 0, 0),
		Size = UDim2.new(0.52, -5, 1, 0),
		Parent = content,
	}, {
		padding(9),
	})

	local analysisDivider = make("Frame", {
		BackgroundColor3 = ConfigModule.THEME.borderSoft,
		BackgroundTransparency = 0.38,
		BorderSizePixel = 0,
		Position = UDim2.new(0.48, 0, 0, 8),
		Size = UDim2.new(0, 1, 1, -16),
		Parent = content,
	})

	make("UIListLayout", {
		FillDirection = Enum.FillDirection.Vertical,
		SortOrder = Enum.SortOrder.LayoutOrder,
		Padding = UDim.new(0, 10),
		Parent = detailPanel,
	})

	reportScroll = make("ScrollingFrame", {
		BackgroundColor3 = ConfigModule.THEME.panel2,
		BorderColor3 = ConfigModule.THEME.borderSoft,
		BorderMode = Enum.BorderMode.Inset,
		BorderSizePixel = 1,
		CanvasSize = UDim2.fromScale(0, 0),
		AutomaticCanvasSize = Enum.AutomaticSize.Y,
		ScrollBarThickness = 4,
		ScrollBarImageColor3 = Color3.fromRGB(118, 122, 126),
		ScrollBarImageTransparency = 0.15,
		Size = UDim2.new(1, 0, 0, 0),
		Visible = false,
		LayoutOrder = 3,
		Parent = content,
	}, {
		padding(9),
	})

	reportText = make("TextLabel", {
		BackgroundTransparency = 1,
		Font = ConfigModule.FONT.Code,
		Text = "",
		TextColor3 = ConfigModule.THEME.text,
		TextSize = 11,
		TextXAlignment = Enum.TextXAlignment.Left,
		TextYAlignment = Enum.TextYAlignment.Top,
		TextWrapped = true,
		AutomaticSize = Enum.AutomaticSize.Y,
		Size = UDim2.new(1, -10, 0, 0),
		Parent = reportScroll,
	})

	settingsPanel = make("ScrollingFrame", {
		BackgroundColor3 = ConfigModule.THEME.panel2,
		BorderColor3 = ConfigModule.THEME.borderSoft,
		BorderMode = Enum.BorderMode.Inset,
		BorderSizePixel = 1,
		CanvasSize = UDim2.fromScale(0, 0),
		AutomaticCanvasSize = Enum.AutomaticSize.Y,
		ScrollBarThickness = 4,
		ScrollBarImageColor3 = Color3.fromRGB(118, 122, 126),
		ScrollBarImageTransparency = 0.15,
		Size = UDim2.new(1, 0, 0, 0),
		Visible = false,
		LayoutOrder = 4,
		Parent = content,
	}, {
		padding(9),
	})

	make("UIListLayout", {
		FillDirection = Enum.FillDirection.Vertical,
		SortOrder = Enum.SortOrder.LayoutOrder,
		Padding = UDim.new(0, 8),
		Parent = settingsPanel,
	})

	local function clearContainer(container)
		for _, child in ipairs(container:GetChildren()) do
			if not child:IsA("UILayout") and not child:IsA("UIPadding") and not child:IsA("UICorner") and not child:IsA("UIStroke") then
				child:Destroy()
			end
		end
	end

	local function filteredIssues()
		if not state.result then
			return {}
		end

		if state.selectedTab == "All" then
			return state.result.activeIssues or {}
		end

		if state.selectedTab == "Ignored" then
			return state.result.falsePositiveIssues or {}
		end

		local filtered = {}
		for _, issue in ipairs(state.result.activeIssues or {}) do
			if issue.category == state.selectedTab then
				table.insert(filtered, issue)
			end
		end

		return filtered
	end

	local function sortedTrustedValidatorNames(validators)
		local names = {}
		for name in pairs(validators or {}) do
			table.insert(names, name)
		end
		table.sort(names)
		return names
	end

	local function formatGrantList(grants)
		local grantNames = {}
		for _, option in ipairs(ConfigModule.TRUSTED_VALIDATOR_GRANT_OPTIONS) do
			if grants and grants[option.id] == true then
				table.insert(grantNames, option.label)
			end
		end
		return #grantNames > 0 and table.concat(grantNames, ", ") or "No valid grants"
	end

	local function isValidTrustedValidatorName(name)
		name = tostring(name or "")
		if name == "" or name:sub(1, 1) == "." or name:sub(-1) == "." or name:find("%.%.", 1, true) then
			return false
		end
		for part in name:gmatch("[^%.]+") do
			if not part:find("^[%a_][%w_]*$") then
				return false
			end
		end
		return true
	end

	local function saveTrustedValidatorState(statusText)
		local saveOk, saveErr = ConfigModule.saveTrustedValidators(state.trustedValidators)
		if saveOk then
			setStatus(statusText or "Trusted validator settings saved.")
		else
			warn("[VirtualGuard] Failed to save trusted validators: " .. tostring(saveErr))
			setStatus("Failed to save trusted validators: " .. tostring(saveErr))
		end
	end

	local function renderSettingsPanel()
		clearContainer(settingsPanel)
		state.trustedValidators = ConfigModule.cloneTrustedValidators(state.trustedValidators)

		label("Scan Mode", 14, ConfigModule.THEME.text, true).Parent = settingsPanel
		label("Automatic chooses a mode from project size. Fast prioritizes responsiveness. Deep forces the widest available CFG budgets.", 11, ConfigModule.THEME.muted, false).Parent = settingsPanel

		local scanModeRow = make("Frame", {
			BackgroundTransparency = 1,
			Size = UDim2.new(1, 0, 0, 28),
			Parent = settingsPanel,
		})
		make("UIListLayout", {
			FillDirection = Enum.FillDirection.Horizontal,
			SortOrder = Enum.SortOrder.LayoutOrder,
			Padding = UDim.new(0, 6),
			Parent = scanModeRow,
		})

		for index, mode in ipairs({ "Automatic", "Fast", "Deep" }) do
			local modeButton = detailButton(mode, state.scanMode == mode)
			modeButton.Size = UDim2.new(0, mode == "Automatic" and 104 or 74, 1, 0)
			modeButton.LayoutOrder = index
			modeButton.Parent = scanModeRow
			modeButton.MouseButton1Click:Connect(function()
				local ok, err = ConfigModule.saveScanMode(mode)
				if ok then
					state.scanMode = mode
					setStatus("Scan mode saved: " .. mode)
					render()
				else
					setStatus("Failed to save scan mode: " .. tostring(err))
				end
			end)
		end

		local selectedBudget = state.scanMode == "Automatic" and nil or ConfigModule.SCAN_MODE_BUDGETS[state.scanMode]
		local modeDetail = state.scanMode == "Automatic"
			and "Automatic: Deep for projects up to 180 scripts and 900,000 source characters; otherwise Fast."
			or (state.scanMode == "Deep"
				and ("Deep: depth " .. tostring(selectedBudget.maxDepth)
					.. ", " .. tostring(selectedBudget.maxAnalysesPerScan) .. " analyses, "
					.. tostring(selectedBudget.maxTotalTime) .. "s CFG budget.")
				or ("Fast: depth " .. tostring(selectedBudget.maxDepth)
					.. ", " .. tostring(selectedBudget.maxAnalysesPerScan) .. " analyses, "
					.. tostring(selectedBudget.maxTotalTime) .. "s CFG budget."))
		label(modeDetail, 10, ConfigModule.THEME.muted, false).Parent = settingsPanel

		make("Frame", {
			BackgroundColor3 = Color3.fromRGB(55, 57, 61),
			BorderSizePixel = 0,
			Size = UDim2.new(1, 0, 0, 1),
			Parent = settingsPanel,
		})

		label("Trusted Validators", 14, ConfigModule.THEME.text, true).Parent = settingsPanel
		label("Add only validators whose implementation you have reviewed. These grants are authorization hints, not proof that client data is safe.", 11, ConfigModule.THEME.muted, false).Parent = settingsPanel
		label("VALIDATOR CALL", 9, Color3.fromRGB(142, 144, 146), true).Parent = settingsPanel

		local input = make("TextBox", {
			BackgroundColor3 = Color3.fromRGB(31, 32, 34),
			BorderColor3 = Color3.fromRGB(55, 57, 61),
			BorderMode = Enum.BorderMode.Inset,
			BorderSizePixel = 1,
			ClearTextOnFocus = false,
			Font = ConfigModule.FONT.Code,
			Text = state.settingsNameDraft or "",
			PlaceholderText = "PurchaseService.ValidateReceipt",
			PlaceholderColor3 = ConfigModule.THEME.muted,
			TextColor3 = ConfigModule.THEME.text,
			TextSize = 12,
			TextXAlignment = Enum.TextXAlignment.Left,
			TextYAlignment = Enum.TextYAlignment.Center,
			Size = UDim2.new(1, 0, 0, 32),
			Parent = settingsPanel,
		}, {
			padding(8),
		})

		input.FocusLost:Connect(function()
			state.settingsNameDraft = input.Text
		end)

		label("GRANT", 9, Color3.fromRGB(142, 144, 146), true).Parent = settingsPanel

		local grantRow = make("Frame", {
			BackgroundTransparency = 1,
			Size = UDim2.new(1, 0, 0, 28),
			Parent = settingsPanel,
		})
		make("UIListLayout", {
			FillDirection = Enum.FillDirection.Horizontal,
			SortOrder = Enum.SortOrder.LayoutOrder,
			Padding = UDim.new(0, 6),
			Parent = grantRow,
		})

		for index, option in ipairs(ConfigModule.TRUSTED_VALIDATOR_GRANT_OPTIONS) do
			local button = detailButton(option.label, state.settingsGrant == option.id)
			button.Size = UDim2.new(0, option.label == "Distance" and 86 or 92, 1, 0)
			button.LayoutOrder = index
			button.Parent = grantRow
			button.MouseButton1Click:Connect(function()
				state.settingsGrant = option.id
				state.settingsNameDraft = input.Text
				state.pendingTrustedValidatorReset = false
				render()
			end)
		end

		local actionRow = make("Frame", {
			BackgroundTransparency = 1,
			Size = UDim2.new(1, 0, 0, 30),
			Parent = settingsPanel,
		})
		make("UIListLayout", {
			FillDirection = Enum.FillDirection.Horizontal,
			SortOrder = Enum.SortOrder.LayoutOrder,
			Padding = UDim.new(0, 8),
			Parent = actionRow,
		})

		local addButton = detailButton("Add / Save Validator", true)
		addButton.Size = UDim2.new(0, 154, 1, 0)
		addButton.Parent = actionRow
		addButton.MouseButton1Click:Connect(function()
			local name = ConfigModule.normalizeTrustedValidatorName(input.Text)
			state.settingsNameDraft = input.Text
			if name == "" then
				setStatus("Enter a validator call name first.")
				return
			end
			if not isValidTrustedValidatorName(name) then
				setStatus("Validator name must look like Service.Validator or ValidatorAlias.")
				return
			end
			state.trustedValidators[name] = state.trustedValidators[name] or {}
			state.trustedValidators[name][state.settingsGrant] = true
			state.settingsNameDraft = ""
			state.pendingTrustedValidatorReset = false
			saveTrustedValidatorState("Trusted validator saved: " .. name)
			render()
		end)

		local resetButton = detailButton(state.pendingTrustedValidatorReset and "Confirm Reset" or "Reset", state.pendingTrustedValidatorReset)
		resetButton.Size = UDim2.new(0, state.pendingTrustedValidatorReset and 110 or 70, 1, 0)
		resetButton.Parent = actionRow
		resetButton.MouseButton1Click:Connect(function()
			if not state.pendingTrustedValidatorReset then
				state.pendingTrustedValidatorReset = true
				setStatus("Press Confirm Reset to remove all trusted validators.")
				render()
				return
			end
			state.trustedValidators = {}
			state.settingsNameDraft = ""
			state.pendingTrustedValidatorReset = false
			saveTrustedValidatorState("Trusted validator settings reset.")
			render()
		end)

		make("Frame", {
			BackgroundColor3 = Color3.fromRGB(55, 57, 61),
			BorderSizePixel = 0,
			Size = UDim2.new(1, 0, 0, 1),
			Parent = settingsPanel,
		})
		label("ACTIVE VALIDATORS", 9, Color3.fromRGB(142, 144, 146), true).Parent = settingsPanel
		local names = sortedTrustedValidatorNames(state.trustedValidators)
		if #names == 0 then
			label("No trusted validators configured. Review a project validator, enter its call name above, then assign the narrowest matching grant.", 11, ConfigModule.THEME.muted, false).Parent = settingsPanel
		else
			for index, name in ipairs(names) do
				local row = make("Frame", {
					BackgroundColor3 = Color3.fromRGB(31, 32, 34),
					BorderColor3 = Color3.fromRGB(55, 57, 61),
					BorderMode = Enum.BorderMode.Inset,
					BorderSizePixel = 1,
					Size = UDim2.new(1, -8, 0, 84),
					LayoutOrder = 20 + index,
					Parent = settingsPanel,
				})

				make("TextLabel", {
					BackgroundTransparency = 1,
					Font = ConfigModule.FONT.Code,
					Text = name,
					TextColor3 = ConfigModule.THEME.text,
					TextSize = 12,
					TextXAlignment = Enum.TextXAlignment.Left,
					TextYAlignment = Enum.TextYAlignment.Center,
					TextTruncate = Enum.TextTruncate.AtEnd,
					Position = UDim2.new(0, 8, 0, 7),
					Size = UDim2.new(1, -98, 0, 18),
					Parent = row,
				})

				make("TextLabel", {
					BackgroundTransparency = 1,
					Font = ConfigModule.FONT.Body,
					Text = "Grants: " .. formatGrantList(state.trustedValidators[name]),
					TextColor3 = ConfigModule.THEME.muted,
					TextSize = 11,
					TextXAlignment = Enum.TextXAlignment.Left,
					TextYAlignment = Enum.TextYAlignment.Center,
					TextTruncate = Enum.TextTruncate.AtEnd,
					Position = UDim2.new(0, 8, 0, 28),
					Size = UDim2.new(1, -98, 0, 16),
					Parent = row,
				})

				local grantButtonIndex = 0
				for _, option in ipairs(ConfigModule.TRUSTED_VALIDATOR_GRANT_OPTIONS) do
					if state.trustedValidators[name] and state.trustedValidators[name][option.id] == true then
						grantButtonIndex += 1
						local shortLabel = option.id == "economyAuthorized" and "Remove Eco"
							or option.id == "damageAuthorized" and "Remove Dmg"
							or "Remove Dist"
						local dropGrantButton = detailButton(shortLabel, false)
						dropGrantButton.Position = UDim2.new(0, 8 + ((grantButtonIndex - 1) * 94), 0, 50)
						dropGrantButton.Size = UDim2.new(0, 88, 0, 24)
						dropGrantButton.Parent = row
						dropGrantButton.MouseButton1Click:Connect(function()
							local grants = state.trustedValidators[name]
							if grants then
								grants[option.id] = nil
								if next(grants) == nil then
									state.trustedValidators[name] = nil
								end
							end
							state.pendingTrustedValidatorReset = false
							saveTrustedValidatorState("Removed " .. option.id .. " from " .. name)
							render()
						end)
						if grantButtonIndex >= 3 then
							break
						end
					end
				end

				local removeButton = detailButton("Remove", false)
				removeButton.Position = UDim2.new(1, -82, 0, 15)
				removeButton.Size = UDim2.new(0, 74, 0, 28)
				removeButton.Parent = row
				removeButton.MouseButton1Click:Connect(function()
					state.trustedValidators[name] = nil
					state.pendingTrustedValidatorReset = false
					saveTrustedValidatorState("Trusted validator removed: " .. name)
					render()
				end)
			end
		end
	end

	local function readWatchReport()
		return PluginReports.readWatchReport(ConfigModule)
	end

	local function formatWatchReport()
		return PluginReports.formatWatchReport(ConfigModule)
	end

	local function formatSettingsReport()
		return PluginReports.formatSettingsReport(ConfigModule)
	end

	local function renderDetail(issue)
		clearContainer(detailPanel)

		if not issue then
			make("TextLabel", {
				BackgroundTransparency = 1,
				Font = ConfigModule.FONT.Strong,
				Text = "Select a finding to view its analysis.",
				TextColor3 = ConfigModule.THEME.muted,
				TextSize = 13,
				TextXAlignment = Enum.TextXAlignment.Center,
				TextYAlignment = Enum.TextYAlignment.Center,
				Size = UDim2.new(1, 0, 0, 180),
				Parent = detailPanel,
			})
			return
		end

		local findingHeader = make("Frame", {
			BackgroundColor3 = ConfigModule.THEME.panel,
			BorderColor3 = ConfigModule.THEME.border,
			BorderMode = Enum.BorderMode.Inset,
			BorderSizePixel = 1,
			Size = UDim2.new(1, 0, 0, 84),
			Parent = detailPanel,
		})

		make("TextLabel", {
			BackgroundTransparency = 1,
			Font = ConfigModule.FONT.Strong,
			Text = "Finding details",
			TextColor3 = ConfigModule.THEME.muted,
			TextSize = 11,
			TextXAlignment = Enum.TextXAlignment.Left,
			Position = UDim2.new(0, 9, 0, 7),
			Size = UDim2.new(1, -18, 0, 12),
			Parent = findingHeader,
		})

		make("TextLabel", {
			BackgroundTransparency = 1,
			Font = ConfigModule.FONT.Strong,
			Text = issue.title,
			TextColor3 = ConfigModule.THEME.accent,
			TextSize = 15,
			TextXAlignment = Enum.TextXAlignment.Left,
			TextYAlignment = Enum.TextYAlignment.Top,
			TextWrapped = true,
			Position = UDim2.new(0, 9, 0, 22),
			Size = UDim2.new(1, -112, 0, 38),
			Parent = findingHeader,
		})

		make("TextLabel", {
			BackgroundColor3 = ConfigModule.THEME.panel2,
			BorderColor3 = ConfigModule.SEVERITY_COLORS[issue.severity] or ConfigModule.THEME.border,
			BorderMode = Enum.BorderMode.Inset,
			BorderSizePixel = 1,
			Font = ConfigModule.FONT.Strong,
			Text = issue.severity:upper(),
			TextColor3 = ConfigModule.SEVERITY_COLORS[issue.severity] or ConfigModule.THEME.text,
			TextSize = 11,
			TextXAlignment = Enum.TextXAlignment.Center,
			TextYAlignment = Enum.TextYAlignment.Center,
			Position = UDim2.new(1, -94, 0, 12),
			Size = UDim2.new(0, 82, 0, 26),
			Parent = findingHeader,
		})

		make("TextLabel", {
			BackgroundTransparency = 1,
			Font = ConfigModule.FONT.Body,
			Text = (issue.falsePositive and "Ignored" or issue.category)
				.. " | Confidence: "
				.. issue.confidence,
			TextColor3 = ConfigModule.THEME.muted,
			TextSize = 10,
			TextXAlignment = Enum.TextXAlignment.Left,
			Position = UDim2.new(0, 9, 1, -19),
			Size = UDim2.new(1, -18, 0, 12),
			Parent = findingHeader,
		})

		local sourceLine = issue.sourcePath
		addDetailSection(
			detailPanel,
			"Location",
			sourceLine
				.. "\n"
				.. (
			(issue.line and ("Line " .. tostring(issue.line)) or "Line unknown")
				.. "  |  "
				.. tostring(issue.lifecycle or "Unclassified")
				),
			ConfigModule.THEME.accent
		)

		local canMarkSource = issue.sourcePath and issue.sourcePath ~= "Project"
		local canMarkIssue = issue.key ~= nil
		local actionRow = nil

		if canMarkSource or canMarkIssue then
			label("Review actions", 12, ConfigModule.THEME.accent, true).Parent = detailPanel
			actionRow = make("Frame", {
				BackgroundTransparency = 1,
				BorderSizePixel = 0,
				Size = UDim2.new(1, 0, 0, 28),
				Parent = detailPanel,
			})

			make("UIListLayout", {
				FillDirection = Enum.FillDirection.Horizontal,
				SortOrder = Enum.SortOrder.LayoutOrder,
				Padding = UDim.new(0, 6),
				Parent = actionRow,
			})
		end

		if canMarkSource then
			local sourceKey = ConfigModule.normalizePathKey(issue.sourcePath)
			local markedLongLived = state.longLivedPaths[sourceKey] == true
			local action = detailButton(markedLongLived and "Remove long-lived" or "Long-lived source", markedLongLived)
			action.BackgroundColor3 = markedLongLived and ConfigModule.THEME.panel3 or ConfigModule.THEME.panel
			action.BorderColor3 = markedLongLived and ConfigModule.THEME.accent2 or ConfigModule.THEME.border
			action.TextSize = 11
			action.Size = canMarkIssue and UDim2.new(0.58, -3, 0, 28) or UDim2.new(1, 0, 0, 28)
			action.LayoutOrder = 1
			action.Parent = actionRow
			action.MouseButton1Click:Connect(function()
				if markedLongLived then
					state.longLivedPaths[sourceKey] = nil
					local saveOk, saveErr = ConfigModule.saveLongLivedMap(state.longLivedPaths)
					if not saveOk then
						warn("[VirtualGuard] Failed to save long-lived override: " .. tostring(saveErr))
					end
					setStatus("Removed long-lived override. Rescanning...")
				else
					state.longLivedPaths[sourceKey] = true
					local saveOk, saveErr = ConfigModule.saveLongLivedMap(state.longLivedPaths)
					if not saveOk then
						warn("[VirtualGuard] Failed to save long-lived override: " .. tostring(saveErr))
					end
					setStatus("Marked source long-lived. Rescanning...")
				end

				if runScan then
					runScan(state.status)
				else
					render()
				end
			end)
		end

		if canMarkIssue then
			local markedFalsePositive = state.falsePositiveIssues[issue.key] == true or issue.falsePositive == true
			local ignoreAction = detailButton(markedFalsePositive and "Restore finding" or "Ignore finding", markedFalsePositive)
			ignoreAction.BackgroundColor3 = markedFalsePositive and ConfigModule.THEME.panel3 or ConfigModule.THEME.panel
			ignoreAction.BackgroundTransparency = 0
			ignoreAction.BorderColor3 = markedFalsePositive and ConfigModule.THEME.accent2 or ConfigModule.THEME.border
			ignoreAction.TextColor3 = markedFalsePositive and ConfigModule.THEME.accent or ConfigModule.THEME.text
			ignoreAction.TextSize = 11
			ignoreAction.Size = canMarkSource and UDim2.new(0.42, -3, 0, 28) or UDim2.new(1, 0, 0, 28)
			ignoreAction.LayoutOrder = 2
			ignoreAction.Parent = actionRow
			ignoreAction.MouseButton1Click:Connect(function()
				if markedFalsePositive then
					state.falsePositiveIssues[issue.key] = nil
					local saveOk, saveErr = ConfigModule.saveFalsePositiveMap(state.falsePositiveIssues)
					if not saveOk then
						warn("[VirtualGuard] Failed to save false-positive override: " .. tostring(saveErr))
					end
					setStatus("Restored finding. Rescanning...")
				else
					state.falsePositiveIssues[issue.key] = true
					local saveOk, saveErr = ConfigModule.saveFalsePositiveMap(state.falsePositiveIssues)
					if not saveOk then
						warn("[VirtualGuard] Failed to save false-positive override: " .. tostring(saveErr))
					end
					setStatus("Marked false-positive. Rescanning...")
				end

				if runScan then
					runScan(state.status)
				else
					render()
				end
			end)
		end

		addDetailSection(
			detailPanel,
			"[!] Impact",
			tostring(issue.impact or ReportingModule.defaultImpact(issue.category)),
			ConfigModule.SEVERITY_COLORS[issue.severity]
		)
		addDetailSection(detailPanel, "[?] Problem", issue.problem, ConfigModule.SEVERITY_COLORS.High)
		addDetailSection(detailPanel, "[+] Suggestion", issue.suggestion, ConfigModule.THEME.accent)
		addDetailSection(
			detailPanel,
			"[>] Review Step",
			tostring(issue.review or ReportingModule.defaultReviewStep(issue.category)),
			ConfigModule.THEME.accent2
		)
		addDetailSection(
			detailPanel,
			"[~] Flow",
			#issue.flow > 0 and table.concat(issue.flow, "\n> ") or "No call chain inferred yet",
			ConfigModule.THEME.accent
		)
		addDetailSection(
			detailPanel,
			"[i] Evidence",
			tostring(issue.evidence or issue.reason or "Pattern matched by static review."),
			ConfigModule.THEME.accent2
		)
		addDetailSection(
			detailPanel,
			"Lifecycle",
			tostring(issue.lifecycle or "Unclassified"),
			issue.longLived and ConfigModule.THEME.accent2 or ConfigModule.THEME.muted
		)

		if issue.reason and issue.reason ~= "" then
			addDetailSection(detailPanel, "[i] Reason", issue.reason, Color3.fromRGB(164, 113, 214))
		end
	end

	local function renderIssueCard(issue, order)
		local mutedFinding = issue.falsePositive == true
		local selectedFinding = state.selectedIssue == issue
		local card = make("TextButton", {
			AutoButtonColor = true,
			BackgroundColor3 = mutedFinding and ConfigModule.THEME.panel or (selectedFinding and ConfigModule.THEME.panel3 or ConfigModule.THEME.panel2),
			BackgroundTransparency = 0,
			BorderColor3 = selectedFinding and ConfigModule.THEME.accent2 or ConfigModule.THEME.borderSoft,
			BorderMode = Enum.BorderMode.Inset,
			BorderSizePixel = 1,
			Text = "",
			Size = UDim2.new(1, -4, 0, 76),
			LayoutOrder = order,
		})

		make("Frame", {
			BackgroundColor3 = ConfigModule.THEME.borderSoft,
			BackgroundTransparency = 0.3,
			BorderSizePixel = 0,
			Position = UDim2.new(0, 0, 1, -1),
			Size = UDim2.new(1, 0, 0, 1),
			Parent = card,
		})

		local badgeWidth = (mutedFinding or issue.severity == "Critical") and 50 or 44

		make("TextLabel", {
			BackgroundTransparency = 1,
			Font = ConfigModule.FONT.Strong,
			Text = compactIssueTitle(issue.title),
			TextColor3 = mutedFinding and ConfigModule.THEME.muted or (selectedFinding and Color3.fromRGB(230, 246, 248) or ConfigModule.THEME.text),
			TextSize = 14,
			TextXAlignment = Enum.TextXAlignment.Left,
			TextYAlignment = Enum.TextYAlignment.Top,
			TextWrapped = false,
			TextTruncate = Enum.TextTruncate.AtEnd,
			Size = UDim2.new(1, -(badgeWidth + 22), 0, 18),
			Position = UDim2.new(0, 9, 0, 7),
			Parent = card,
		})

		local severityColor = ConfigModule.SEVERITY_COLORS[issue.severity] or ConfigModule.THEME.muted
		make("TextLabel", {
			BackgroundTransparency = 1,
			Font = ConfigModule.FONT.Body,
			Text = mutedFinding and "IGNORED" or issue.severity:upper(),
			TextColor3 = mutedFinding and ConfigModule.THEME.muted or severityColor,
			TextSize = 10,
			TextXAlignment = Enum.TextXAlignment.Right,
			TextYAlignment = Enum.TextYAlignment.Center,
			Position = UDim2.new(1, -(badgeWidth + 10), 0, 8),
			Size = UDim2.new(0, badgeWidth, 0, 14),
			Parent = card,
		})

		local source = issue.sourcePath

		make("TextLabel", {
			BackgroundTransparency = 1,
			Font = ConfigModule.FONT.Body,
			Text = source,
			TextColor3 = mutedFinding and Color3.fromRGB(135, 139, 143) or Color3.fromRGB(188, 189, 184),
			TextSize = 11,
			TextXAlignment = Enum.TextXAlignment.Left,
			TextYAlignment = Enum.TextYAlignment.Top,
			TextTruncate = Enum.TextTruncate.AtEnd,
			Size = UDim2.new(1, -14, 0, 12),
			Position = UDim2.new(0, 9, 0, 39),
			Parent = card,
		})

		make("TextLabel", {
			BackgroundTransparency = 1,
			Font = ConfigModule.FONT.Body,
			Text = (issue.line and ("Line " .. tostring(issue.line)) or "Line unknown")
				.. "  |  "
				.. tostring(issue.lifecycle or "Unclassified"),
			TextColor3 = mutedFinding and Color3.fromRGB(138, 142, 146) or Color3.fromRGB(190, 191, 186),
			TextSize = 11,
			TextXAlignment = Enum.TextXAlignment.Left,
			TextYAlignment = Enum.TextYAlignment.Top,
			Size = UDim2.new(1, -14, 0, 14),
			Position = UDim2.new(0, 9, 0, 56),
			Parent = card,
		})

		card.MouseButton1Click:Connect(function()
			state.selectedIssue = issue
			render()
		end)

		return card
	end

	render = function()
		for tabName, button in pairs(tabButtons) do
			local selected = tabName == state.selectedTab
			button.BackgroundColor3 = selected and ConfigModule.THEME.panel3 or ConfigModule.THEME.panel
			button.BackgroundTransparency = selected and 0 or 1
			button.BorderColor3 = selected and ConfigModule.THEME.accent or ConfigModule.THEME.borderSoft
			button.BorderSizePixel = 1
			button.Font = selected and ConfigModule.FONT.Strong or ConfigModule.FONT.Body
			button.TextColor3 = selected and Color3.fromRGB(239, 242, 238) or Color3.fromRGB(162, 166, 169)
		end

		local result = state.result
		if result then
			scoreText.Text = "Score: <font color=\"#00C6E2\">" .. tostring(result.score) .. "</font> / 100"
			local categoryCounts = {}
			for _, issue in ipairs(result.activeIssues or {}) do
				categoryCounts[issue.category] = (categoryCounts[issue.category] or 0) + 1
			end
			for tabName, countLabel in pairs(tabCountLabels) do
				if tabName == "All" then
					countLabel.Text = tostring(#(result.activeIssues or {}))
				elseif tabName == "Ignored" then
					countLabel.Text = tostring(#(result.falsePositiveIssues or {}))
				elseif CATEGORY_TABS[tabName] then
					countLabel.Text = tostring(categoryCounts[tabName] or 0)
				else
					countLabel.Text = ""
				end
			end
			for severity, textLabel in pairs(summaryLabels) do
				local count = result.counts[severity] or 0
				textLabel.Text = tostring(count)
				textLabel.TextColor3 = count > 0
					and ConfigModule.SEVERITY_COLORS[severity]
					or Color3.fromRGB(104, 108, 113)
			end
		else
			scoreText.Text = "Score: <font color=\"#00C6E2\">N/A</font>"
			for _, countLabel in pairs(tabCountLabels) do
				countLabel.Text = ""
			end
			for _, textLabel in pairs(summaryLabels) do
				textLabel.Text = "0"
				textLabel.TextColor3 = Color3.fromRGB(104, 108, 113)
			end
		end

		local showTextView = state.selectedTab == "Report" or state.selectedTab == "Watch"
		local showSettingsView = state.selectedTab == "Settings"
		issueList.Visible = not showTextView and not showSettingsView
		detailPanel.Visible = not showTextView and not showSettingsView
		analysisDivider.Visible = not showTextView and not showSettingsView
		reportScroll.Visible = showTextView
		settingsPanel.Visible = showSettingsView

		if showTextView then
			issueList.Size = UDim2.new(0, 0, 0, 0)
			detailPanel.Size = UDim2.new(0, 0, 0, 0)
			reportScroll.Size = UDim2.fromScale(1, 1)
			settingsPanel.Size = UDim2.new(1, 0, 0, 0)
			if state.selectedTab == "Watch" then
				reportText.Text = formatWatchReport()
			else
				reportText.Text = result and result.reportMarkdown or "Run Scan Project to generate a report."
			end
			return
		end

		if showSettingsView then
			issueList.Size = UDim2.new(0, 0, 0, 0)
			detailPanel.Size = UDim2.new(0, 0, 0, 0)
			reportScroll.Size = UDim2.new(1, 0, 0, 0)
			settingsPanel.Size = UDim2.fromScale(1, 1)
			renderSettingsPanel()
			return
		end

		issueList.Position = UDim2.fromOffset(0, 0)
		issueList.Size = UDim2.new(0.48, -5, 1, 0)
		detailPanel.Position = UDim2.new(0.48, 5, 0, 0)
		detailPanel.Size = UDim2.new(0.52, -5, 1, 0)
		reportScroll.Size = UDim2.new(1, 0, 0, 0)
		settingsPanel.Size = UDim2.new(1, 0, 0, 0)

		clearContainer(issueList)

		local issues = filteredIssues()
		local listHeader = make("Frame", {
			BackgroundColor3 = ConfigModule.THEME.panel2,
			BorderColor3 = ConfigModule.THEME.borderSoft,
			BorderMode = Enum.BorderMode.Inset,
			BorderSizePixel = 1,
			Size = UDim2.new(1, -4, 0, 28),
			LayoutOrder = 0,
			Parent = issueList,
		})

		make("TextLabel", {
			BackgroundTransparency = 1,
			Font = ConfigModule.FONT.Strong,
			Text = "Findings",
			TextColor3 = ConfigModule.THEME.muted,
			TextSize = 10,
			TextXAlignment = Enum.TextXAlignment.Left,
			Position = UDim2.new(0, 7, 0, 7),
			Size = UDim2.new(0.65, 0, 0, 12),
			Parent = listHeader,
		})

		make("TextLabel", {
			BackgroundTransparency = 1,
			Font = ConfigModule.FONT.Body,
			Text = tostring(#issues),
			TextColor3 = ConfigModule.THEME.muted,
			TextSize = 10,
			TextXAlignment = Enum.TextXAlignment.Right,
			Position = UDim2.new(0.65, 0, 0, 6),
			Size = UDim2.new(0.35, -2, 0, 13),
			Parent = listHeader,
		})

		if not result then
			local empty = label("Run Scan Project to inspect scripts, modules, remotes, DataStore usage, cleanup patterns, performance markers, and release risks.", 13, ConfigModule.THEME.muted, false)
			empty.LayoutOrder = 1
			empty.Parent = issueList
		elseif #issues == 0 then
			local empty = label("No issues in this tab with the current rule set.", 13, ConfigModule.THEME.muted, false)
			empty.LayoutOrder = 1
			empty.Parent = issueList
		else
			for index, issue in ipairs(issues) do
				renderIssueCard(issue, index + 1).Parent = issueList
			end
		end

		renderDetail(state.selectedIssue)
	end

	local function installOrRemoveWatchMonitor()
		local existing = ConfigModule.ServerScriptService:FindFirstChild("_VirtualGuardPlaytestMonitor")
		if existing then
			existing:Destroy()
			local watchFolder = ConfigModule.ReplicatedStorage:FindFirstChild("VirtualGuardWatch")
			if watchFolder then
				watchFolder:Destroy()
			end
			state.selectedTab = "Watch"
			setStatus("Watch monitor and temporary report container removed.")
			render()
			return
		end

		local watchFolder = ConfigModule.ReplicatedStorage:FindFirstChild("VirtualGuardWatch")
		if not watchFolder then
			watchFolder = Instance.new("Folder")
			watchFolder.Name = "VirtualGuardWatch"
			watchFolder.Parent = ConfigModule.ReplicatedStorage
		end

		local reportValue = watchFolder:FindFirstChild("ReportJson")
		if not reportValue then
			reportValue = Instance.new("StringValue")
			reportValue.Name = "ReportJson"
			reportValue.Parent = watchFolder
		end
		reportValue.Value = ""

		local monitor = Instance.new("Script")
		monitor.Name = "_VirtualGuardPlaytestMonitor"
		monitor.Source = WatchMonitorSource
		monitor.Parent = ConfigModule.ServerScriptService
		state.selectedTab = "Watch"
		setStatus("Monitor installed for Play Solo. Remove it before publishing.")
		render()
	end

	runScan = function(statusText)
		if state.isScanning then
			setStatus("Scan already running...")
			return
		end

		state.isScanning = true
		state.longLivedPaths = ConfigModule.loadLongLivedMap()
		state.falsePositiveIssues = ConfigModule.loadFalsePositiveMap()
		local requestedMode = state.scanMode or ConfigModule.loadScanMode()
		setStatus(statusText or ("Scanning project (" .. requestedMode .. ")..."))
		scanButton.Text = "SCANNING..."
		scanButton.Active = false
		scanButton.AutoButtonColor = false

		task.defer(function()
			local ok, resultOrError = pcall(function()
				return AnalyzerModule.Analyzer.scan(requestedMode)
			end)

			if ok then
				state.result = resultOrError
				state.selectedIssue = (resultOrError.activeIssues and resultOrError.activeIssues[1]) or (resultOrError.falsePositiveIssues and resultOrError.falsePositiveIssues[1])
				state.selectedTab = "All"
				print("[VirtualGuard] Scan complete (" .. tostring(resultOrError.requestedScanMode) .. " -> " .. tostring(resultOrError.effectiveScanMode) .. "): " .. tostring(resultOrError.scriptCount) .. " scripts, " .. tostring(#resultOrError.activeIssues or 0) .. " active issues, " .. tostring(resultOrError.falsePositiveCount or 0) .. " ignored, score " .. tostring(resultOrError.score) .. "/100")
				print(resultOrError.reportMarkdown)
				print(resultOrError.reportJson)
				setStatus("Scan complete (" .. tostring(resultOrError.effectiveScanMode) .. "): " .. tostring(resultOrError.scriptCount) .. " scripts, " .. tostring(#resultOrError.activeIssues or 0) .. " active, " .. tostring(resultOrError.falsePositiveCount or 0) .. " ignored. Output updated.")
			else
				warn("[VirtualGuard] Scan failed: " .. tostring(resultOrError))
				setStatus("Scan failed: " .. tostring(resultOrError))
			end

			state.isScanning = false
			scanButton.Text = "SCAN"
			scanButton.Active = true
			scanButton.AutoButtonColor = true
			render()
		end)
	end

	scanButton.MouseButton1Click:Connect(function()
		runScan()
	end)

	watchButton.MouseButton1Click:Connect(function()
		installOrRemoveWatchMonitor()
	end)

	printButton.MouseButton1Click:Connect(function()
		if state.selectedTab == "Watch" then
			local report, err = readWatchReport()
			print(formatWatchReport())
			if report then
				print(ConfigModule.HttpService:JSONEncode(report))
				setStatus("Watch report printed to Output")
			else
				setStatus(err or "No Watch report available")
			end
			return
		end

		if state.selectedTab == "Settings" then
			print(formatSettingsReport())
			setStatus("Settings summary printed to Output")
			return
		end

		if not state.result then
			setStatus("Run a scan before printing a report")
			return
		end

		print(state.result.reportMarkdown)
		print(state.result.reportJson)
		setStatus("Markdown and JSON report printed to Output")
	end)

	openButton.Click:Connect(function()
		widget.Enabled = not widget.Enabled
		openButton:SetActive(widget.Enabled)
	end)

	widget:GetPropertyChangedSignal("Enabled"):Connect(function()
		openButton:SetActive(widget.Enabled)
	end)

	render()
end

bootVirtualGuardUi()

return true
