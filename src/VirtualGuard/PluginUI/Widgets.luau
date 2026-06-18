local Config = require(script.Parent.Parent.Config)

local Widgets = {}

function Widgets.make(className, props, children)
	local instance = Instance.new(className)

	for key, value in pairs(props or {}) do
		instance[key] = value
	end

	for _, child in ipairs(children or {}) do
		child.Parent = instance
	end

	return instance
end

function Widgets.corner(radius)
	radius = radius or 0
	if radius > 1 then
		radius = 1
	end
	return Widgets.make("UICorner", {
		CornerRadius = UDim.new(0, radius),
	})
end

function Widgets.stroke(color, thickness)
	return Widgets.make("UIStroke", {
		Color = color or Config.THEME.border,
		Thickness = thickness or 1,
		Transparency = 0,
	})
end

function Widgets.padding(all)
	return Widgets.make("UIPadding", {
		PaddingTop = UDim.new(0, all),
		PaddingRight = UDim.new(0, all),
		PaddingBottom = UDim.new(0, all),
		PaddingLeft = UDim.new(0, all),
	})
end

function Widgets.label(text, size, color, bold)
	return Widgets.make("TextLabel", {
		BackgroundTransparency = 1,
		Font = bold and Config.FONT.Strong or Config.FONT.Body,
		Text = text,
		TextColor3 = color or Config.THEME.text,
		TextSize = (size or 13) + 1,
		TextXAlignment = Enum.TextXAlignment.Left,
		TextYAlignment = Enum.TextYAlignment.Top,
		TextWrapped = true,
		AutomaticSize = Enum.AutomaticSize.Y,
		Size = UDim2.new(1, 0, 0, 0),
	})
end

function Widgets.actionButton(text, width, primary)
	return Widgets.make("TextButton", {
		AutoButtonColor = true,
		BackgroundColor3 = primary and Color3.fromRGB(8, 99, 130) or Color3.fromRGB(25, 27, 28),
		BorderColor3 = primary and Config.THEME.accent or Config.THEME.border,
		BorderMode = Enum.BorderMode.Inset,
		BorderSizePixel = 1,
		Font = Config.FONT.Strong,
		Text = text,
		TextColor3 = primary and Color3.fromRGB(238, 248, 248) or Config.THEME.text,
		TextSize = 14,
		Size = UDim2.new(0, width, 0, 30),
	})
end

function Widgets.detailButton(text, active)
	return Widgets.make("TextButton", {
		AutoButtonColor = true,
		BackgroundColor3 = active and Color3.fromRGB(15, 62, 82) or Color3.fromRGB(25, 27, 28),
		BorderColor3 = active and Config.THEME.accent or Config.THEME.border,
		BorderMode = Enum.BorderMode.Inset,
		BorderSizePixel = 1,
		Font = active and Config.FONT.Strong or Config.FONT.Body,
		Text = text,
		TextColor3 = active and Config.THEME.accent or Config.THEME.text,
		TextSize = 11,
		Size = UDim2.new(1, 0, 0, 28),
	})
end

return Widgets
