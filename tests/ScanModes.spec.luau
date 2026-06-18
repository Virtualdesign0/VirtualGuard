local function resolveScanMode(requestedMode, documents)
	if requestedMode == "Fast" or requestedMode == "Deep" then
		return requestedMode
	end

	local sourceCharacters = 0
	for _, doc in ipairs(documents or {}) do
		sourceCharacters += #(doc.source or "")
	end

	if #(documents or {}) <= 180 and sourceCharacters <= 900000 then
		return "Deep"
	end
	return "Fast"
end

local smallProject = {
	{ source = string.rep("a", 1000) },
	{ source = string.rep("b", 1000) },
}
assert(resolveScanMode("Automatic", smallProject) == "Deep")
assert(resolveScanMode("Fast", smallProject) == "Fast")
assert(resolveScanMode("Deep", smallProject) == "Deep")

local manyDocuments = {}
for _ = 1, 181 do
	table.insert(manyDocuments, {
		source = "",
	})
end
assert(resolveScanMode("Automatic", manyDocuments) == "Fast")
assert(resolveScanMode("Deep", manyDocuments) == "Deep")

local largeSourceProject = {
	{ source = string.rep("x", 900001) },
}
assert(resolveScanMode("Automatic", largeSourceProject) == "Fast")
assert(resolveScanMode("Deep", largeSourceProject) == "Deep")

print("ScanModes regression test passed")
