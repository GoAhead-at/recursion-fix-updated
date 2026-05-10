#pragma once
#include "PCH.h"

#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <string>
#include <string_view>

struct StackOverFlowHook
{
	using FuncCallQueryPtr = RE::BSTSmartPointer<RE::BSScript::Internal::IFuncCallQuery>;
	enum class NotificationMode
	{
		kNone,
		kOncePerSession,
		kCooldown,
		kPopup
	};

	struct Settings
	{
		NotificationMode notificationMode{ NotificationMode::kOncePerSession };
		std::uint32_t cooldownSeconds{ 30 };
	};

	struct StackMatch
	{
		bool found{ false };
		std::string callerScript{ "<unknown>" };
		std::string callerFunction{ "<unknown>" };
		std::uint32_t framesScanned{ 0 };
	};

	static constexpr std::uint32_t kPapyrusStackLimit = 1000;
	static constexpr std::uint32_t kMaxFramesToScan = 4096;

	static const std::filesystem::path& GetPluginDirectoryPath()
	{
		static const std::filesystem::path pluginDirectory = []() -> std::filesystem::path {
			std::array<char, 1024> modulePath{};
			HMODULE moduleHandle = nullptr;
			constexpr auto flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
			const auto resolved = GetModuleHandleExA(flags, reinterpret_cast<LPCSTR>(&thunk), &moduleHandle);
			if (resolved != 0 && moduleHandle != nullptr) {
				const auto length = GetModuleFileNameA(moduleHandle, modulePath.data(), static_cast<DWORD>(modulePath.size()));
				if (length > 0) {
					return std::filesystem::path{ std::string(modulePath.data(), length) }.parent_path();
				}
			}
			return std::filesystem::path{ "Data/SKSE/Plugins" };
		}();
		return pluginDirectory;
	}

	static const std::filesystem::path& GetSettingsPath()
	{
		static const std::filesystem::path settingsPath = GetPluginDirectoryPath() / "RecursionFPSFix.ini";
		return settingsPath;
	}

	static RE::BSFixedString* thunk(std::uint64_t unk0, RE::BSScript::Stack* a_stack, FuncCallQueryPtr* a_funcCallQuery)
	{
		if (a_stack != nullptr && a_stack->frames > kPapyrusStackLimit && a_funcCallQuery != nullptr) {
			RE::BSScript::Internal::IFuncCallQuery::CallType ignore;
			RE::BSTSmartPointer<RE::BSScript::ObjectTypeInfo> scriptInfo;
			RE::BSScript::Variable ignore2;
			RE::BSScrapArray<RE::BSScript::Variable> ignore3;
			RE::BSFixedString functionName;

			const auto query = a_funcCallQuery->get();
			if (query != nullptr) {
				query->GetFunctionCallInfo(ignore, scriptInfo, functionName, ignore2, ignore3);
			}

			const auto functionNameString = functionName.c_str();

			const auto script = scriptInfo.get();
			if (script != nullptr && functionNameString != nullptr) {
				const auto scriptName = script->GetName();

				const auto stackMatch = FindCallInStack(a_stack, scriptName, functionNameString);
				if (scriptName != nullptr && stackMatch.found) {
					const auto count = recursionEventCount.fetch_add(1, std::memory_order_relaxed) + 1;
					LogRecursionExit(scriptName, functionNameString, stackMatch, a_stack->frames, count);
					NotifyRecursion(scriptName, functionNameString);
					a_funcCallQuery->reset();
				} else {
					// might be a regular native call or something not directly causing recursion, don't break it yet
				}
			}
		}
		return func(unk0, a_stack, a_funcCallQuery);
	}

	static StackMatch FindCallInStack(RE::BSScript::Stack* a_stack, const char* scriptName, const char* functionName)
	{
		StackMatch result;
		if (a_stack == nullptr || scriptName == nullptr || functionName == nullptr) {
			return result;
		}

		RE::BSScript::StackFrame* stackFrame = a_stack->top;
		if (stackFrame == nullptr) {
			return result;
		}
		stackFrame = stackFrame->previousFrame; // Get the frame before the current function call, as we don't want to check against ourselves
		auto remainingFrames = a_stack->frames < kMaxFramesToScan ? a_stack->frames : kMaxFramesToScan;
		while (stackFrame != nullptr && remainingFrames-- > 0) { // Loop through all frames in the stack
			const auto owningFunction = stackFrame->owningFunction.get();
			if (owningFunction != nullptr) {
				const auto owningScriptName = owningFunction->GetObjectTypeName();
				const auto owningFunctionName = owningFunction->GetName();

				if (result.callerScript == "<unknown>" && result.callerFunction == "<unknown>") {
					result.callerScript = SafeName(owningScriptName.c_str());
					result.callerFunction = SafeName(owningFunctionName.c_str());
				}

				if (iequals(owningScriptName.c_str(), scriptName) &&
					iequals(owningFunctionName.c_str(), functionName)) {
					result.found = true;
					return result;
				}
			}
			stackFrame = stackFrame->previousFrame;
			++result.framesScanned;
		}
		return result;
	}

	static std::string SafeName(const char* value)
	{
		return value != nullptr && value[0] != '\0' ? value : "<unknown>";
	}

	static bool iequals(std::string_view a, std::string_view b)
	{
		std::size_t sz = a.size();
		if (b.size() != sz)
			return false;
		for (std::size_t i = 0; i < sz; ++i)
			if (ToLowerAscii(a[i]) != ToLowerAscii(b[i]))
				return false;
		return true;
	}

	static char ToLowerAscii(char c)
	{
		return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c;
	}

	static NotificationMode ParseNotificationMode(const char* modeName)
	{
		if (modeName == nullptr) {
			return NotificationMode::kOncePerSession;
		}
		const std::string_view mode{ modeName };
		if (iequals(mode, "none")) {
			return NotificationMode::kNone;
		}
		if (iequals(mode, "once_per_session")) {
			return NotificationMode::kOncePerSession;
		}
		if (iequals(mode, "cooldown")) {
			return NotificationMode::kCooldown;
		}
		if (iequals(mode, "popup")) {
			return NotificationMode::kPopup;
		}
		return NotificationMode::kOncePerSession;
	}

	static const char* NotificationModeName(NotificationMode mode)
	{
		switch (mode) {
		case NotificationMode::kNone:
			return "none";
		case NotificationMode::kOncePerSession:
			return "once_per_session";
		case NotificationMode::kCooldown:
			return "cooldown";
		case NotificationMode::kPopup:
			return "popup";
		}
		return "once_per_session";
	}

	static Settings LoadSettings()
	{
		Settings settings;
		CSimpleIniA ini;
		ini.SetUnicode();
		const auto settingsPath = GetSettingsPath();
		const auto result = ini.LoadFile(settingsPath.string().c_str());
		if (result < 0) {
			logger::info("Recursion settings not found at {}; using defaults", settingsPath.string());
			return settings;
		}

		settings.notificationMode = ParseNotificationMode(ini.GetValue("Notifications", "Mode", "once_per_session"));
		const auto rawCooldown = ini.GetLongValue("Notifications", "CooldownSeconds", 30);
		settings.cooldownSeconds = rawCooldown < 0 ? 0u : static_cast<std::uint32_t>(rawCooldown);
		return settings;
	}

	static const Settings& GetSettings()
	{
		static const Settings settings = LoadSettings();
		return settings;
	}

	static std::string BuildNotificationMessage(const char* scriptName, const char* functionName)
	{
		return fmt::format(
			"Recursion FPS Fix: prevented recursion in {}.{} (see SKSE log)",
			scriptName,
			functionName);
	}

	static bool ShouldNotifyCooldown(std::uint32_t cooldownSeconds)
	{
		const auto nowMs = static_cast<std::uint64_t>(
			std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now().time_since_epoch())
				.count());
		const auto cooldownMs = static_cast<std::uint64_t>(cooldownSeconds) * 1000ULL;
		auto lastMs = lastNotificationMillis.load(std::memory_order_relaxed);
		while (true) {
			if (lastMs != 0 && nowMs - lastMs < cooldownMs) {
				return false;
			}
			if (lastNotificationMillis.compare_exchange_weak(lastMs, nowMs, std::memory_order_relaxed)) {
				return true;
			}
		}
	}

	static void NotifyRecursion(const char* scriptName, const char* functionName)
	{
		const auto& settings = GetSettings();
		switch (settings.notificationMode) {
		case NotificationMode::kNone:
			return;
		case NotificationMode::kOncePerSession:
			if (hasNotifiedThisSession.exchange(true, std::memory_order_relaxed)) {
				return;
			}
			break;
		case NotificationMode::kCooldown:
		case NotificationMode::kPopup:
			if (!ShouldNotifyCooldown(settings.cooldownSeconds)) {
				return;
			}
			break;
		}

		const auto message = BuildNotificationMessage(scriptName, functionName);
		if (settings.notificationMode == NotificationMode::kPopup) {
			RE::DebugMessageBox(message.c_str());
		} else {
			RE::DebugNotification(message.c_str());
		}
	}

	static void LogRecursionExit(const char* scriptName, const char* functionName, const StackMatch& stackMatch, std::uint32_t frames, std::uint32_t count)
	{
		if (count <= 10 || count % 100 == 0) {
			logger::warn(
				"Papyrus recursion detected: {}.{} called {}.{} again while it was already in the stack (match {} frames below caller, total stack frames {}). Cancelling call to prevent FPS drop. Suppressed repeated warnings: {}",
				stackMatch.callerScript,
				stackMatch.callerFunction,
				scriptName,
				functionName,
				stackMatch.framesScanned,
				frames,
				count > 10 ? count - 10 : 0);
			spdlog::default_logger()->flush();
		}
	}

	static inline REL::Relocation<decltype(thunk)> func;
	static inline std::atomic<std::uint32_t> recursionEventCount{ 0 };
	static inline std::atomic<bool> hasNotifiedThisSession{ false };
	static inline std::atomic<std::uint64_t> lastNotificationMillis{ 0 };

	// Install our hook at the specified address
	static inline void Install()
	{
		REL::Relocation<std::uintptr_t> target{ RELOCATION_ID(98130, 104853), REL::VariantOffset(0x7F, 0x7F, 0x7F) };
		stl::write_thunk_call<StackOverFlowHook>(target.address());
	}
};

struct StackOverFlowLogHook
{
	static void thunk(RE::BSScript::Stack* a_stack, const char* a_source, std::uint32_t unk2, char* unk3, std::uint32_t sizeInBytes)
	{
		if (a_stack != nullptr && a_stack->frames > StackOverFlowHook::kPapyrusStackLimit) {
			func(a_stack, "StackFrameOverFlow exception, function call exceeded 1000 call stack limit - returning None", unk2, unk3, sizeInBytes);
		} else {
			func(a_stack, a_source, unk2, unk3, sizeInBytes);
		}
	}

	static inline REL::Relocation<decltype(thunk)> func;

	// Install our hook at the specified address
	static inline void Install()
	{
		REL::Relocation<std::uintptr_t> target{ RELOCATION_ID(98130, 104853), REL::VariantOffset(0x963, 0x97A, 0x963) };
		stl::write_thunk_call<StackOverFlowLogHook>(target.address());
	}
};
