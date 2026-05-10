#pragma once
#include "PCH.h"

#include <atomic>
#include <string_view>

struct StackOverFlowHook
{
	using FuncCallQueryPtr = RE::BSTSmartPointer<RE::BSScript::Internal::IFuncCallQuery>;

	static constexpr std::uint32_t kPapyrusStackLimit = 1000;
	static constexpr std::uint32_t kMaxFramesToScan = 4096;

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

				if (scriptName != nullptr && IsCallInStack(a_stack, scriptName, functionNameString)) {
					LogRecursionExit(scriptName, functionNameString, a_stack->frames);
					a_funcCallQuery->reset();
				} else {
					// might be a regular native call or something not directly causing recursion, don't break it yet
				}
			}
		}
		return func(unk0, a_stack, a_funcCallQuery);
	}

	static bool IsCallInStack(RE::BSScript::Stack* a_stack, const char* scriptName, const char* functionName)
	{
		if (a_stack == nullptr || scriptName == nullptr || functionName == nullptr) {
			return false;
		}

		RE::BSScript::StackFrame* stackFrame = a_stack->top;
		if (stackFrame == nullptr) {
			return false;
		}
		stackFrame = stackFrame->previousFrame; // Get the frame before the current function call, as we don't want to check against ourselves
		auto remainingFrames = a_stack->frames < kMaxFramesToScan ? a_stack->frames : kMaxFramesToScan;
		while (stackFrame != nullptr && remainingFrames-- > 0) { // Loop through all frames in the stack
			const auto owningFunction = stackFrame->owningFunction.get();
			if (owningFunction != nullptr) {
				const auto owningScriptName = owningFunction->GetObjectTypeName().c_str();
				const auto owningFunctionName = owningFunction->GetName().c_str();

				if (owningScriptName != nullptr &&
					owningFunctionName != nullptr &&
					iequals(owningScriptName, scriptName) &&
					iequals(owningFunctionName, functionName)) {
					return true;
				}
			}
			stackFrame = stackFrame->previousFrame;
		}
		return false;
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

	static void LogRecursionExit(const char* scriptName, const char* functionName, std::uint32_t frames)
	{
		const auto count = recursionLogCount.fetch_add(1, std::memory_order_relaxed) + 1;
		if (count <= 10 || count % 100 == 0) {
			logger::warn(
				"Papyrus recursion detected in {}.{} with {} stack frames; cancelling call to prevent FPS drop. Suppressed repeated warnings: {}",
				scriptName,
				functionName,
				frames,
				count > 10 ? count - 10 : 0);
		}
	}

	static inline REL::Relocation<decltype(thunk)> func;
	static inline std::atomic<std::uint32_t> recursionLogCount{ 0 };

	// Install our hook at the specified address
	static inline void Install()
	{
		REL::Relocation<std::uintptr_t> target{ RELOCATION_ID(98130, 104853), REL::VariantOffset(0x7F, 0x7F, 0x7F) };
		stl::write_thunk_call<StackOverFlowHook>(target.address());

		logger::info("StackFrameOverFlow hooked at address {}", fmt::format("{:x}", target.address()));
		logger::info("StackFrameOverFlow hooked at offset {}", fmt::format("{:x}", target.offset()));
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

		logger::info("StackFrameOverFlowLog hooked at address {}", fmt::format("{:x}", target.address()));
		logger::info("StackFrameOverFlowLog hooked at offset {}", fmt::format("{:x}", target.offset()));
	}
};
