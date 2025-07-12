// SPDX-FileCopyrightText: 2002-2025 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include "AnalysisFramework.h"

namespace AnalysisFramework
{
	/// Implementation of IDebugInterface that integrates with PCSX2's debug system
	class DebugInterface : public IDebugInterface
	{
	public:
		DebugInterface() = default;
		virtual ~DebugInterface() = default;

		/// Breakpoint management implementations
		bool SetBreakpoint(u32 address, bool enabled = true) override;
		bool RemoveBreakpoint(u32 address) override;
		bool IsBreakpointSet(u32 address) override;
		std::vector<u32> GetBreakpoints() override;

		/// Register access implementations
		u32 GetRegister(const std::string& regName) override;
		bool SetRegister(const std::string& regName, u32 value) override;
		std::unordered_map<std::string, u32> GetAllRegisters() override;

		/// Execution control implementations
		bool IsRunning() override;
		bool IsPaused() override;
		void Pause() override;
		void Resume() override;
		void StepInstruction() override;

		/// Disassembly implementations
		std::string DisassembleInstruction(u32 address) override;
		std::vector<std::string> DisassembleRange(u32 startAddress, u32 endAddress) override;

	private:
		/// Helper to validate register names
		bool IsValidRegisterName(const std::string& regName) const;

		/// Helper to convert register name to internal representation
		int GetRegisterIndex(const std::string& regName) const;
	};

} // namespace AnalysisFramework