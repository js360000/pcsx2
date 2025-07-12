// SPDX-FileCopyrightText: 2002-2025 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "PrecompiledHeader.h"
#include "DebugInterface.h"
#include "DebugTools/Breakpoints.h"
#include "DebugTools/DebugInterface.h"
#include "DebugTools/DisassemblyManager.h"
#include "R5900.h"
#include "VMManager.h"
#include "Console.h"
#include <unordered_set>

namespace AnalysisFramework
{
	bool DebugInterface::SetBreakpoint(u32 address, bool enabled)
	{
		try
		{
			if (!enabled)
				return RemoveBreakpoint(address);

			BreakPointCpu cpu = BreakPointCpu::EE; // Default to EE CPU
			CBreakPoints::AddBreakPoint(cpu, address, false);
			Console.WriteLn("(AnalysisFramework) Set breakpoint at 0x%08X", address);
			return true;
		}
		catch (...)
		{
			Console.Error("(AnalysisFramework) Failed to set breakpoint at 0x%08X", address);
			return false;
		}
	}

	bool DebugInterface::RemoveBreakpoint(u32 address)
	{
		try
		{
			BreakPointCpu cpu = BreakPointCpu::EE;
			CBreakPoints::RemoveBreakPoint(cpu, address);
			Console.WriteLn("(AnalysisFramework) Removed breakpoint at 0x%08X", address);
			return true;
		}
		catch (...)
		{
			Console.Error("(AnalysisFramework) Failed to remove breakpoint at 0x%08X", address);
			return false;
		}
	}

	bool DebugInterface::IsBreakpointSet(u32 address)
	{
		try
		{
			BreakPointCpu cpu = BreakPointCpu::EE;
			return CBreakPoints::IsAddressBreakPoint(cpu, address);
		}
		catch (...)
		{
			return false;
		}
	}

	std::vector<u32> DebugInterface::GetBreakpoints()
	{
		std::vector<u32> breakpoints;
		try
		{
			BreakPointCpu cpu = BreakPointCpu::EE;
			auto bps = CBreakPoints::GetBreakpoints(cpu);
			for (const auto& bp : bps)
			{
				breakpoints.push_back(bp.addr);
			}
		}
		catch (...)
		{
			Console.Error("(AnalysisFramework) Failed to get breakpoints list");
		}
		return breakpoints;
	}

	bool DebugInterface::IsValidRegisterName(const std::string& regName) const
	{
		// Common EE register names
		static const std::unordered_set<std::string> validRegs = {
			"zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
			"t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
			"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
			"t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra",
			"pc", "hi", "lo", "hi1", "lo1"
		};

		return validRegs.find(regName) != validRegs.end();
	}

	int DebugInterface::GetRegisterIndex(const std::string& regName) const
	{
		// Map register names to indices (simplified mapping)
		static const std::unordered_map<std::string, int> regMap = {
			{"zero", 0}, {"at", 1}, {"v0", 2}, {"v1", 3},
			{"a0", 4}, {"a1", 5}, {"a2", 6}, {"a3", 7},
			{"t0", 8}, {"t1", 9}, {"t2", 10}, {"t3", 11},
			{"t4", 12}, {"t5", 13}, {"t6", 14}, {"t7", 15},
			{"s0", 16}, {"s1", 17}, {"s2", 18}, {"s3", 19},
			{"s4", 20}, {"s5", 21}, {"s6", 22}, {"s7", 23},
			{"t8", 24}, {"t9", 25}, {"k0", 26}, {"k1", 27},
			{"gp", 28}, {"sp", 29}, {"fp", 30}, {"ra", 31}
		};

		auto it = regMap.find(regName);
		return (it != regMap.end()) ? it->second : -1;
	}

	u32 DebugInterface::GetRegister(const std::string& regName)
	{
		if (!IsValidRegisterName(regName))
		{
			Console.Error("(AnalysisFramework) Invalid register name: %s", regName.c_str());
			return 0;
		}

		try
		{
			if (regName == "pc")
				return cpuRegs.pc;
			else if (regName == "hi")
				return cpuRegs.hi.UD[0];
			else if (regName == "lo")
				return cpuRegs.lo.UD[0];
			else if (regName == "hi1")
				return cpuRegs.hi1.UD[0];
			else if (regName == "lo1")
				return cpuRegs.lo1.UD[0];
			else
			{
				int index = GetRegisterIndex(regName);
				if (index >= 0 && index < 32)
					return cpuRegs.GPR.r[index].UD[0];
			}
		}
		catch (...)
		{
			Console.Error("(AnalysisFramework) Exception reading register %s", regName.c_str());
		}

		return 0;
	}

	bool DebugInterface::SetRegister(const std::string& regName, u32 value)
	{
		if (!IsValidRegisterName(regName))
		{
			Console.Error("(AnalysisFramework) Invalid register name: %s", regName.c_str());
			return false;
		}

		try
		{
			if (regName == "pc")
				cpuRegs.pc = value;
			else if (regName == "hi")
				cpuRegs.hi.UD[0] = value;
			else if (regName == "lo")
				cpuRegs.lo.UD[0] = value;
			else if (regName == "hi1")
				cpuRegs.hi1.UD[0] = value;
			else if (regName == "lo1")
				cpuRegs.lo1.UD[0] = value;
			else
			{
				int index = GetRegisterIndex(regName);
				if (index >= 0 && index < 32)
				{
					if (index == 0) // $zero register cannot be modified
						return false;
					cpuRegs.GPR.r[index].UD[0] = value;
				}
				else
					return false;
			}

			Console.WriteLn("(AnalysisFramework) Set register %s = 0x%08X", regName.c_str(), value);
			return true;
		}
		catch (...)
		{
			Console.Error("(AnalysisFramework) Exception setting register %s", regName.c_str());
			return false;
		}
	}

	std::unordered_map<std::string, u32> DebugInterface::GetAllRegisters()
	{
		std::unordered_map<std::string, u32> registers;

		try
		{
			// General purpose registers
			const char* regNames[] = {
				"zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
				"t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
				"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
				"t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra"
			};

			for (int i = 0; i < 32; ++i)
			{
				registers[regNames[i]] = cpuRegs.GPR.r[i].UD[0];
			}

			// Special registers
			registers["pc"] = cpuRegs.pc;
			registers["hi"] = cpuRegs.hi.UD[0];
			registers["lo"] = cpuRegs.lo.UD[0];
			registers["hi1"] = cpuRegs.hi1.UD[0];
			registers["lo1"] = cpuRegs.lo1.UD[0];
		}
		catch (...)
		{
			Console.Error("(AnalysisFramework) Exception reading registers");
		}

		return registers;
	}

	bool DebugInterface::IsRunning()
	{
		return VMManager::GetState() == VMState::Running;
	}

	bool DebugInterface::IsPaused()
	{
		return VMManager::GetState() == VMState::Paused;
	}

	void DebugInterface::Pause()
	{
		if (IsRunning())
		{
			VMManager::SetPaused(true);
			Console.WriteLn("(AnalysisFramework) Paused execution");
		}
	}

	void DebugInterface::Resume()
	{
		if (IsPaused())
		{
			VMManager::SetPaused(false);
			Console.WriteLn("(AnalysisFramework) Resumed execution");
		}
	}

	void DebugInterface::StepInstruction()
	{
		// This would require integration with the debugger stepping system
		// For now, just log the request
		Console.WriteLn("(AnalysisFramework) Step instruction requested");
	}

	std::string DebugInterface::DisassembleInstruction(u32 address)
	{
		try
		{
			// Use existing disassembly system
			DisassemblyManager manager;
			auto line = manager.getLine(address, true);
			return line.text;
		}
		catch (...)
		{
			Console.Error("(AnalysisFramework) Failed to disassemble instruction at 0x%08X", address);
			return "";
		}
	}

	std::vector<std::string> DebugInterface::DisassembleRange(u32 startAddress, u32 endAddress)
	{
		std::vector<std::string> disassembly;

		try
		{
			DisassemblyManager manager;
			for (u32 addr = startAddress; addr <= endAddress; addr += 4)
			{
				auto line = manager.getLine(addr, true);
				disassembly.push_back(line.text);
			}
		}
		catch (...)
		{
			Console.Error("(AnalysisFramework) Failed to disassemble range 0x%08X-0x%08X", 
				startAddress, endAddress);
		}

		return disassembly;
	}

} // namespace AnalysisFramework