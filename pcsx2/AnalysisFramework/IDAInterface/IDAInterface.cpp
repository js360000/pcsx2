// SPDX-FileCopyrightText: 2002-2025 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "PrecompiledHeader.h"
#include "IDAInterface.h"
#include "AnalysisFramework/Core/AnalysisFramework.h"
#include "AnalysisFramework/Common/Utilities.h"
#include "Console.h"
#include "Elfheader.h"
#include <fstream>
#include <sstream>

namespace AnalysisFramework
{
	IDAInterface::IDAInterface() = default;

	IDAInterface::~IDAInterface()
	{
		Shutdown();
	}

	bool IDAInterface::Initialize()
	{
		if (m_initialized)
			return true;

		Console.WriteLn("(IDAInterface) Initializing IDA Pro interface...");

		try
		{
			m_initialized = true;
			Console.WriteLn("(IDAInterface) IDA Pro interface initialized successfully");
			return true;
		}
		catch (const std::exception& e)
		{
			Console.Error("(IDAInterface) Failed to initialize: %s", e.what());
			return false;
		}
	}

	void IDAInterface::Shutdown()
	{
		if (!m_initialized)
			return;

		Console.WriteLn("(IDAInterface) Shutting down IDA Pro interface...");

		m_symbols.clear();
		m_functions.clear();
		m_initialized = false;

		Console.WriteLn("(IDAInterface) IDA Pro interface shutdown complete");
	}

	void IDAInterface::OnFrameworkEvent(AnalysisEvent event, const void* data, size_t size)
	{
		// Handle framework events for symbol discovery and analysis
		switch (event)
		{
			case AnalysisEvent::MemoryRead:
			case AnalysisEvent::MemoryWrite:
				// Could be used for dynamic symbol discovery
				break;
			case AnalysisEvent::BreakpointHit:
				// Analyze function at breakpoint
				if (data && size >= sizeof(u32))
				{
					u32 address = *static_cast<const u32*>(data);
					AnalyzeFunction(address);
				}
				break;
			default:
				break;
		}
	}

	bool IDAInterface::AddSymbol(const SymbolInfo& symbol)
	{
		if (!AddressUtils::IsValidPS2Address(symbol.address))
		{
			Console.Error("(IDAInterface) Invalid symbol address: 0x%08X", symbol.address);
			return false;
		}

		m_symbols[symbol.address] = symbol;
		Console.WriteLn("(IDAInterface) Added symbol '%s' at 0x%08X", 
			symbol.name.c_str(), symbol.address);
		return true;
	}

	bool IDAInterface::RemoveSymbol(u32 address)
	{
		auto it = m_symbols.find(address);
		if (it != m_symbols.end())
		{
			Console.WriteLn("(IDAInterface) Removed symbol '%s' at 0x%08X", 
				it->second.name.c_str(), address);
			m_symbols.erase(it);
			return true;
		}
		return false;
	}

	SymbolInfo IDAInterface::GetSymbol(u32 address) const
	{
		auto it = m_symbols.find(address);
		return (it != m_symbols.end()) ? it->second : SymbolInfo{};
	}

	std::vector<SymbolInfo> IDAInterface::GetAllSymbols() const
	{
		std::vector<SymbolInfo> symbols;
		symbols.reserve(m_symbols.size());
		
		for (const auto& [address, symbol] : m_symbols)
		{
			symbols.push_back(symbol);
		}
		
		return symbols;
	}

	bool IDAInterface::AnalyzeFunction(u32 startAddress)
	{
		if (!AddressUtils::IsValidPS2Address(startAddress))
			return false;

		auto& core = AnalysisFrameworkCore::GetInstance();
		auto memInterface = core.GetMemoryInterface();
		auto debugInterface = core.GetDebugInterface();

		if (!memInterface || !debugInterface)
			return false;

		FunctionInfo function;
		function.startAddress = startAddress;
		function.name = "sub_" + HexUtils::ToHex(startAddress, false);

		// Simple function analysis - scan forward until return or invalid instruction
		u32 currentAddress = startAddress;
		const u32 maxFunctionSize = 4096; // Reasonable limit
		
		while (currentAddress < startAddress + maxFunctionSize)
		{
			if (!memInterface->IsValidAddress(currentAddress))
				break;

			u32 instruction = memInterface->ReadMemory32(currentAddress);
			
			// Check for PS2 MIPS return instruction (jr $ra)
			if ((instruction & 0xFC1FFFFF) == 0x03E00008) // jr $ra
			{
				function.endAddress = currentAddress + 4; // Include delay slot
				break;
			}

			// Check for function calls (jal instructions)
			if ((instruction & 0xFC000000) == 0x0C000000) // jal
			{
				u32 target = ((instruction & 0x03FFFFFF) << 2) | (currentAddress & 0xF0000000);
				function.callTargets.push_back(target);
			}

			currentAddress += 4;
		}

		// If we didn't find an end, use current position
		if (function.endAddress == 0)
			function.endAddress = currentAddress;

		m_functions.push_back(function);
		
		// Add as symbol too
		SymbolInfo symbol;
		symbol.address = startAddress;
		symbol.name = function.name;
		symbol.type = "function";
		symbol.size = function.endAddress - function.startAddress;
		symbol.section = ".text";
		
		AddSymbol(symbol);

		Console.WriteLn("(IDAInterface) Analyzed function at 0x%08X (size: %u bytes)", 
			startAddress, symbol.size);
		return true;
	}

	FunctionInfo IDAInterface::GetFunctionInfo(u32 address) const
	{
		for (const auto& func : m_functions)
		{
			if (address >= func.startAddress && address < func.endAddress)
				return func;
		}
		return FunctionInfo{};
	}

	std::vector<FunctionInfo> IDAInterface::GetAllFunctions() const
	{
		return m_functions;
	}

	std::vector<u32> IDAInterface::GetCrossReferences(u32 address) const
	{
		std::vector<u32> xrefs;
		
		// Find all functions that call this address
		for (const auto& func : m_functions)
		{
			for (u32 target : func.callTargets)
			{
				if (target == address)
				{
					xrefs.push_back(func.startAddress);
					break;
				}
			}
		}
		
		return xrefs;
	}

	void IDAInterface::GenerateCodeCrossReferences()
	{
		Console.WriteLn("(IDAInterface) Generating cross-references...");
		
		// Update caller information for all functions
		for (auto& func : m_functions)
		{
			func.callers.clear();
			for (u32 target : func.callTargets)
			{
				// Find function containing target
				for (auto& targetFunc : m_functions)
				{
					if (target >= targetFunc.startAddress && target < targetFunc.endAddress)
					{
						targetFunc.callers.push_back(func.startAddress);
						break;
					}
				}
			}
		}
		
		Console.WriteLn("(IDAInterface) Cross-reference generation complete");
	}

	bool IDAInterface::ExportToIDADatabase(const std::string& outputPath)
	{
		try
		{
			std::string scriptPath = outputPath + ".py";
			if (!CreateIDAScript(scriptPath, GetAllSymbols()))
			{
				Console.Error("(IDAInterface) Failed to create IDA script");
				return false;
			}
			
			Console.WriteLn("(IDAInterface) Exported IDA script to: %s", scriptPath.c_str());
			return true;
		}
		catch (const std::exception& e)
		{
			Console.Error("(IDAInterface) Export failed: %s", e.what());
			return false;
		}
	}

	bool IDAInterface::CreateIDAScript(const std::string& scriptPath, const std::vector<SymbolInfo>& symbols)
	{
		std::ofstream script(scriptPath);
		if (!script.is_open())
			return false;

		// Write IDA Python script header
		script << "# PCSX2 Analysis Framework - IDA Pro Import Script\n";
		script << "# Generated automatically - do not modify manually\n\n";
		script << "import ida_name\n";
		script << "import ida_auto\n";
		script << "import ida_funcs\n\n";

		script << "def apply_pcsx2_analysis():\n";
		script << "    \"\"\"Apply PCSX2 analysis results to IDA database\"\"\"\n";
		script << "    print(\"Applying PCSX2 analysis results...\")\n\n";

		// Add symbols
		for (const auto& symbol : symbols)
		{
			if (symbol.type == "function")
			{
				script << "    # Function: " << symbol.name << "\n";
				script << "    ida_funcs.add_func(0x" << std::hex << symbol.address << ")\n";
				script << "    ida_name.set_name(0x" << std::hex << symbol.address 
					   << ", \"" << symbol.name << "\")\n\n";
			}
			else
			{
				script << "    # " << symbol.type << ": " << symbol.name << "\n";
				script << "    ida_name.set_name(0x" << std::hex << symbol.address 
					   << ", \"" << symbol.name << "\")\n\n";
			}
		}

		script << "    ida_auto.auto_wait()\n";
		script << "    print(\"PCSX2 analysis applied successfully!\")\n\n";
		script << "# Execute the analysis\n";
		script << "apply_pcsx2_analysis()\n";

		script.close();
		return true;
	}

	bool IDAInterface::LoadPS2ELF(const std::string& elfPath)
	{
		Console.WriteLn("(IDAInterface) Loading PS2 ELF: %s", elfPath.c_str());

		// This would integrate with PCSX2's existing ELF loading code
		// For now, provide a placeholder implementation
		
		// In a full implementation, this would:
		// 1. Parse the ELF header and sections
		// 2. Extract symbol table information
		// 3. Add symbols to our database
		// 4. Analyze entry point and exported functions

		Console.WriteLn("(IDAInterface) PS2 ELF loading not yet fully implemented");
		return false;
	}

	bool IDAInterface::ExportPS2Symbols(const std::string& outputPath)
	{
		std::ofstream file(outputPath);
		if (!file.is_open())
			return false;

		file << "# PS2 Symbol Export from PCSX2 Analysis Framework\n";
		file << "# Format: address type name section\n\n";

		for (const auto& [address, symbol] : m_symbols)
		{
			file << HexUtils::ToHex(address, false) << " " 
				 << symbol.type << " " 
				 << symbol.name << " " 
				 << symbol.section << "\n";
		}

		file.close();
		Console.WriteLn("(IDAInterface) Exported %zu symbols to: %s", 
			m_symbols.size(), outputPath.c_str());
		return true;
	}

	std::string IDAInterface::FormatIDACommand(const std::string& command, u32 address, const std::string& name)
	{
		std::stringstream ss;
		ss << command << "(0x" << std::hex << address;
		if (!name.empty())
			ss << ", \"" << name << "\"";
		ss << ")";
		return ss.str();
	}

	bool IDAInterface::IsPS2Instruction(u32 instruction)
	{
		// Basic validation for PS2 MIPS instructions
		// This is a simplified check - real implementation would be more comprehensive
		return instruction != 0 && instruction != 0xFFFFFFFF;
	}

	std::string IDAInterface::DisassemblePS2Instruction(u32 address, u32 instruction)
	{
		auto& core = AnalysisFrameworkCore::GetInstance();
		if (auto debugInterface = core.GetDebugInterface())
		{
			return debugInterface->DisassembleInstruction(address);
		}
		
		return HexUtils::ToHex(instruction);
	}

} // namespace AnalysisFramework