// SPDX-FileCopyrightText: 2002-2025 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "PrecompiledHeader.h"
#include "GhidraAnalyzer.h"
#include "AnalysisFramework/Core/AnalysisFramework.h"
#include "AnalysisFramework/Common/Utilities.h"
#include "Console.h"
#include <fstream>
#include <sstream>

namespace AnalysisFramework
{
	GhidraAnalyzer::GhidraAnalyzer() = default;

	GhidraAnalyzer::~GhidraAnalyzer()
	{
		Shutdown();
	}

	bool GhidraAnalyzer::Initialize()
	{
		if (m_initialized)
			return true;

		Console.WriteLn("(GhidraAnalyzer) Initializing Ghidra analyzer...");

		try
		{
			// Validate Ghidra installation
			if (!ValidateGhidraInstallation())
			{
				Console.Warning("(GhidraAnalyzer) Ghidra installation not found or invalid");
				// Continue initialization anyway for offline use
			}

			m_initialized = true;
			Console.WriteLn("(GhidraAnalyzer) Ghidra analyzer initialized successfully");
			return true;
		}
		catch (const std::exception& e)
		{
			Console.Error("(GhidraAnalyzer) Failed to initialize: %s", e.what());
			return false;
		}
	}

	void GhidraAnalyzer::Shutdown()
	{
		if (!m_initialized)
			return;

		Console.WriteLn("(GhidraAnalyzer) Shutting down Ghidra analyzer...");

		m_currentProject = {};
		m_initialized = false;

		Console.WriteLn("(GhidraAnalyzer) Ghidra analyzer shutdown complete");
	}

	void GhidraAnalyzer::OnFrameworkEvent(AnalysisEvent event, const void* data, size_t size)
	{
		// Handle framework events for automatic analysis
		switch (event)
		{
			case AnalysisEvent::GameStateChange:
				// Could trigger re-analysis when game changes
				break;
			case AnalysisEvent::BreakpointHit:
				// Could analyze code at breakpoint location
				break;
			default:
				break;
		}
	}

	bool GhidraAnalyzer::CreateGhidraProject(const GhidraProject& project)
	{
		Console.WriteLn("(GhidraAnalyzer) Creating Ghidra project: %s", project.programName.c_str());

		m_currentProject = project;

		// Generate Ghidra project creation script
		std::string scriptPath = project.projectPath + "/create_project.py";
		if (!CreateGhidraImportScript(scriptPath))
		{
			Console.Error("(GhidraAnalyzer) Failed to create project script");
			return false;
		}

		Console.WriteLn("(GhidraAnalyzer) Ghidra project creation script generated: %s", scriptPath.c_str());
		return true;
	}

	bool GhidraAnalyzer::ExportMemoryDump(const std::string& outputPath, u32 startAddress, u32 size)
	{
		auto& core = AnalysisFrameworkCore::GetInstance();
		auto memInterface = core.GetMemoryInterface();

		if (!memInterface)
		{
			Console.Error("(GhidraAnalyzer) Memory interface not available");
			return false;
		}

		if (!ValidationUtils::IsValidMemoryRange(startAddress, startAddress + size))
		{
			Console.Error("(GhidraAnalyzer) Invalid memory range: 0x%08X-0x%08X", 
				startAddress, startAddress + size);
			return false;
		}

		try
		{
			std::ofstream file(outputPath, std::ios::binary);
			if (!file.is_open())
			{
				Console.Error("(GhidraAnalyzer) Failed to open output file: %s", outputPath.c_str());
				return false;
			}

			// Export memory in chunks to avoid large allocations
			const size_t chunkSize = 64 * 1024; // 64KB chunks
			std::vector<u8> buffer(chunkSize);

			for (u32 offset = 0; offset < size; offset += chunkSize)
			{
				size_t currentChunkSize = std::min(chunkSize, static_cast<size_t>(size - offset));
				u32 currentAddress = startAddress + offset;

				if (memInterface->ReadMemory(currentAddress, buffer.data(), currentChunkSize))
				{
					file.write(reinterpret_cast<const char*>(buffer.data()), currentChunkSize);
				}
				else
				{
					// Fill with zeros for invalid memory
					std::fill(buffer.begin(), buffer.begin() + currentChunkSize, 0);
					file.write(reinterpret_cast<const char*>(buffer.data()), currentChunkSize);
				}
			}

			file.close();
			Console.WriteLn("(GhidraAnalyzer) Exported %u bytes to: %s", size, outputPath.c_str());
			return true;
		}
		catch (const std::exception& e)
		{
			Console.Error("(GhidraAnalyzer) Memory export failed: %s", e.what());
			return false;
		}
	}

	bool GhidraAnalyzer::ExportFullMemoryImage(const std::string& outputPath)
	{
		// Export main PS2 memory (32MB)
		return ExportMemoryDump(outputPath, 0x00000000, 0x02000000);
	}

	bool GhidraAnalyzer::GenerateGhidraScript(const std::string& scriptPath, const GhidraAnalysisConfig& config)
	{
		std::ofstream script(scriptPath);
		if (!script.is_open())
			return false;

		// Write Ghidra Python script header
		script << "# PCSX2 Analysis Framework - Ghidra Analysis Script\n";
		script << "# Generated automatically\n\n";
		script << "from ghidra.app.script import GhidraScript\n";
		script << "from ghidra.program.model.address import AddressSet\n";
		script << "from ghidra.app.util.importer import MessageLog\n";
		script << "from ghidra.app.services import DataTypeManagerService\n\n";

		script << "class PCSX2AnalysisScript(GhidraScript):\n";
		script << "    def run(self):\n";
		script << "        print(\"Running PCSX2 analysis on PS2 program...\")\n\n";

		// Memory map setup
		script << "        # Set up PS2 memory map\n";
		script << "        self.setup_ps2_memory_map()\n\n";

		// Analysis configuration
		if (config.enableFunctionAnalysis)
		{
			script << "        # Enable function analysis\n";
			script << "        self.analyzeProgram()\n\n";
		}

		if (config.enableDataTypeAnalysis)
		{
			script << "        # Apply PS2-specific data types\n";
			script << "        self.apply_ps2_data_types()\n\n";
		}

		if (config.enableStringAnalysis)
		{
			script << "        # Analyze strings\n";
			script << "        self.analyze_strings()\n\n";
		}

		// Helper methods
		script << "    def setup_ps2_memory_map(self):\n";
		script << "        \"\"\"Set up PS2-specific memory segments\"\"\"\n";
		script << "        memory = currentProgram.getMemory()\n";
		script << "        \n";
		script << "        # Main memory: 0x00000000-0x01FFFFFF (32MB)\n";
		script << "        # Scratchpad: 0x70000000-0x70003FFF (16KB)\n";
		script << "        # I/O: 0x10000000-0x1FFFFFFF\n";
		script << "        # BIOS: 0x1FC00000-0x1FFFFFFF\n";
		script << "        pass\n\n";

		script << "    def apply_ps2_data_types(self):\n";
		script << "        \"\"\"Apply PS2-specific data types and structures\"\"\"\n";
		script << "        # Could define PS2 system structures here\n";
		script << "        pass\n\n";

		script << "    def analyze_strings(self):\n";
		script << "        \"\"\"Find and analyze string data\"\"\"\n";
		script << "        # String analysis specific to PS2 games\n";
		script << "        pass\n\n";

		script << "# Create and run the script\n";
		script << "if __name__ == \"__main__\":\n";
		script << "    script = PCSX2AnalysisScript()\n";
		script << "    script.run()\n";

		script.close();
		Console.WriteLn("(GhidraAnalyzer) Generated Ghidra analysis script: %s", scriptPath.c_str());
		return true;
	}

	bool GhidraAnalyzer::CreateGhidraImportScript(const std::string& scriptPath)
	{
		std::ofstream script(scriptPath);
		if (!script.is_open())
			return false;

		script << "# PCSX2 Analysis Framework - Ghidra Import Script\n";
		script << "# Import PS2 memory dump into Ghidra\n\n";
		script << "from ghidra.app.util.importer import MessageLog\n";
		script << "from ghidra.app.util.opinion import LoadResults\n";
		script << "from ghidra.framework.model import DomainFile\n";
		script << "from ghidra.framework.model import DomainFolder\n";
		script << "from ghidra.program.database import ProgramDB\n\n";

		script << "def import_ps2_memory():\n";
		script << "    \"\"\"Import PS2 memory dump into Ghidra project\"\"\"\n";
		script << "    print(\"Importing PS2 memory dump...\")\n\n";

		script << "    # Project and program configuration\n";
		script << "    project_name = \"" << m_currentProject.programName << "\"\n";
		script << "    language_id = \"" << GetGhidraLanguageSpec() << "\"\n";
		script << "    compiler_spec = \"default\"\n\n";

		script << "    # Memory layout for PS2\n";
		script << "    memory_layout = {\n";
		script << "        'main_memory': {'start': 0x00000000, 'size': 0x02000000},\n";
		script << "        'scratchpad': {'start': 0x70000000, 'size': 0x00004000},\n";
		script << "        'io_registers': {'start': 0x10000000, 'size': 0x10000000},\n";
		script << "        'bios_rom': {'start': 0x1FC00000, 'size': 0x00400000}\n";
		script << "    }\n\n";

		script << "    print(\"PS2 memory import configuration complete\")\n\n";

		script << "# Execute import\n";
		script << "import_ps2_memory()\n";

		script.close();
		return true;
	}

	std::string GhidraAnalyzer::GetGhidraLanguageSpec()
	{
		// PS2 uses MIPS R5900 (little-endian, 32-bit)
		return "mips:LE:32:R5900";
	}

	std::string GhidraAnalyzer::GenerateMemoryMap()
	{
		std::stringstream map;
		
		map << "PS2 Memory Map:\n";
		map << "0x00000000-0x01FFFFFF: Main Memory (32MB)\n";
		map << "0x70000000-0x70003FFF: Scratchpad (16KB)\n";
		map << "0x10000000-0x1FFFFFFF: I/O Registers\n";
		map << "0x1FC00000-0x1FFFFFFF: BIOS ROM\n";
		
		return map.str();
	}

	bool GhidraAnalyzer::ValidateGhidraInstallation()
	{
		// Check for common Ghidra installation paths
		// This is a simplified check - real implementation would be more thorough
		Console.WriteLn("(GhidraAnalyzer) Validating Ghidra installation...");
		
		// For now, assume Ghidra is not installed but scripts can still be generated
		return false;
	}

	std::string GhidraAnalyzer::DecompileFunction(u32 functionAddress)
	{
		// This would require integration with Ghidra's decompiler
		// For now, return a placeholder
		Console.WriteLn("(GhidraAnalyzer) Decompilation requested for function at 0x%08X", 
			functionAddress);
		return "// Decompilation not yet implemented";
	}

	bool GhidraAnalyzer::ExportSymbolsToGhidra(const std::string& symbolsPath)
	{
		Console.WriteLn("(GhidraAnalyzer) Exporting symbols for Ghidra import: %s", symbolsPath.c_str());
		
		// This would export symbols in a format Ghidra can import
		// Implementation would depend on available symbol data
		
		return true;
	}

	bool GhidraAnalyzer::InstallPS2Processor()
	{
		Console.WriteLn("(GhidraAnalyzer) PS2 processor module installation requested");
		
		// This would create/install a custom processor module for PS2
		// The PS2 uses a modified MIPS R5900 with additional instructions
		
		return true;
	}

} // namespace AnalysisFramework