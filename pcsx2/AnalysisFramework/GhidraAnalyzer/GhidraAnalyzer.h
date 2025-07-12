// SPDX-FileCopyrightText: 2002-2025 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include "AnalysisFramework/Core/AnalysisFramework.h"
#include <string>
#include <vector>
#include <memory>

namespace AnalysisFramework
{
	/// Structure for Ghidra project information
	struct GhidraProject
	{
		std::string projectPath;
		std::string programName;
		std::string language; // "mips:LE:32:default" for PS2
		std::string compiler; // "gcc" or "default"
	};

	/// Structure for Ghidra analysis configuration
	struct GhidraAnalysisConfig
	{
		bool enableDecompiler = true;
		bool enableFunctionAnalysis = true;
		bool enableDataTypeAnalysis = true;
		bool enableStringAnalysis = true;
		bool enableSymbolAnalysis = true;
		std::vector<std::string> customAnalyzers;
	};

	/// Ghidra integration and analysis module
	class GhidraAnalyzer : public IAnalysisModule
	{
	public:
		GhidraAnalyzer();
		virtual ~GhidraAnalyzer();

		/// IAnalysisModule implementation
		const std::string& GetModuleId() const override { return m_moduleId; }
		const std::string& GetModuleName() const override { return m_moduleName; }
		const std::string& GetModuleVersion() const override { return m_moduleVersion; }

		bool Initialize() override;
		void Shutdown() override;
		bool IsInitialized() const override { return m_initialized; }

		void OnFrameworkEvent(AnalysisEvent event, const void* data, size_t size) override;

		/// Ghidra project management
		bool CreateGhidraProject(const GhidraProject& project);
		bool LoadGhidraProject(const std::string& projectPath);
		bool ExportToGhidra(const std::string& outputPath);

		/// Memory export for Ghidra analysis
		bool ExportMemoryDump(const std::string& outputPath, u32 startAddress, u32 size);
		bool ExportFullMemoryImage(const std::string& outputPath);

		/// Symbol and function export
		bool ExportSymbolsToGhidra(const std::string& symbolsPath);
		bool ImportSymbolsFromGhidra(const std::string& symbolsPath);

		/// Analysis automation
		bool RunGhidraAnalysis(const GhidraAnalysisConfig& config);
		bool GenerateGhidraScript(const std::string& scriptPath, const GhidraAnalysisConfig& config);

		/// PS2-specific processors and loaders
		bool InstallPS2Processor();
		bool InstallPS2Loader();

		/// Decompilation support
		std::string DecompileFunction(u32 functionAddress);
		bool ExportDecompiledCode(const std::string& outputPath);

		/// Database synchronization
		bool SyncWithGhidraDatabase(const std::string& databasePath);

	private:
		// Module identification
		std::string m_moduleId = "ghidra_analyzer";
		std::string m_moduleName = "Ghidra Analyzer Integration";
		std::string m_moduleVersion = "1.0.0";

		bool m_initialized = false;
		GhidraProject m_currentProject;

		/// Script generation helpers
		bool CreateGhidraImportScript(const std::string& scriptPath);
		bool CreatePS2ProcessorScript(const std::string& scriptPath);
		bool CreateAnalysisScript(const std::string& scriptPath, const GhidraAnalysisConfig& config);

		/// Memory layout helpers
		std::string GenerateMemoryMap();
		bool CreateMemorySegments(const std::string& scriptPath);

		/// Utility functions
		std::string GetGhidraLanguageSpec();
		std::string FormatGhidraCommand(const std::string& command, const std::vector<std::string>& args = {});
		bool ValidateGhidraInstallation();
	};

} // namespace AnalysisFramework