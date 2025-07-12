// SPDX-FileCopyrightText: 2002-2025 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include "AnalysisFramework/Core/AnalysisFramework.h"
#include <string>
#include <vector>
#include <unordered_map>

namespace AnalysisFramework
{
	/// Structure representing symbol information for export to IDA Pro
	struct SymbolInfo
	{
		u32 address;
		std::string name;
		std::string type; // "function", "data", "label"
		u32 size;
		std::string section; // ".text", ".data", ".rodata", etc.
	};

	/// Structure representing function information
	struct FunctionInfo
	{
		u32 startAddress;
		u32 endAddress;
		std::string name;
		std::vector<u32> callTargets;
		std::vector<u32> callers;
		bool isThumb = false; // For ARM compatibility
	};

	/// IDA Pro integration module
	class IDAInterface : public IAnalysisModule
	{
	public:
		IDAInterface();
		virtual ~IDAInterface();

		/// IAnalysisModule implementation
		const std::string& GetModuleId() const override { return m_moduleId; }
		const std::string& GetModuleName() const override { return m_moduleName; }
		const std::string& GetModuleVersion() const override { return m_moduleVersion; }

		bool Initialize() override;
		void Shutdown() override;
		bool IsInitialized() const override { return m_initialized; }

		void OnFrameworkEvent(AnalysisEvent event, const void* data, size_t size) override;

		/// IDA Pro specific functionality
		bool ExportToIDADatabase(const std::string& outputPath);
		bool ImportFromIDADatabase(const std::string& inputPath);

		/// Symbol management
		bool AddSymbol(const SymbolInfo& symbol);
		bool RemoveSymbol(u32 address);
		SymbolInfo GetSymbol(u32 address) const;
		std::vector<SymbolInfo> GetAllSymbols() const;

		/// Function analysis
		bool AnalyzeFunction(u32 startAddress);
		FunctionInfo GetFunctionInfo(u32 address) const;
		std::vector<FunctionInfo> GetAllFunctions() const;

		/// Cross-reference generation
		std::vector<u32> GetCrossReferences(u32 address) const;
		void GenerateCodeCrossReferences();

		/// PS2 ELF support
		bool LoadPS2ELF(const std::string& elfPath);
		bool ExportPS2Symbols(const std::string& outputPath);

	private:
		// Module identification
		std::string m_moduleId = "ida_interface";
		std::string m_moduleName = "IDA Pro Interface";
		std::string m_moduleVersion = "1.0.0";

		bool m_initialized = false;

		// Symbol database
		std::unordered_map<u32, SymbolInfo> m_symbols;
		std::vector<FunctionInfo> m_functions;

		/// Helper functions
		bool CreateIDAScript(const std::string& scriptPath, const std::vector<SymbolInfo>& symbols);
		bool ParseIDAExport(const std::string& exportPath);
		std::string FormatIDACommand(const std::string& command, u32 address, const std::string& name = "");

		/// PS2-specific helpers
		bool IsPS2Instruction(u32 instruction);
		std::string DisassemblePS2Instruction(u32 address, u32 instruction);
	};

} // namespace AnalysisFramework