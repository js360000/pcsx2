// SPDX-FileCopyrightText: 2002-2025 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include "AnalysisFramework/Core/AnalysisFramework.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>

namespace AnalysisFramework
{
	/// Structure representing a cheat/code entry
	struct CheatEntry
	{
		u32 address;
		u32 value;
		u32 originalValue;
		std::string description;
		std::string type; // "8bit", "16bit", "32bit", "float", "double", "string"
		bool enabled = false;
		bool locked = false; // Continuously apply the value
	};

	/// Structure for memory scan criteria
	struct ScanCriteria
	{
		enum class ScanType
		{
			ExactValue,
			Range,
			IncreasedValue,
			DecreasedValue,
			ChangedValue,
			UnchangedValue,
			Pattern
		};

		ScanType scanType = ScanType::ExactValue;
		std::string valueType = "32bit"; // "8bit", "16bit", "32bit", "float", "double"
		std::vector<u8> searchValue;
		std::vector<u8> searchValue2; // For range scans
		std::vector<u8> pattern;
		std::vector<bool> mask;
		u32 startAddress = 0x00000000;
		u32 endAddress = 0x02000000;
		u32 alignment = 1;
	};

	/// Structure representing scan results
	struct ScanResults
	{
		std::vector<u32> addresses;
		std::vector<std::vector<u8>> values;
		size_t totalResults = 0;
		bool tooManyResults = false;
		static constexpr size_t MAX_RESULTS = 10000;
	};

	/// CheatEngine-compatible memory analysis module
	class CheatEngine : public IAnalysisModule
	{
	public:
		CheatEngine();
		virtual ~CheatEngine();

		/// IAnalysisModule implementation
		const std::string& GetModuleId() const override { return m_moduleId; }
		const std::string& GetModuleName() const override { return m_moduleName; }
		const std::string& GetModuleVersion() const override { return m_moduleVersion; }

		bool Initialize() override;
		void Shutdown() override;
		bool IsInitialized() const override { return m_initialized; }

		void OnFrameworkEvent(AnalysisEvent event, const void* data, size_t size) override;

		/// Memory scanning functionality
		ScanResults ScanMemory(const ScanCriteria& criteria);
		ScanResults RescanMemory(const ScanResults& previousResults, const ScanCriteria& criteria);
		void ClearScanResults();

		/// Cheat management
		bool AddCheat(const CheatEntry& cheat);
		bool RemoveCheat(u32 address);
		bool EnableCheat(u32 address, bool enabled = true);
		bool SetCheatValue(u32 address, u32 newValue);
		CheatEntry GetCheat(u32 address) const;
		std::vector<CheatEntry> GetAllCheats() const;

		/// Cheat table import/export
		bool ExportCheatTable(const std::string& filePath);
		bool ImportCheatTable(const std::string& filePath);

		/// Real-time value monitoring
		using ValueChangeCallback = std::function<void(u32 address, u32 oldValue, u32 newValue)>;
		bool AddWatchAddress(u32 address, ValueChangeCallback callback = nullptr);
		bool RemoveWatchAddress(u32 address);
		void ProcessWatchedAddresses();

		/// Code injection and modification
		bool InjectCode(u32 address, const std::vector<u8>& code, bool backup = true);
		bool RestoreOriginalCode(u32 address);
		std::vector<u8> GetOriginalCode(u32 address) const;

		/// Freeze/lock functionality
		void ProcessFrozenValues();
		void SetFreezeEnabled(bool enabled) { m_freezeEnabled = enabled; }
		bool IsFreezeEnabled() const { return m_freezeEnabled; }

	private:
		// Module identification
		std::string m_moduleId = "cheat_engine";
		std::string m_moduleName = "CheatEngine Memory Scanner";
		std::string m_moduleVersion = "1.0.0";

		bool m_initialized = false;
		bool m_freezeEnabled = true;

		// Cheat and scan data
		std::unordered_map<u32, CheatEntry> m_cheats;
		ScanResults m_lastScanResults;

		// Watch system
		struct WatchEntry
		{
			u32 address;
			u32 lastValue;
			ValueChangeCallback callback;
		};
		std::vector<WatchEntry> m_watchedAddresses;

		// Code injection tracking
		struct CodeBackup
		{
			u32 address;
			std::vector<u8> originalCode;
			std::vector<u8> injectedCode;
		};
		std::unordered_map<u32, CodeBackup> m_codeBackups;

		/// Helper functions
		bool MatchesCriteria(const std::vector<u8>& value, const std::vector<u8>& previousValue,
							 const ScanCriteria& criteria);
		std::vector<u8> ReadValueAtAddress(u32 address, const std::string& valueType);
		bool WriteValueAtAddress(u32 address, const std::vector<u8>& value);
		size_t GetValueSize(const std::string& valueType);
		
		/// Scan optimization
		void OptimizeScanRange(u32& startAddress, u32& endAddress);
		bool IsValidScanAddress(u32 address, const std::string& valueType);

		/// Cheat table format helpers
		bool WriteCheatTableXML(const std::string& filePath);
		bool ReadCheatTableXML(const std::string& filePath);
	};

} // namespace AnalysisFramework