// SPDX-FileCopyrightText: 2002-2025 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "CheatEngine.h"
#include "AnalysisFramework/Core/MemoryInterface.h"
#include "AnalysisFramework/Core/AnalysisFramework.h"
#include "Common.h"
#include <algorithm>
#include <regex>
#include <thread>

namespace AnalysisFramework
{
	CheatEngine::CheatEngine()
	{
	}

	CheatEngine::~CheatEngine()
	{
		Shutdown();
	}

	bool CheatEngine::Initialize()
	{
		if (m_initialized)
			return true;

		Console.WriteLn("(CheatEngine) Initializing CheatEngine module...");

		// Initialize data structures
		m_cheats.clear();
		m_scanResults.clear();
		m_lastScanResults.clear();

		m_initialized = true;
		Console.WriteLn("(CheatEngine) CheatEngine module initialized successfully");
		return true;
	}

	void CheatEngine::Shutdown()
	{
		if (!m_initialized)
			return;

		Console.WriteLn("(CheatEngine) Shutting down CheatEngine module...");

		StopContinuousScanning();
		
		m_cheats.clear();
		m_scanResults.clear();
		m_lastScanResults.clear();
		
		m_initialized = false;
		Console.WriteLn("(CheatEngine) CheatEngine module shut down");
	}

	void CheatEngine::OnFrameworkEvent(AnalysisEvent event, const void* data, size_t size)
	{
		if (!m_initialized)
			return;

		// Handle memory access events for enhanced pattern detection
		switch (event)
		{
		case AnalysisEvent::MemoryWrite:
			if (data && size >= sizeof(u32))
			{
				u32 address = *static_cast<const u32*>(data);
				DetectWritePatterns(address);
			}
			break;
		case AnalysisEvent::MemoryRead:
			// Track frequently read addresses for pattern analysis
			break;
		}
	}

	std::vector<ScanResult> CheatEngine::ScanMemory(const ScanCriteria& criteria)
	{
		std::vector<ScanResult> results;
		
		auto memInterface = AnalysisFrameworkCore::GetInstance().GetMemoryInterface();
		if (!memInterface)
		{
			Console.Error("(CheatEngine) Memory interface not available");
			return results;
		}

		Console.WriteLn("(CheatEngine) Starting memory scan from 0x%08X to 0x%08X", 
						criteria.startAddress, criteria.endAddress);

		// Perform scan based on criteria type
		switch (criteria.scanType)
		{
		case ScanCriteria::ScanType::ExactValue:
			results = ScanExactValue(criteria, memInterface);
			break;
		case ScanCriteria::ScanType::Range:
			results = ScanRange(criteria, memInterface);
			break;
		case ScanCriteria::ScanType::Pattern:
			results = ScanPattern(criteria, memInterface);
			break;
		case ScanCriteria::ScanType::ChangedValue:
			results = ScanChangedValues(criteria, memInterface);
			break;
		case ScanCriteria::ScanType::UnchangedValue:
			results = ScanUnchangedValues(criteria, memInterface);
			break;
		case ScanCriteria::ScanType::IncreasedValue:
			results = ScanIncreasedValues(criteria, memInterface);
			break;
		case ScanCriteria::ScanType::DecreasedValue:
			results = ScanDecreasedValues(criteria, memInterface);
			break;
		}

		// Store results for next scan comparison
		m_lastScanResults = results;
		m_scanResults = results;

		Console.WriteLn("(CheatEngine) Memory scan completed. Found %zu results", results.size());
		return results;
	}

	std::vector<ScanResult> CheatEngine::RescanMemory(const ScanCriteria& criteria)
	{
		if (m_lastScanResults.empty())
		{
			Console.Warning("(CheatEngine) No previous scan results for rescan");
			return ScanMemory(criteria);
		}

		Console.WriteLn("(CheatEngine) Rescanning %zu previous results", m_lastScanResults.size());
		
		std::vector<ScanResult> newResults;
		auto memInterface = AnalysisFrameworkCore::GetInstance().GetMemoryInterface();
		if (!memInterface)
			return newResults;

		// Filter previous results based on new criteria
		for (const auto& prevResult : m_lastScanResults)
		{
			if (TestScanCriteria(prevResult.address, criteria, memInterface))
			{
				ScanResult newResult = prevResult;
				// Update current value
				memInterface->ReadMemory(prevResult.address, reinterpret_cast<u8*>(&newResult.currentValue), 
										 GetValueSize(criteria.valueType));
				newResults.push_back(newResult);
			}
		}

		m_lastScanResults = newResults;
		m_scanResults = newResults;

		Console.WriteLn("(CheatEngine) Rescan completed. %zu results remaining", newResults.size());
		return newResults;
	}

	bool CheatEngine::AddCheat(const CheatEntry& cheat)
	{
		// Validate address
		if (!IsValidAddress(cheat.address))
		{
			Console.Error("(CheatEngine) Invalid address for cheat: 0x%08X", cheat.address);
			return false;
		}

		m_cheats[cheat.address] = cheat;
		Console.WriteLn("(CheatEngine) Added cheat at 0x%08X: %s", cheat.address, cheat.description.c_str());
		return true;
	}

	bool CheatEngine::RemoveCheat(u32 address)
	{
		auto it = m_cheats.find(address);
		if (it != m_cheats.end())
		{
			Console.WriteLn("(CheatEngine) Removed cheat at 0x%08X", address);
			m_cheats.erase(it);
			return true;
		}
		return false;
	}

	bool CheatEngine::EnableCheat(u32 address, bool enabled)
	{
		auto it = m_cheats.find(address);
		if (it != m_cheats.end())
		{
			it->second.enabled = enabled;
			Console.WriteLn("(CheatEngine) Cheat at 0x%08X %s", address, enabled ? "enabled" : "disabled");
			return true;
		}
		return false;
	}

	std::vector<CheatEntry> CheatEngine::GetActiveAimCheats() const
	{
		std::vector<CheatEntry> active;
		for (const auto& pair : m_cheats)
		{
			if (pair.second.enabled)
			{
				active.push_back(pair.second);
			}
		}
		return active;
	}

	void CheatEngine::ApplyCheats()
	{
		if (!m_initialized)
			return;

		auto memInterface = AnalysisFrameworkCore::GetInstance().GetMemoryInterface();
		if (!memInterface)
			return;

		for (auto& pair : m_cheats)
		{
			CheatEntry& cheat = pair.second;
			if (cheat.enabled)
			{
				// Apply cheat value
				size_t valueSize = GetValueSize(cheat.type);
				if (cheat.locked)
				{
					// Continuously apply the value
					memInterface->WriteMemory(cheat.address, reinterpret_cast<const u8*>(&cheat.value), valueSize);
				}
				else
				{
					// Apply once and disable
					memInterface->WriteMemory(cheat.address, reinterpret_cast<const u8*>(&cheat.value), valueSize);
					cheat.enabled = false;
				}
			}
		}
	}

	void CheatEngine::StartContinuousScanning(const ScanCriteria& criteria, u32 intervalMs)
	{
		if (m_continuousScanning)
			return;

		m_continuousScanning = true;
		m_continuousCriteria = criteria;
		m_scanInterval = intervalMs;

		m_scanThread = std::make_unique<std::thread>(&CheatEngine::ContinuousScanThreadFunc, this);
		Console.WriteLn("(CheatEngine) Started continuous scanning");
	}

	void CheatEngine::StopContinuousScanning()
	{
		if (!m_continuousScanning)
			return;

		m_continuousScanning = false;
		
		if (m_scanThread && m_scanThread->joinable())
		{
			m_scanThread->join();
			m_scanThread.reset();
		}

		Console.WriteLn("(CheatEngine) Stopped continuous scanning");
	}

	std::vector<MemoryPattern> CheatEngine::DetectGameSpecificPatterns()
	{
		std::vector<MemoryPattern> patterns;

		// Detect common game patterns
		patterns.push_back(DetectPlayerHealthPattern());
		patterns.push_back(DetectPlayerPositionPattern());
		patterns.push_back(DetectScorePattern());
		patterns.push_back(DetectAmmoPattern());

		// Remove invalid patterns
		patterns.erase(std::remove_if(patterns.begin(), patterns.end(),
			[](const MemoryPattern& pattern) { return pattern.baseAddress == 0; }), patterns.end());

		Console.WriteLn("(CheatEngine) Detected %zu game-specific patterns", patterns.size());
		return patterns;
	}

	std::vector<FunctionPattern> CheatEngine::AnalyzeFunctionPatterns()
	{
		std::vector<FunctionPattern> patterns;

		// Analyze memory access patterns to identify function types
		for (const auto& pair : m_cheats)
		{
			const CheatEntry& cheat = pair.second;
			FunctionPattern pattern = AnalyzeFunctionAroundAddress(cheat.address);
			if (pattern.confidence > 0.5f)
			{
				patterns.push_back(pattern);
			}
		}

		Console.WriteLn("(CheatEngine) Analyzed %zu function patterns", patterns.size());
		return patterns;
	}

	// Private implementation methods
	std::vector<ScanResult> CheatEngine::ScanExactValue(const ScanCriteria& criteria, std::shared_ptr<IMemoryInterface> memInterface)
	{
		std::vector<ScanResult> results;
		size_t valueSize = GetValueSize(criteria.valueType);
		
		if (criteria.searchValue.size() != valueSize)
		{
			Console.Error("(CheatEngine) Search value size mismatch");
			return results;
		}

		for (u32 address = criteria.startAddress; address < criteria.endAddress; address += criteria.alignment)
		{
			std::vector<u8> data(valueSize);
			if (memInterface->ReadMemory(address, data.data(), valueSize))
			{
				if (std::equal(data.begin(), data.end(), criteria.searchValue.begin()))
				{
					ScanResult result;
					result.address = address;
					result.previousValue = 0; // Will be filled on rescan
					std::memcpy(&result.currentValue, data.data(), std::min(valueSize, sizeof(result.currentValue)));
					result.valueType = criteria.valueType;
					results.push_back(result);
				}
			}
		}

		return results;
	}

	std::vector<ScanResult> CheatEngine::ScanRange(const ScanCriteria& criteria, std::shared_ptr<IMemoryInterface> memInterface)
	{
		std::vector<ScanResult> results;
		size_t valueSize = GetValueSize(criteria.valueType);

		if (criteria.searchValue.size() != valueSize || criteria.searchValue2.size() != valueSize)
		{
			Console.Error("(CheatEngine) Range search value size mismatch");
			return results;
		}

		u64 minValue = 0, maxValue = 0;
		std::memcpy(&minValue, criteria.searchValue.data(), valueSize);
		std::memcpy(&maxValue, criteria.searchValue2.data(), valueSize);

		for (u32 address = criteria.startAddress; address < criteria.endAddress; address += criteria.alignment)
		{
			std::vector<u8> data(valueSize);
			if (memInterface->ReadMemory(address, data.data(), valueSize))
			{
				u64 value = 0;
				std::memcpy(&value, data.data(), valueSize);
				
				if (value >= minValue && value <= maxValue)
				{
					ScanResult result;
					result.address = address;
					result.previousValue = 0;
					result.currentValue = value;
					result.valueType = criteria.valueType;
					results.push_back(result);
				}
			}
		}

		return results;
	}

	std::vector<ScanResult> CheatEngine::ScanPattern(const ScanCriteria& criteria, std::shared_ptr<IMemoryInterface> memInterface)
	{
		std::vector<ScanResult> results;
		
		if (criteria.pattern.empty())
			return results;

		// Read larger chunks for pattern scanning
		const size_t chunkSize = 4096;
		for (u32 address = criteria.startAddress; address < criteria.endAddress; address += chunkSize)
		{
			std::vector<u8> data(chunkSize);
			size_t readSize = std::min(chunkSize, static_cast<size_t>(criteria.endAddress - address));
			
			if (memInterface->ReadMemory(address, data.data(), readSize))
			{
				// Search for pattern in chunk
				for (size_t i = 0; i <= readSize - criteria.pattern.size(); ++i)
				{
					bool patternMatch = true;
					for (size_t j = 0; j < criteria.pattern.size(); ++j)
					{
						if (j < criteria.mask.size() && !criteria.mask[j])
							continue; // Skip masked bytes
							
						if (data[i + j] != criteria.pattern[j])
						{
							patternMatch = false;
							break;
						}
					}
					
					if (patternMatch)
					{
						ScanResult result;
						result.address = address + i;
						result.previousValue = 0;
						std::memcpy(&result.currentValue, &data[i], std::min(sizeof(u64), criteria.pattern.size()));
						result.valueType = "pattern";
						results.push_back(result);
					}
				}
			}
		}

		return results;
	}

	std::vector<ScanResult> CheatEngine::ScanChangedValues(const ScanCriteria& criteria, std::shared_ptr<IMemoryInterface> memInterface)
	{
		std::vector<ScanResult> results;
		
		for (const auto& prevResult : m_lastScanResults)
		{
			u64 currentValue = 0;
			size_t valueSize = GetValueSize(criteria.valueType);
			
			if (memInterface->ReadMemory(prevResult.address, reinterpret_cast<u8*>(&currentValue), valueSize))
			{
				if (currentValue != prevResult.currentValue)
				{
					ScanResult result = prevResult;
					result.previousValue = prevResult.currentValue;
					result.currentValue = currentValue;
					results.push_back(result);
				}
			}
		}

		return results;
	}

	std::vector<ScanResult> CheatEngine::ScanUnchangedValues(const ScanCriteria& criteria, std::shared_ptr<IMemoryInterface> memInterface)
	{
		std::vector<ScanResult> results;
		
		for (const auto& prevResult : m_lastScanResults)
		{
			u64 currentValue = 0;
			size_t valueSize = GetValueSize(criteria.valueType);
			
			if (memInterface->ReadMemory(prevResult.address, reinterpret_cast<u8*>(&currentValue), valueSize))
			{
				if (currentValue == prevResult.currentValue)
				{
					ScanResult result = prevResult;
					result.currentValue = currentValue;
					results.push_back(result);
				}
			}
		}

		return results;
	}

	std::vector<ScanResult> CheatEngine::ScanIncreasedValues(const ScanCriteria& criteria, std::shared_ptr<IMemoryInterface> memInterface)
	{
		std::vector<ScanResult> results;
		
		for (const auto& prevResult : m_lastScanResults)
		{
			u64 currentValue = 0;
			size_t valueSize = GetValueSize(criteria.valueType);
			
			if (memInterface->ReadMemory(prevResult.address, reinterpret_cast<u8*>(&currentValue), valueSize))
			{
				if (currentValue > prevResult.currentValue)
				{
					ScanResult result = prevResult;
					result.previousValue = prevResult.currentValue;
					result.currentValue = currentValue;
					results.push_back(result);
				}
			}
		}

		return results;
	}

	std::vector<ScanResult> CheatEngine::ScanDecreasedValues(const ScanCriteria& criteria, std::shared_ptr<IMemoryInterface> memInterface)
	{
		std::vector<ScanResult> results;
		
		for (const auto& prevResult : m_lastScanResults)
		{
			u64 currentValue = 0;
			size_t valueSize = GetValueSize(criteria.valueType);
			
			if (memInterface->ReadMemory(prevResult.address, reinterpret_cast<u8*>(&currentValue), valueSize))
			{
				if (currentValue < prevResult.currentValue)
				{
					ScanResult result = prevResult;
					result.previousValue = prevResult.currentValue;
					result.currentValue = currentValue;
					results.push_back(result);
				}
			}
		}

		return results;
	}

	bool CheatEngine::TestScanCriteria(u32 address, const ScanCriteria& criteria, std::shared_ptr<IMemoryInterface> memInterface)
	{
		size_t valueSize = GetValueSize(criteria.valueType);
		u64 currentValue = 0;
		
		if (!memInterface->ReadMemory(address, reinterpret_cast<u8*>(&currentValue), valueSize))
			return false;

		switch (criteria.scanType)
		{
		case ScanCriteria::ScanType::ExactValue:
			{
				u64 searchValue = 0;
				std::memcpy(&searchValue, criteria.searchValue.data(), valueSize);
				return currentValue == searchValue;
			}
		case ScanCriteria::ScanType::Range:
			{
				u64 minValue = 0, maxValue = 0;
				std::memcpy(&minValue, criteria.searchValue.data(), valueSize);
				std::memcpy(&maxValue, criteria.searchValue2.data(), valueSize);
				return currentValue >= minValue && currentValue <= maxValue;
			}
		default:
			return true; // For comparative scans, we'll handle this in the main scan functions
		}
	}

	size_t CheatEngine::GetValueSize(const std::string& valueType)
	{
		if (valueType == "8bit") return 1;
		if (valueType == "16bit") return 2;
		if (valueType == "32bit") return 4;
		if (valueType == "64bit") return 8;
		if (valueType == "float") return 4;
		if (valueType == "double") return 8;
		return 4; // Default to 32-bit
	}

	bool CheatEngine::IsValidAddress(u32 address)
	{
		// Check if address is in valid PS2 memory regions
		return (address >= 0x00000000 && address < 0x02000000) || // Main memory
			   (address >= 0x70000000 && address < 0x70004000);   // Scratchpad
	}

	void CheatEngine::ContinuousScanThreadFunc()
	{
		Console.WriteLn("(CheatEngine) Continuous scanning thread started");
		
		while (m_continuousScanning)
		{
			auto results = ScanMemory(m_continuousCriteria);
			
			// Analyze results for patterns
			if (!results.empty())
			{
				AnalyzeScanResultsForPatterns(results);
			}
			
			std::this_thread::sleep_for(std::chrono::milliseconds(m_scanInterval));
		}
		
		Console.WriteLn("(CheatEngine) Continuous scanning thread stopped");
	}

	void CheatEngine::DetectWritePatterns(u32 address)
	{
		// Track write patterns for enhanced analysis
		auto now = std::chrono::steady_clock::now();
		
		// Store write event
		WriteEvent event;
		event.address = address;
		event.timestamp = now;
		
		m_writeEvents.push_back(event);
		
		// Keep only recent events (last 1000)
		if (m_writeEvents.size() > 1000)
		{
			m_writeEvents.erase(m_writeEvents.begin());
		}
		
		// Analyze for patterns
		AnalyzeWriteEventPatterns();
	}

	void CheatEngine::AnalyzeScanResultsForPatterns(const std::vector<ScanResult>& results)
	{
		// Look for clusters of addresses that might represent arrays or structures
		for (size_t i = 0; i < results.size() - 1; ++i)
		{
			u32 currentAddr = results[i].address;
			u32 nextAddr = results[i + 1].address;
			
			if (nextAddr - currentAddr <= 16) // Close addresses might be structure members
			{
				// Potential structure detected
				MemoryPattern pattern;
				pattern.patternType = "structure";
				pattern.baseAddress = currentAddr;
				pattern.confidence = 0.7f;
				pattern.description = "Potential game structure";
				
				// Would store this for further analysis
			}
		}
	}

	void CheatEngine::AnalyzeWriteEventPatterns()
	{
		// Analyze write events for patterns that might indicate specific game functions
		if (m_writeEvents.size() < 10)
			return;
		
		// Look for repeated writes to same address (potential counters)
		std::unordered_map<u32, int> writeFrequency;
		for (const auto& event : m_writeEvents)
		{
			writeFrequency[event.address]++;
		}
		
		// Identify frequently written addresses
		for (const auto& pair : writeFrequency)
		{
			if (pair.second > 5) // Written more than 5 times recently
			{
				// This could be a game counter or timer
				MemoryPattern pattern;
				pattern.patternType = "counter";
				pattern.baseAddress = pair.first;
				pattern.confidence = 0.6f;
				pattern.description = "Frequently updated value (counter/timer)";
			}
		}
	}

	MemoryPattern CheatEngine::DetectPlayerHealthPattern()
	{
		MemoryPattern pattern;
		pattern.patternType = "player_health";
		pattern.confidence = 0.0f;
		
		// Look for typical health values (1-100, 1-1000, etc.)
		ScanCriteria criteria;
		criteria.scanType = ScanCriteria::ScanType::Range;
		criteria.valueType = "32bit";
		
		// Health typically in range 1-100 or 1-1000
		u32 minHealth = 1;
		u32 maxHealth = 1000;
		criteria.searchValue.resize(4);
		criteria.searchValue2.resize(4);
		std::memcpy(criteria.searchValue.data(), &minHealth, 4);
		std::memcpy(criteria.searchValue2.data(), &maxHealth, 4);
		
		auto results = ScanMemory(criteria);
		
		if (!results.empty())
		{
			// Simple heuristic: health is often in main memory, not too high address
			for (const auto& result : results)
			{
				if (result.address >= 0x00100000 && result.address < 0x01000000)
				{
					pattern.baseAddress = result.address;
					pattern.confidence = 0.6f;
					pattern.description = "Potential player health";
					break;
				}
			}
		}
		
		return pattern;
	}

	MemoryPattern CheatEngine::DetectPlayerPositionPattern()
	{
		MemoryPattern pattern;
		pattern.patternType = "player_position";
		pattern.confidence = 0.0f;
		
		// Position values are often float coordinates
		// Look for typical position ranges
		ScanCriteria criteria;
		criteria.scanType = ScanCriteria::ScanType::Range;
		criteria.valueType = "float";
		
		// Position typically in range -10000.0 to 10000.0
		float minPos = -10000.0f;
		float maxPos = 10000.0f;
		criteria.searchValue.resize(4);
		criteria.searchValue2.resize(4);
		std::memcpy(criteria.searchValue.data(), &minPos, 4);
		std::memcpy(criteria.searchValue2.data(), &maxPos, 4);
		
		auto results = ScanMemory(criteria);
		
		if (results.size() >= 3) // Position usually has X, Y, Z coordinates
		{
			// Look for clusters of 3 float values (X, Y, Z)
			for (size_t i = 0; i < results.size() - 2; ++i)
			{
				if (results[i + 1].address == results[i].address + 4 &&
					results[i + 2].address == results[i].address + 8)
				{
					pattern.baseAddress = results[i].address;
					pattern.confidence = 0.7f;
					pattern.description = "Potential player position (X, Y, Z)";
					break;
				}
			}
		}
		
		return pattern;
	}

	MemoryPattern CheatEngine::DetectScorePattern()
	{
		MemoryPattern pattern;
		pattern.patternType = "score";
		pattern.confidence = 0.0f;
		
		// Scores are often incrementing integers
		// This would require monitoring value changes over time
		// For now, just look for values that might be scores
		
		return pattern;
	}

	MemoryPattern CheatEngine::DetectAmmoPattern()
	{
		MemoryPattern pattern;
		pattern.patternType = "ammo";
		pattern.confidence = 0.0f;
		
		// Ammo values are typically small integers (0-999)
		ScanCriteria criteria;
		criteria.scanType = ScanCriteria::ScanType::Range;
		criteria.valueType = "32bit";
		
		u32 minAmmo = 0;
		u32 maxAmmo = 999;
		criteria.searchValue.resize(4);
		criteria.searchValue2.resize(4);
		std::memcpy(criteria.searchValue.data(), &minAmmo, 4);
		std::memcpy(criteria.searchValue2.data(), &maxAmmo, 4);
		
		auto results = ScanMemory(criteria);
		
		if (!results.empty())
		{
			// Ammo is often in main memory area
			for (const auto& result : results)
			{
				if (result.address >= 0x00100000 && result.address < 0x01000000)
				{
					pattern.baseAddress = result.address;
					pattern.confidence = 0.5f;
					pattern.description = "Potential ammo counter";
					break;
				}
			}
		}
		
		return pattern;
	}

	FunctionPattern CheatEngine::AnalyzeFunctionAroundAddress(u32 address)
	{
		FunctionPattern pattern;
		pattern.address = address;
		pattern.confidence = 0.0f;
		
		// This would analyze disassembly around the address to identify function patterns
		// For now, provide a basic analysis based on address range
		
		if (address >= 0x00100000 && address < 0x00200000)
		{
			pattern.functionType = "game_logic";
			pattern.confidence = 0.6f;
			pattern.description = "Game logic function";
		}
		else if (address >= 0x10000000 && address < 0x20000000)
		{
			pattern.functionType = "hardware_access";
			pattern.confidence = 0.8f;
			pattern.description = "Hardware register access";
		}
		else
		{
			pattern.functionType = "unknown";
			pattern.confidence = 0.3f;
			pattern.description = "Unknown function type";
		}
		
		return pattern;
	}

} // namespace AnalysisFramework