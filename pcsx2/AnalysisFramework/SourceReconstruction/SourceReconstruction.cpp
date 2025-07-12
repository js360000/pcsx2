// SPDX-FileCopyrightText: 2002-2025 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "SourceReconstruction.h"
#include "AnalysisFramework/Core/MemoryInterface.h"
#include "AnalysisFramework/Core/DebugInterface.h"
#include "AnalysisFramework/Common/Utilities.h"
#include "Common.h"
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <regex>

namespace AnalysisFramework
{
	SourceReconstruction::SourceReconstruction()
	{
		m_lastAnalysisUpdate = std::chrono::steady_clock::now();
	}

	SourceReconstruction::~SourceReconstruction()
	{
		Shutdown();
	}

	bool SourceReconstruction::Initialize()
	{
		if (m_initialized)
			return true;

		Console.WriteLn("(SourceReconstruction) Initializing Source Code Reconstruction module...");

		// Initialize data structures
		m_functions.clear();
		m_microprogramPatterns.clear();
		m_gameplayCorrelations.clear();

		m_initialized = true;
		Console.WriteLn("(SourceReconstruction) Source Code Reconstruction module initialized successfully");
		return true;
	}

	void SourceReconstruction::Shutdown()
	{
		if (!m_initialized)
			return;

		Console.WriteLn("(SourceReconstruction) Shutting down Source Code Reconstruction module...");

		StopRealtimeAnalysis();
		
		m_functions.clear();
		m_microprogramPatterns.clear();
		m_gameplayCorrelations.clear();
		
		m_initialized = false;
		Console.WriteLn("(SourceReconstruction) Source Code Reconstruction module shut down");
	}

	void SourceReconstruction::OnFrameworkEvent(AnalysisEvent event, const void* data, size_t size)
	{
		if (!m_initialized || !m_analysisRunning)
			return;

		switch (event)
		{
		case AnalysisEvent::MemoryWrite:
			if (data && size >= sizeof(u32))
			{
				u32 address = *static_cast<const u32*>(data);
				AnalyzeMemoryAccessPattern(address, size, "write");
			}
			break;
		case AnalysisEvent::MemoryRead:
			if (data && size >= sizeof(u32))
			{
				u32 address = *static_cast<const u32*>(data);
				AnalyzeMemoryAccessPattern(address, size, "read");
			}
			break;
		case AnalysisEvent::BreakpointHit:
			if (data && size >= sizeof(u32))
			{
				u32 address = *static_cast<const u32*>(data);
				AnalyzeFunctionBehavior(address, m_currentGameplayContext);
			}
			break;
		case AnalysisEvent::GameStateChange:
			// Update gameplay correlation when game state changes
			UpdateGameplayCorrelation();
			break;
		}
	}

	void SourceReconstruction::StartRealtimeAnalysis()
	{
		if (m_analysisRunning)
			return;

		Console.WriteLn("(SourceReconstruction) Starting real-time analysis...");
		m_analysisRunning = true;
		m_analysisThread = std::make_unique<std::thread>(&SourceReconstruction::AnalysisThreadFunc, this);
	}

	void SourceReconstruction::StopRealtimeAnalysis()
	{
		if (!m_analysisRunning)
			return;

		Console.WriteLn("(SourceReconstruction) Stopping real-time analysis...");
		m_analysisRunning = false;
		
		if (m_analysisThread && m_analysisThread->joinable())
		{
			m_analysisThread->join();
			m_analysisThread.reset();
		}
	}

	std::vector<DiscoveredFunction> SourceReconstruction::GetDiscoveredFunctions() const
	{
		std::vector<DiscoveredFunction> functions;
		functions.reserve(m_functions.size());
		
		for (const auto& pair : m_functions)
		{
			if (pair.second.confidence >= m_config.confidenceThreshold)
			{
				functions.push_back(pair.second);
			}
		}
		
		// Sort by confidence (highest first)
		std::sort(functions.begin(), functions.end(),
			[](const DiscoveredFunction& a, const DiscoveredFunction& b) {
				return a.confidence > b.confidence;
			});
		
		return functions;
	}

	DiscoveredFunction* SourceReconstruction::GetFunction(u32 address)
	{
		auto it = m_functions.find(address);
		return (it != m_functions.end()) ? &it->second : nullptr;
	}

	void SourceReconstruction::AnalyzeFunctionBehavior(u32 address, const std::string& context)
	{
		if (!IsValidCodeAddress(address))
			return;

		auto it = m_functions.find(address);
		if (it == m_functions.end())
		{
			// Create new function entry
			DiscoveredFunction newFunction;
			newFunction.address = address;
			newFunction.firstSeen = std::chrono::steady_clock::now();
			newFunction.lastSeen = newFunction.firstSeen;
			
			// Try to detect function boundaries
			DetectFunctionPattern(address, newFunction.size);
			
			m_functions[address] = newFunction;
			it = m_functions.find(address);
		}

		// Update function statistics
		DiscoveredFunction& function = it->second;
		function.lastSeen = std::chrono::steady_clock::now();
		function.executionCount++;
		
		// Correlate with current gameplay context
		if (!context.empty() && context != "unknown")
		{
			function.isGameplayRelated = true;
		}

		UpdateFunctionStatistics(function);
	}

	std::vector<MicroprogramPattern> SourceReconstruction::GetMicroprogramPatterns() const
	{
		return m_microprogramPatterns;
	}

	void SourceReconstruction::DetectAssetDecompression(u32 address, size_t size)
	{
		// Read memory to analyze for decompression patterns
		auto memInterface = AnalysisFrameworkCore::GetInstance().GetMemoryInterface();
		if (!memInterface)
			return;

		std::vector<u8> data(size);
		if (memInterface->ReadMemory(address, data.data(), size))
		{
			if (IsAssetDecompressionPattern(data))
			{
				MicroprogramPattern pattern;
				pattern.startAddress = address;
				pattern.endAddress = address + size;
				pattern.operationType = "decompress";
				pattern.detectedAt = std::chrono::steady_clock::now();
				
				// Try to identify asset type based on decompressed data patterns
				if (std::find(data.begin(), data.end(), 0x89) != data.end() && 
					std::find(data.begin(), data.end(), 0x50) != data.end())
				{
					pattern.assetType = "texture"; // PNG signature
				}
				else if (std::find(data.begin(), data.end(), 0xFF) != data.end() && 
						 std::find(data.begin(), data.end(), 0xD8) != data.end())
				{
					pattern.assetType = "texture"; // JPEG signature
				}
				else
				{
					pattern.assetType = "unknown";
				}
				
				m_microprogramPatterns.push_back(pattern);
			}
		}
	}

	void SourceReconstruction::DetectELFLoading(u32 address, const std::vector<u8>& data)
	{
		if (IsELFLoadingPattern(data))
		{
			MicroprogramPattern pattern;
			pattern.startAddress = address;
			pattern.endAddress = address + data.size();
			pattern.operationType = "load";
			pattern.assetType = "elf";
			pattern.detectedAt = std::chrono::steady_clock::now();
			
			m_microprogramPatterns.push_back(pattern);
			
			Console.WriteLn("(SourceReconstruction) ELF loading detected at 0x%08X", address);
		}
	}

	void SourceReconstruction::SetGameplayContext(const std::string& context)
	{
		if (m_currentGameplayContext != context)
		{
			Console.WriteLn("(SourceReconstruction) Gameplay context changed: %s -> %s", 
							m_currentGameplayContext.c_str(), context.c_str());
			m_currentGameplayContext = context;
			UpdateGameplayCorrelation();
		}
	}

	void SourceReconstruction::AddVideoFrameAnalysis(const std::string& frameDescription)
	{
		// Correlate video frame analysis with current memory state
		GameplayMemoryCorrelation correlation;
		correlation.timestamp = std::chrono::steady_clock::now();
		correlation.gameplayContext = m_currentGameplayContext;
		correlation.suggestedDescription = frameDescription;
		
		// Capture currently active memory regions and functions
		for (const auto& pair : m_functions)
		{
			const auto& function = pair.second;
			auto timeDiff = std::chrono::duration_cast<std::chrono::milliseconds>(
				correlation.timestamp - function.lastSeen).count();
			
			if (timeDiff < 1000) // Function was active within last second
			{
				correlation.activeFunctions.push_back(function.address);
			}
		}
		
		m_gameplayCorrelations.push_back(correlation);
		
		// Keep only recent correlations (last 1000 entries)
		if (m_gameplayCorrelations.size() > 1000)
		{
			m_gameplayCorrelations.erase(m_gameplayCorrelations.begin());
		}
	}

	std::vector<GameplayMemoryCorrelation> SourceReconstruction::GetGameplayCorrelations() const
	{
		return m_gameplayCorrelations;
	}

	std::string SourceReconstruction::GenerateFunctionName(const DiscoveredFunction& function)
	{
		std::stringstream name;
		
		// Generate name based on function characteristics
		std::string type = ClassifyFunctionType(function);
		
		if (type == "graphics")
		{
			name << "render_func_" << std::hex << function.address;
		}
		else if (type == "audio")
		{
			name << "audio_func_" << std::hex << function.address;
		}
		else if (type == "input")
		{
			name << "input_func_" << std::hex << function.address;
		}
		else if (type == "memory")
		{
			name << "mem_func_" << std::hex << function.address;
		}
		else if (function.isGameplayRelated)
		{
			name << "gameplay_func_" << std::hex << function.address;
		}
		else
		{
			name << "func_" << std::hex << function.address;
		}
		
		return name.str();
	}

	std::string SourceReconstruction::AnalyzeFunctionPurpose(const DiscoveredFunction& function)
	{
		std::string purpose = "Unknown function";
		
		// Analyze based on memory access patterns
		for (const auto& access : function.memoryAccesses)
		{
			u32 addr = access.first;
			const std::string& pattern = access.second;
			
			if (addr >= 0x10000000 && addr < 0x20000000)
			{
				purpose = "Hardware register access - likely system function";
				break;
			}
			else if (pattern.find("texture") != std::string::npos)
			{
				purpose = "Graphics/texture processing function";
				break;
			}
			else if (pattern.find("audio") != std::string::npos)
			{
				purpose = "Audio processing function";
				break;
			}
		}
		
		// Analyze based on execution frequency
		if (function.executionCount > 1000)
		{
			purpose += " (high frequency - possibly main loop or critical function)";
		}
		else if (function.executionCount == 1)
		{
			purpose += " (single execution - possibly initialization function)";
		}
		
		return purpose;
	}

	std::string SourceReconstruction::GenerateSourceReconstructionReport()
	{
		std::stringstream report;
		
		report << "# PCSX2 Source Code Reconstruction Report\n";
		report << "Generated: " << GenerateTimestamp() << "\n\n";
		
		report << "## Analysis Summary\n";
		report << "- Discovered Functions: " << m_functions.size() << "\n";
		report << "- High Confidence Functions: " << GetDiscoveredFunctions().size() << "\n";
		report << "- Microprogram Patterns: " << m_microprogramPatterns.size() << "\n";
		report << "- Gameplay Correlations: " << m_gameplayCorrelations.size() << "\n\n";
		
		report << "## High Confidence Functions\n";
		auto functions = GetDiscoveredFunctions();
		for (const auto& function : functions)
		{
			report << "### " << GenerateFunctionName(function) << "\n";
			report << "- Address: 0x" << std::hex << function.address << "\n";
			report << "- Size: " << std::dec << function.size << " bytes\n";
			report << "- Confidence: " << std::fixed << std::setprecision(2) << function.confidence << "\n";
			report << "- Purpose: " << AnalyzeFunctionPurpose(function) << "\n";
			report << "- Execution Count: " << function.executionCount << "\n";
			if (function.isGameplayRelated)
			{
				report << "- Gameplay Related: Yes\n";
			}
			report << "\n";
		}
		
		report << "## Microprogram Patterns\n";
		for (const auto& pattern : m_microprogramPatterns)
		{
			report << "- " << pattern.operationType << " operation at 0x" << std::hex << pattern.startAddress;
			report << " (" << pattern.assetType << ")\n";
		}
		
		return report.str();
	}

	bool SourceReconstruction::ExportToIDAScript(const std::string& filename)
	{
		std::ofstream file(filename);
		if (!file.is_open())
			return false;

		file << "# PCSX2 Source Reconstruction - IDA Pro Import Script\n";
		file << "# Generated: " << GenerateTimestamp() << "\n\n";
		file << "import ida_name\n";
		file << "import ida_funcs\n";
		file << "import ida_auto\n\n";
		file << "def apply_pcsx2_source_reconstruction():\n";
		file << "    print(\"Applying PCSX2 source reconstruction...\")\n\n";

		auto functions = GetDiscoveredFunctions();
		for (const auto& function : functions)
		{
			std::string name = GenerateFunctionName(function);
			file << "    # " << AnalyzeFunctionPurpose(function) << "\n";
			file << "    ida_funcs.add_func(0x" << std::hex << function.address << ")\n";
			file << "    ida_name.set_name(0x" << std::hex << function.address << ", \"" << name << "\")\n\n";
		}

		file << "    ida_auto.auto_wait()\n";
		file << "    print(\"PCSX2 source reconstruction applied successfully!\")\n\n";
		file << "apply_pcsx2_source_reconstruction()\n";

		return true;
	}

	bool SourceReconstruction::ExportToGhidraScript(const std::string& filename)
	{
		std::ofstream file(filename);
		if (!file.is_open())
			return false;

		file << "# PCSX2 Source Reconstruction - Ghidra Import Script\n";
		file << "# Generated: " << GenerateTimestamp() << "\n\n";
		file << "from ghidra.app.script import GhidraScript\n";
		file << "from ghidra.program.model.symbol import SourceType\n\n";
		file << "class PCSX2SourceReconstructionScript(GhidraScript):\n";
		file << "    def run(self):\n";
		file << "        print(\"Applying PCSX2 source reconstruction...\")\n\n";

		auto functions = GetDiscoveredFunctions();
		for (const auto& function : functions)
		{
			std::string name = GenerateFunctionName(function);
			file << "        # " << AnalyzeFunctionPurpose(function) << "\n";
			file << "        addr = toAddr(0x" << std::hex << function.address << ")\n";
			file << "        self.createFunction(addr, \"" << name << "\")\n";
			file << "        self.setPlateComment(addr, \"" << AnalyzeFunctionPurpose(function) << "\")\n\n";
		}

		file << "        print(\"PCSX2 source reconstruction applied successfully!\")\n";

		return true;
	}

	bool SourceReconstruction::ExportSymbolsJSON(const std::string& filename)
	{
		std::ofstream file(filename);
		if (!file.is_open())
			return false;

		file << "{\n";
		file << "  \"pcsx2_source_reconstruction\": {\n";
		file << "    \"generated\": \"" << GenerateTimestamp() << "\",\n";
		file << "    \"functions\": [\n";

		auto functions = GetDiscoveredFunctions();
		for (size_t i = 0; i < functions.size(); ++i)
		{
			const auto& function = functions[i];
			file << "      {\n";
			file << "        \"address\": \"0x" << std::hex << function.address << "\",\n";
			file << "        \"name\": \"" << GenerateFunctionName(function) << "\",\n";
			file << "        \"size\": " << std::dec << function.size << ",\n";
			file << "        \"confidence\": " << function.confidence << ",\n";
			file << "        \"purpose\": \"" << AnalyzeFunctionPurpose(function) << "\",\n";
			file << "        \"execution_count\": " << function.executionCount << ",\n";
			file << "        \"gameplay_related\": " << (function.isGameplayRelated ? "true" : "false") << "\n";
			file << "      }";
			if (i < functions.size() - 1) file << ",";
			file << "\n";
		}

		file << "    ]\n";
		file << "  }\n";
		file << "}\n";

		return true;
	}

	// Private implementation methods
	void SourceReconstruction::AnalysisThreadFunc()
	{
		Console.WriteLn("(SourceReconstruction) Analysis thread started");
		
		while (m_analysisRunning)
		{
			auto now = std::chrono::steady_clock::now();
			auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
				now - m_lastAnalysisUpdate).count();
			
			if (elapsed >= m_config.analysisIntervalMs)
			{
				if (m_config.enableFunctionDiscovery)
					UpdateFunctionAnalysis();
				
				if (m_config.enableMicroprogramAnalysis)
					UpdateMicroprogramAnalysis();
				
				if (m_config.enableGameplayCorrelation)
					UpdateGameplayCorrelation();
				
				m_lastAnalysisUpdate = now;
			}
			
			std::this_thread::sleep_for(std::chrono::milliseconds(50));
		}
		
		Console.WriteLn("(SourceReconstruction) Analysis thread stopped");
	}

	void SourceReconstruction::UpdateFunctionAnalysis()
	{
		// Update confidence scores and analyze function relationships
		for (auto& pair : m_functions)
		{
			UpdateFunctionStatistics(pair.second);
		}
		
		BuildFunctionCallGraph();
		AnalyzeFunctionRelationships();
	}

	void SourceReconstruction::UpdateMicroprogramAnalysis()
	{
		// Remove old microprogram patterns (older than 5 minutes)
		auto now = std::chrono::steady_clock::now();
		m_microprogramPatterns.erase(
			std::remove_if(m_microprogramPatterns.begin(), m_microprogramPatterns.end(),
				[now](const MicroprogramPattern& pattern) {
					auto age = std::chrono::duration_cast<std::chrono::minutes>(
						now - pattern.detectedAt).count();
					return age > 5;
				}),
			m_microprogramPatterns.end());
	}

	void SourceReconstruction::UpdateGameplayCorrelation()
	{
		// Create correlation entry for current state
		if (!m_gameplayCorrelations.empty() || m_currentGameplayContext != "unknown")
		{
			GameplayMemoryCorrelation correlation;
			correlation.timestamp = std::chrono::steady_clock::now();
			correlation.gameplayContext = m_currentGameplayContext;
			
			// Add currently active functions
			for (const auto& pair : m_functions)
			{
				const auto& function = pair.second;
				auto timeDiff = std::chrono::duration_cast<std::chrono::milliseconds>(
					correlation.timestamp - function.lastSeen).count();
				
				if (timeDiff < 500) // Function was active within last 500ms
				{
					correlation.activeFunctions.push_back(function.address);
				}
			}
			
			// Only add if there's meaningful data
			if (!correlation.activeFunctions.empty())
			{
				m_gameplayCorrelations.push_back(correlation);
			}
		}
	}

	bool SourceReconstruction::DetectFunctionPattern(u32 address, u32& functionSize)
	{
		auto memInterface = AnalysisFrameworkCore::GetInstance().GetMemoryInterface();
		if (!memInterface)
			return false;

		// Read instruction data to detect function boundaries
		std::vector<u8> data(256); // Read up to 256 bytes
		if (!memInterface->ReadMemory(address, data.data(), data.size()))
			return false;

		// Simple heuristic: look for common MIPS function patterns
		functionSize = m_config.minFunctionSize;
		
		// Look for function prologue patterns (simplified)
		for (size_t i = 0; i < data.size() - 8; i += 4)
		{
			u32 instruction = *reinterpret_cast<u32*>(&data[i]);
			
			// Common function ending patterns (jr $ra, nop)
			if ((instruction & 0xFC1FFFFF) == 0x03E00008) // jr $ra
			{
				functionSize = i + 8; // Include delay slot
				break;
			}
		}

		return functionSize >= m_config.minFunctionSize;
	}

	std::string SourceReconstruction::ClassifyFunctionType(const DiscoveredFunction& function)
	{
		// Classify based on memory access patterns and address ranges
		for (const auto& access : function.memoryAccesses)
		{
			u32 addr = access.first;
			
			if (addr >= 0x12000000 && addr < 0x12010000)
				return "graphics"; // Graphics registers
			else if (addr >= 0x10003000 && addr < 0x10004000)
				return "audio"; // SPU2 registers  
			else if (addr >= 0x10008000 && addr < 0x10009000)
				return "input"; // Controller registers
		}
		
		// Default classification based on address range
		if (function.address >= 0x00100000 && function.address < 0x00200000)
			return "game_code";
		else if (function.address >= 0x00000000 && function.address < 0x00100000)
			return "system";
		
		return "unknown";
	}

	bool SourceReconstruction::IsAssetDecompressionPattern(const std::vector<u8>& data)
	{
		if (data.size() < 16)
			return false;

		// Look for common compression signatures
		// ZLIB header
		if (data[0] == 0x78 && (data[1] == 0x9C || data[1] == 0xDA || data[1] == 0x01))
			return true;
		
		// GZIP header
		if (data[0] == 0x1F && data[1] == 0x8B)
			return true;
		
		// LZO patterns (common in PS2 games)
		if (data[0] == 0x89 && data[1] == 0x4C && data[2] == 0x5A && data[3] == 0x4F)
			return true;

		return false;
	}

	bool SourceReconstruction::IsELFLoadingPattern(const std::vector<u8>& data)
	{
		if (data.size() < 16)
			return false;

		// ELF magic number
		return (data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F');
	}

	void SourceReconstruction::AnalyzeMemoryAccessPattern(u32 address, size_t size, const std::string& operation)
	{
		// Find functions that might be accessing this memory
		auto now = std::chrono::steady_clock::now();
		
		for (auto& pair : m_functions)
		{
			DiscoveredFunction& function = pair.second;
			auto timeDiff = std::chrono::duration_cast<std::chrono::milliseconds>(
				now - function.lastSeen).count();
			
			if (timeDiff < 100) // Function was active within last 100ms
			{
				std::string pattern = operation + "_" + IdentifyMemoryRegionPurpose(address);
				function.memoryAccesses.emplace_back(address, pattern);
				
				// Keep only recent memory accesses (last 100 entries per function)
				if (function.memoryAccesses.size() > 100)
				{
					function.memoryAccesses.erase(function.memoryAccesses.begin());
				}
			}
		}
	}

	std::string SourceReconstruction::IdentifyMemoryRegionPurpose(u32 address)
	{
		if (address >= 0x00000000 && address < 0x02000000)
			return "main_memory";
		else if (address >= 0x70000000 && address < 0x70004000)
			return "scratchpad";
		else if (address >= 0x10000000 && address < 0x20000000)
			return "hardware_registers";
		else if (address >= 0x1FC00000 && address < 0x20000000)
			return "bios";
		else
			return "unknown";
	}

	void SourceReconstruction::BuildFunctionCallGraph()
	{
		// This would require more complex disassembly analysis
		// For now, placeholder implementation
	}

	void SourceReconstruction::AnalyzeFunctionRelationships()
	{
		// Analyze which functions are called together frequently
		// This helps identify related functionality
	}

	void SourceReconstruction::CorrelateWithGameplayEvents()
	{
		// Correlate recent function execution with gameplay context changes
	}

	void SourceReconstruction::UpdateFunctionStatistics(DiscoveredFunction& function)
	{
		function.confidence = CalculateFunctionConfidence(function);
	}

	float SourceReconstruction::CalculateFunctionConfidence(const DiscoveredFunction& function)
	{
		float confidence = 0.0f;
		
		// Base confidence from execution count
		if (function.executionCount > 0)
			confidence += 0.3f;
		
		// Higher confidence for functions with clear boundaries
		if (function.size >= m_config.minFunctionSize)
			confidence += 0.2f;
		
		// Higher confidence for functions with memory access patterns
		if (!function.memoryAccesses.empty())
			confidence += 0.2f;
		
		// Higher confidence for gameplay-related functions
		if (function.isGameplayRelated)
			confidence += 0.2f;
		
		// Bonus for frequently executed functions
		if (function.executionCount > 100)
			confidence += 0.1f;
		
		return std::min(confidence, 1.0f);
	}

	void SourceReconstruction::AnalyzeExecutionFrequency()
	{
		// Analyze execution patterns over time
	}

	std::string SourceReconstruction::FormatAddress(u32 address) const
	{
		std::stringstream ss;
		ss << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << address;
		return ss.str();
	}

	std::string SourceReconstruction::GenerateTimestamp() const
	{
		auto now = std::chrono::system_clock::now();
		auto time_t = std::chrono::system_clock::to_time_t(now);
		
		std::stringstream ss;
		ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
		return ss.str();
	}

	bool SourceReconstruction::IsValidCodeAddress(u32 address) const
	{
		// Check if address is in valid code regions
		return (address >= 0x00100000 && address < 0x02000000) || // Main memory code
			   (address >= 0x70000000 && address < 0x70004000);   // Scratchpad
	}

} // namespace AnalysisFramework