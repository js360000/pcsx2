// SPDX-FileCopyrightText: 2002-2025 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include "AnalysisFramework/Core/AnalysisFramework.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <thread>
#include <atomic>
#include <memory>
#include <chrono>

namespace AnalysisFramework
{
	/// Structure representing a discovered function during gameplay
	struct DiscoveredFunction
	{
		u32 address;
		u32 size;
		std::string suggestedName;
		std::string purpose;  // Auto-detected purpose based on behavior
		std::vector<u32> calledFrom;  // Addresses that call this function
		std::vector<u32> callsTo;     // Addresses this function calls
		std::vector<std::pair<u32, std::string>> memoryAccesses;  // Memory regions and patterns
		std::chrono::steady_clock::time_point firstSeen;
		std::chrono::steady_clock::time_point lastSeen;
		u32 executionCount = 0;
		float confidence = 0.0f;  // Confidence in the analysis (0.0-1.0)
		bool isGameplayRelated = false;  // True if function was active during specific gameplay
	};

	/// Structure for tracking microprogram execution patterns
	struct MicroprogramPattern
	{
		u32 startAddress;
		u32 endAddress;
		std::string operationType;  // "decompress", "load", "init", "render", "audio", etc.
		std::vector<u32> assetAddresses;  // Memory addresses of related assets
		std::string assetType;  // "texture", "sound", "model", "script", etc.
		std::chrono::steady_clock::time_point detectedAt;
	};

	/// Structure for correlating video gameplay with memory operations
	struct GameplayMemoryCorrelation
	{
		std::chrono::steady_clock::time_point timestamp;
		std::string gameplayContext;  // "menu", "loading", "gameplay", "cutscene", etc.
		std::vector<u32> activeMemoryRegions;
		std::vector<u32> activeFunctions;
		std::string suggestedDescription;  // AI-generated description of what's happening
	};

	/// Real-time source code reconstruction module
	/// Analyzes gameplay patterns to identify and reconstruct source code structure
	class SourceReconstruction : public IAnalysisModule
	{
	public:
		SourceReconstruction();
		virtual ~SourceReconstruction();

		/// IAnalysisModule implementation
		const std::string& GetModuleId() const override { return m_moduleId; }
		const std::string& GetModuleName() const override { return m_moduleName; }
		const std::string& GetModuleVersion() const override { return m_moduleVersion; }

		bool Initialize() override;
		void Shutdown() override;
		bool IsInitialized() const override { return m_initialized; }

		void OnFrameworkEvent(AnalysisEvent event, const void* data, size_t size) override;

		/// Source reconstruction functionality
		void StartRealtimeAnalysis();
		void StopRealtimeAnalysis();
		bool IsAnalysisRunning() const { return m_analysisRunning; }

		/// Function discovery and analysis
		std::vector<DiscoveredFunction> GetDiscoveredFunctions() const;
		DiscoveredFunction* GetFunction(u32 address);
		void AnalyzeFunctionBehavior(u32 address, const std::string& context);

		/// Microprogram analysis
		std::vector<MicroprogramPattern> GetMicroprogramPatterns() const;
		void DetectAssetDecompression(u32 address, size_t size);
		void DetectELFLoading(u32 address, const std::vector<u8>& data);

		/// Gameplay correlation
		void SetGameplayContext(const std::string& context);
		void AddVideoFrameAnalysis(const std::string& frameDescription);
		std::vector<GameplayMemoryCorrelation> GetGameplayCorrelations() const;

		/// AI-assisted analysis
		std::string GenerateFunctionName(const DiscoveredFunction& function);
		std::string AnalyzeFunctionPurpose(const DiscoveredFunction& function);
		std::string GenerateSourceReconstructionReport();

		/// Export functionality for external tools
		bool ExportToIDAScript(const std::string& filename);
		bool ExportToGhidraScript(const std::string& filename);
		bool ExportSymbolsJSON(const std::string& filename);

	private:
		// Module identification
		std::string m_moduleId = "source_reconstruction";
		std::string m_moduleName = "Source Code Reconstruction Module";
		std::string m_moduleVersion = "1.0.0";

		bool m_initialized = false;
		std::atomic<bool> m_analysisRunning{false};
		std::unique_ptr<std::thread> m_analysisThread;

		// Analysis data structures
		std::unordered_map<u32, DiscoveredFunction> m_functions;
		std::vector<MicroprogramPattern> m_microprogramPatterns;
		std::vector<GameplayMemoryCorrelation> m_gameplayCorrelations;
		
		// Current analysis state
		std::string m_currentGameplayContext = "unknown";
		std::chrono::steady_clock::time_point m_lastAnalysisUpdate;

		// Configuration
		struct AnalysisConfig
		{
			bool enableFunctionDiscovery = true;
			bool enableMicroprogramAnalysis = true;
			bool enableGameplayCorrelation = true;
			bool enableAIAssistance = true;
			u32 minFunctionSize = 16;  // Minimum bytes for function detection
			float confidenceThreshold = 0.5f;  // Minimum confidence for function suggestions
			u32 analysisIntervalMs = 100;  // Analysis update interval
		} m_config;

		/// Analysis thread functions
		void AnalysisThreadFunc();
		void UpdateFunctionAnalysis();
		void UpdateMicroprogramAnalysis();
		void UpdateGameplayCorrelation();

		/// Pattern detection helpers
		bool DetectFunctionPattern(u32 address, u32& functionSize);
		std::string ClassifyFunctionType(const DiscoveredFunction& function);
		bool IsAssetDecompressionPattern(const std::vector<u8>& data);
		bool IsELFLoadingPattern(const std::vector<u8>& data);

		/// AI integration helpers
		std::string GenerateAIPrompt(const DiscoveredFunction& function);
		std::string ProcessAIResponse(const std::string& response);
		
		/// Memory pattern analysis
		void AnalyzeMemoryAccessPattern(u32 address, size_t size, const std::string& operation);
		std::string IdentifyMemoryRegionPurpose(u32 address);

		/// Cross-reference analysis
		void BuildFunctionCallGraph();
		void AnalyzeFunctionRelationships();
		void CorrelateWithGameplayEvents();

		/// Statistical analysis
		void UpdateFunctionStatistics(DiscoveredFunction& function);
		float CalculateFunctionConfidence(const DiscoveredFunction& function);
		void AnalyzeExecutionFrequency();

		/// Utility functions
		std::string FormatAddress(u32 address) const;
		std::string GenerateTimestamp() const;
		bool IsValidCodeAddress(u32 address) const;
	};

} // namespace AnalysisFramework