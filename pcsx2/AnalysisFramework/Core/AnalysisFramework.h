// SPDX-FileCopyrightText: 2002-2025 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include "Common.h"
#include <memory>
#include <vector>
#include <unordered_map>
#include <functional>

namespace AnalysisFramework
{
	/// Forward declarations
	class IAnalysisModule;
	class IMemoryInterface;
	class IDebugInterface;

	/// Analysis framework event types
	enum class AnalysisEvent
	{
		MemoryRead,
		MemoryWrite,
		BreakpointHit,
		GameStateChange,
		PerformanceUpdate
	};

	/// Event callback signature
	using EventCallback = std::function<void(AnalysisEvent event, const void* data, size_t size)>;

	/// Core analysis framework manager
	class AnalysisFrameworkCore
	{
	public:
		static AnalysisFrameworkCore& GetInstance();

		/// Lifecycle management
		bool Initialize();
		void Shutdown();
		bool IsInitialized() const { return m_initialized; }

		/// Module management
		bool RegisterModule(std::shared_ptr<IAnalysisModule> module);
		bool UnregisterModule(const std::string& moduleId);
		std::shared_ptr<IAnalysisModule> GetModule(const std::string& moduleId);

		/// Event system
		void RegisterEventCallback(AnalysisEvent event, EventCallback callback);
		void UnregisterEventCallback(AnalysisEvent event);
		void TriggerEvent(AnalysisEvent event, const void* data = nullptr, size_t size = 0);

		/// Interface access
		IMemoryInterface* GetMemoryInterface() const { return m_memoryInterface.get(); }
		IDebugInterface* GetDebugInterface() const { return m_debugInterface.get(); }

		/// Configuration
		void SetEnabled(bool enabled) { m_enabled = enabled; }
		bool IsEnabled() const { return m_enabled; }

	private:
		AnalysisFrameworkCore() = default;
		~AnalysisFrameworkCore() = default;

		bool m_initialized = false;
		bool m_enabled = false;

		std::unordered_map<std::string, std::shared_ptr<IAnalysisModule>> m_modules;
		std::unordered_map<AnalysisEvent, std::vector<EventCallback>> m_eventCallbacks;

		std::unique_ptr<IMemoryInterface> m_memoryInterface;
		std::unique_ptr<IDebugInterface> m_debugInterface;
	};

	/// Base interface for analysis modules
	class IAnalysisModule
	{
	public:
		virtual ~IAnalysisModule() = default;

		virtual const std::string& GetModuleId() const = 0;
		virtual const std::string& GetModuleName() const = 0;
		virtual const std::string& GetModuleVersion() const = 0;

		virtual bool Initialize() = 0;
		virtual void Shutdown() = 0;
		virtual bool IsInitialized() const = 0;

		virtual void OnFrameworkEvent(AnalysisEvent event, const void* data, size_t size) {}
	};

	/// Memory analysis interface
	class IMemoryInterface
	{
	public:
		virtual ~IMemoryInterface() = default;

		/// Memory reading
		virtual bool ReadMemory(u32 address, void* buffer, size_t size) = 0;
		virtual u8 ReadMemory8(u32 address) = 0;
		virtual u16 ReadMemory16(u32 address) = 0;
		virtual u32 ReadMemory32(u32 address) = 0;
		virtual u64 ReadMemory64(u32 address) = 0;

		/// Memory writing
		virtual bool WriteMemory(u32 address, const void* buffer, size_t size) = 0;
		virtual bool WriteMemory8(u32 address, u8 value) = 0;
		virtual bool WriteMemory16(u32 address, u16 value) = 0;
		virtual bool WriteMemory32(u32 address, u32 value) = 0;
		virtual bool WriteMemory64(u32 address, u64 value) = 0;

		/// Memory validation
		virtual bool IsValidAddress(u32 address) = 0;
		virtual bool IsWritableAddress(u32 address) = 0;

		/// Memory scanning
		virtual std::vector<u32> ScanPattern(const std::vector<u8>& pattern, 
											  const std::vector<bool>& mask = {}) = 0;
		virtual std::vector<u32> ScanValue(const void* value, size_t valueSize) = 0;
	};

	/// Debug interface for breakpoints and analysis
	class IDebugInterface
	{
	public:
		virtual ~IDebugInterface() = default;

		/// Breakpoint management
		virtual bool SetBreakpoint(u32 address, bool enabled = true) = 0;
		virtual bool RemoveBreakpoint(u32 address) = 0;
		virtual bool IsBreakpointSet(u32 address) = 0;
		virtual std::vector<u32> GetBreakpoints() = 0;

		/// Register access
		virtual u32 GetRegister(const std::string& regName) = 0;
		virtual bool SetRegister(const std::string& regName, u32 value) = 0;
		virtual std::unordered_map<std::string, u32> GetAllRegisters() = 0;

		/// Execution control
		virtual bool IsRunning() = 0;
		virtual bool IsPaused() = 0;
		virtual void Pause() = 0;
		virtual void Resume() = 0;
		virtual void StepInstruction() = 0;

		/// Disassembly
		virtual std::string DisassembleInstruction(u32 address) = 0;
		virtual std::vector<std::string> DisassembleRange(u32 startAddress, u32 endAddress) = 0;
	};

} // namespace AnalysisFramework