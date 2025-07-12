// SPDX-FileCopyrightText: 2002-2025 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "PrecompiledHeader.h"
#include "AnalysisFramework.h"
#include "MemoryInterface.h"
#include "DebugInterface.h"
#include "Console.h"

namespace AnalysisFramework
{
	AnalysisFrameworkCore& AnalysisFrameworkCore::GetInstance()
	{
		static AnalysisFrameworkCore instance;
		return instance;
	}

	bool AnalysisFrameworkCore::Initialize()
	{
		if (m_initialized)
			return true;

		Console.WriteLn("(AnalysisFramework) Initializing Analysis Framework...");

		try 
		{
			// Initialize memory interface
			m_memoryInterface = std::make_unique<MemoryInterface>();
			if (!m_memoryInterface)
			{
				Console.Error("(AnalysisFramework) Failed to create memory interface");
				return false;
			}

			// Initialize debug interface  
			m_debugInterface = std::make_unique<DebugInterface>();
			if (!m_debugInterface)
			{
				Console.Error("(AnalysisFramework) Failed to create debug interface");
				return false;
			}

			m_initialized = true;
			m_enabled = true;

			Console.WriteLn("(AnalysisFramework) Analysis Framework initialized successfully");
			return true;
		}
		catch (const std::exception& e)
		{
			Console.Error("(AnalysisFramework) Failed to initialize: %s", e.what());
			return false;
		}
	}

	void AnalysisFrameworkCore::Shutdown()
	{
		if (!m_initialized)
			return;

		Console.WriteLn("(AnalysisFramework) Shutting down Analysis Framework...");

		// Shutdown all modules
		for (auto& [id, module] : m_modules)
		{
			if (module && module->IsInitialized())
			{
				module->Shutdown();
			}
		}
		m_modules.clear();

		// Clear event callbacks
		m_eventCallbacks.clear();

		// Shutdown interfaces
		m_debugInterface.reset();
		m_memoryInterface.reset();

		m_initialized = false;
		m_enabled = false;

		Console.WriteLn("(AnalysisFramework) Analysis Framework shutdown complete");
	}

	bool AnalysisFrameworkCore::RegisterModule(std::shared_ptr<IAnalysisModule> module)
	{
		if (!module)
		{
			Console.Error("(AnalysisFramework) Cannot register null module");
			return false;
		}

		const std::string& moduleId = module->GetModuleId();
		if (m_modules.find(moduleId) != m_modules.end())
		{
			Console.Warning("(AnalysisFramework) Module '%s' already registered", moduleId.c_str());
			return false;
		}

		if (!module->Initialize())
		{
			Console.Error("(AnalysisFramework) Failed to initialize module '%s'", moduleId.c_str());
			return false;
		}

		m_modules[moduleId] = module;
		Console.WriteLn("(AnalysisFramework) Registered module '%s' (%s v%s)", 
			moduleId.c_str(), module->GetModuleName().c_str(), module->GetModuleVersion().c_str());

		return true;
	}

	bool AnalysisFrameworkCore::UnregisterModule(const std::string& moduleId)
	{
		auto it = m_modules.find(moduleId);
		if (it == m_modules.end())
		{
			Console.Warning("(AnalysisFramework) Module '%s' not found", moduleId.c_str());
			return false;
		}

		if (it->second && it->second->IsInitialized())
		{
			it->second->Shutdown();
		}

		m_modules.erase(it);
		Console.WriteLn("(AnalysisFramework) Unregistered module '%s'", moduleId.c_str());

		return true;
	}

	std::shared_ptr<IAnalysisModule> AnalysisFrameworkCore::GetModule(const std::string& moduleId)
	{
		auto it = m_modules.find(moduleId);
		return (it != m_modules.end()) ? it->second : nullptr;
	}

	void AnalysisFrameworkCore::RegisterEventCallback(AnalysisEvent event, EventCallback callback)
	{
		if (callback)
		{
			m_eventCallbacks[event].push_back(callback);
		}
	}

	void AnalysisFrameworkCore::UnregisterEventCallback(AnalysisEvent event)
	{
		m_eventCallbacks[event].clear();
	}

	void AnalysisFrameworkCore::TriggerEvent(AnalysisEvent event, const void* data, size_t size)
	{
		if (!m_enabled)
			return;

		// Call registered callbacks
		auto it = m_eventCallbacks.find(event);
		if (it != m_eventCallbacks.end())
		{
			for (const auto& callback : it->second)
			{
				try
				{
					callback(event, data, size);
				}
				catch (const std::exception& e)
				{
					Console.Error("(AnalysisFramework) Event callback exception: %s", e.what());
				}
			}
		}

		// Notify all modules
		for (auto& [id, module] : m_modules)
		{
			if (module && module->IsInitialized())
			{
				try
				{
					module->OnFrameworkEvent(event, data, size);
				}
				catch (const std::exception& e)
				{
					Console.Error("(AnalysisFramework) Module '%s' event handler exception: %s", 
						id.c_str(), e.what());
				}
			}
		}
	}

} // namespace AnalysisFramework