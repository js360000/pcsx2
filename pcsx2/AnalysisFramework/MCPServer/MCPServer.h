// SPDX-FileCopyrightText: 2002-2025 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include "AnalysisFramework/Core/AnalysisFramework.h"
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>
#include <string>
#include <thread>
#include <atomic>
#include <memory>

namespace AnalysisFramework
{
	/// MCP (Model Context Protocol) server implementation
	/// Extends the existing PINE server functionality with MCP protocol support
	class MCPServer : public IAnalysisModule
	{
	public:
		MCPServer();
		virtual ~MCPServer();

		/// IAnalysisModule implementation
		const std::string& GetModuleId() const override { return m_moduleId; }
		const std::string& GetModuleName() const override { return m_moduleName; }
		const std::string& GetModuleVersion() const override { return m_moduleVersion; }

		bool Initialize() override;
		void Shutdown() override;
		bool IsInitialized() const override { return m_initialized; }

		void OnFrameworkEvent(AnalysisEvent event, const void* data, size_t size) override;

		/// MCP Server specific methods
		bool StartServer(int port = 0); // 0 = auto-select port
		void StopServer();
		bool IsServerRunning() const { return m_serverRunning; }
		int GetServerPort() const { return m_serverPort; }

		/// MCP Protocol handlers
		std::string HandleMCPRequest(const std::string& jsonRequest);

	private:
		// Module identification
		std::string m_moduleId = "mcp_server";
		std::string m_moduleName = "MCP Protocol Server";
		std::string m_moduleVersion = "1.0.0";

		bool m_initialized = false;
		std::atomic<bool> m_serverRunning{false};
		int m_serverPort = 0;
		std::unique_ptr<std::thread> m_serverThread;

		/// JSON processing helpers
		rapidjson::Document ParseJSON(const std::string& json);
		std::string CreateJSONResponse(const rapidjson::Value& result, int id = 0, 
									   const std::string& error = "");

		/// MCP method handlers
		rapidjson::Value HandleListTools(const rapidjson::Value& params);
		rapidjson::Value HandleCallTool(const std::string& toolName, const rapidjson::Value& params);

		/// Tool implementations
		rapidjson::Value ToolReadMemory(const rapidjson::Value& params);
		rapidjson::Value ToolWriteMemory(const rapidjson::Value& params);
		rapidjson::Value ToolScanMemory(const rapidjson::Value& params);
		rapidjson::Value ToolGetRegisters(const rapidjson::Value& params);
		rapidjson::Value ToolSetRegister(const rapidjson::Value& params);
		rapidjson::Value ToolGetBreakpoints(const rapidjson::Value& params);
		rapidjson::Value ToolSetBreakpoint(const rapidjson::Value& params);
		rapidjson::Value ToolRemoveBreakpoint(const rapidjson::Value& params);
		rapidjson::Value ToolDisassemble(const rapidjson::Value& params);
		rapidjson::Value ToolGetGameState(const rapidjson::Value& params);
		rapidjson::Value ToolGetPerformanceMetrics(const rapidjson::Value& params);

		/// Server thread function
		void ServerThreadFunc();

		/// Helper to validate MCP request format
		bool ValidateMCPRequest(const rapidjson::Document& doc, std::string& error);
	};

} // namespace AnalysisFramework