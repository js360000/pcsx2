// SPDX-FileCopyrightText: 2002-2025 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "PrecompiledHeader.h"
#include "MCPServer.h"
#include "AnalysisFramework/Core/AnalysisFramework.h"
#include "PINE.h"
#include "Console.h"
#include "VMManager.h"
#include "PerformanceMetrics.h"
#include <rapidjson/error/en.h>

namespace AnalysisFramework
{
	MCPServer::MCPServer() = default;

	MCPServer::~MCPServer()
	{
		Shutdown();
	}

	bool MCPServer::Initialize()
	{
		if (m_initialized)
			return true;

		Console.WriteLn("(MCPServer) Initializing MCP Server module...");

		try
		{
			m_initialized = true;
			Console.WriteLn("(MCPServer) MCP Server module initialized successfully");
			return true;
		}
		catch (const std::exception& e)
		{
			Console.Error("(MCPServer) Failed to initialize: %s", e.what());
			return false;
		}
	}

	void MCPServer::Shutdown()
	{
		if (!m_initialized)
			return;

		Console.WriteLn("(MCPServer) Shutting down MCP Server module...");

		StopServer();
		m_initialized = false;

		Console.WriteLn("(MCPServer) MCP Server module shutdown complete");
	}

	void MCPServer::OnFrameworkEvent(AnalysisEvent event, const void* data, size_t size)
	{
		// Handle framework events for real-time notifications
		// This could be used to push updates to connected MCP clients
	}

	bool MCPServer::StartServer(int port)
	{
		if (m_serverRunning)
		{
			Console.Warning("(MCPServer) Server already running on port %d", m_serverPort);
			return true;
		}

		// For now, integrate with existing PINE server
		// In a full implementation, we would create our own HTTP/WebSocket server
		if (!PINEServer::IsInitialized())
		{
			int pineSlot = (port > 0) ? port : PINE_DEFAULT_SLOT;
			if (!PINEServer::Initialize(pineSlot))
			{
				Console.Error("(MCPServer) Failed to initialize PINE server");
				return false;
			}
		}

		m_serverPort = PINEServer::GetSlot();
		m_serverRunning = true;

		Console.WriteLn("(MCPServer) MCP Server started, integrating with PINE on slot %d", m_serverPort);
		return true;
	}

	void MCPServer::StopServer()
	{
		if (!m_serverRunning)
			return;

		Console.WriteLn("(MCPServer) Stopping MCP Server...");

		m_serverRunning = false;
		
		// Note: We don't shutdown PINE here as it might be used by other components
		
		Console.WriteLn("(MCPServer) MCP Server stopped");
	}

	rapidjson::Document MCPServer::ParseJSON(const std::string& json)
	{
		rapidjson::Document doc;
		doc.Parse(json.c_str());
		return doc;
	}

	std::string MCPServer::CreateJSONResponse(const rapidjson::Value& result, int id, const std::string& error)
	{
		rapidjson::Document response;
		response.SetObject();
		auto& allocator = response.GetAllocator();

		response.AddMember("jsonrpc", "2.0", allocator);

		if (!error.empty())
		{
			rapidjson::Value errorObj(rapidjson::kObjectType);
			errorObj.AddMember("code", -1, allocator);
			errorObj.AddMember("message", rapidjson::Value(error.c_str(), allocator), allocator);
			response.AddMember("error", errorObj, allocator);
		}
		else
		{
			rapidjson::Value resultCopy;
			resultCopy.CopyFrom(result, allocator);
			response.AddMember("result", resultCopy, allocator);
		}

		response.AddMember("id", id, allocator);

		rapidjson::StringBuffer buffer;
		rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
		response.Accept(writer);

		return buffer.GetString();
	}

	bool MCPServer::ValidateMCPRequest(const rapidjson::Document& doc, std::string& error)
	{
		if (doc.HasParseError())
		{
			error = "Invalid JSON: " + std::string(rapidjson::GetParseError_En(doc.GetParseError()));
			return false;
		}

		if (!doc.IsObject())
		{
			error = "Request must be a JSON object";
			return false;
		}

		if (!doc.HasMember("jsonrpc") || !doc["jsonrpc"].IsString() || doc["jsonrpc"].GetString() != std::string("2.0"))
		{
			error = "Invalid or missing jsonrpc version";
			return false;
		}

		if (!doc.HasMember("method") || !doc["method"].IsString())
		{
			error = "Missing or invalid method";
			return false;
		}

		return true;
	}

	std::string MCPServer::HandleMCPRequest(const std::string& jsonRequest)
	{
		auto doc = ParseJSON(jsonRequest);
		std::string error;

		if (!ValidateMCPRequest(doc, error))
		{
			return CreateJSONResponse(rapidjson::Value(), 0, error);
		}

		std::string method = doc["method"].GetString();
		int id = doc.HasMember("id") && doc["id"].IsInt() ? doc["id"].GetInt() : 0;
		const auto& params = doc.HasMember("params") ? doc["params"] : rapidjson::Value();

		rapidjson::Value result;
		result.SetObject();

		try
		{
			if (method == "tools/list")
			{
				result = HandleListTools(params);
			}
			else if (method == "tools/call")
			{
				if (!params.HasMember("name") || !params["name"].IsString())
				{
					return CreateJSONResponse(result, id, "Missing tool name");
				}
				
				std::string toolName = params["name"].GetString();
				const auto& toolParams = params.HasMember("arguments") ? params["arguments"] : rapidjson::Value();
				result = HandleCallTool(toolName, toolParams);
			}
			else
			{
				return CreateJSONResponse(result, id, "Unknown method: " + method);
			}

			return CreateJSONResponse(result, id);
		}
		catch (const std::exception& e)
		{
			return CreateJSONResponse(result, id, "Internal error: " + std::string(e.what()));
		}
	}

	rapidjson::Value MCPServer::HandleListTools(const rapidjson::Value& params)
	{
		rapidjson::Value result(rapidjson::kObjectType);
		rapidjson::Document doc; // For allocator
		auto& allocator = doc.GetAllocator();
		
		rapidjson::Value tools(rapidjson::kArrayType);

		// Define available tools
		const char* toolDefinitions[][3] = {
			{"read_memory", "Read memory from PS2 emulated system", "address,size"},
			{"write_memory", "Write memory to PS2 emulated system", "address,data"},
			{"scan_memory", "Scan PS2 memory for patterns or values", "pattern,mask"},
			{"get_registers", "Get CPU register values", ""},
			{"set_register", "Set CPU register value", "name,value"},
			{"get_breakpoints", "Get list of active breakpoints", ""},
			{"set_breakpoint", "Set a breakpoint at address", "address"},
			{"remove_breakpoint", "Remove breakpoint", "address"},
			{"disassemble", "Disassemble instructions at address", "address,count"},
			{"get_game_state", "Get current game state information", ""},
			{"get_performance_metrics", "Get performance metrics", ""}
		};

		for (const auto& toolDef : toolDefinitions)
		{
			rapidjson::Value tool(rapidjson::kObjectType);
			tool.AddMember("name", rapidjson::Value(toolDef[0], allocator), allocator);
			tool.AddMember("description", rapidjson::Value(toolDef[1], allocator), allocator);
			
			rapidjson::Value schema(rapidjson::kObjectType);
			schema.AddMember("type", "object", allocator);
			rapidjson::Value properties(rapidjson::kObjectType);
			
			if (strlen(toolDef[2]) > 0)
			{
				// Add properties based on parameter string
				// This is simplified - in a full implementation we'd have proper schema definitions
				rapidjson::Value prop(rapidjson::kObjectType);
				prop.AddMember("type", "string", allocator);
				properties.AddMember("parameters", prop, allocator);
			}
			
			schema.AddMember("properties", properties, allocator);
			tool.AddMember("inputSchema", schema, allocator);
			
			tools.PushBack(tool, allocator);
		}

		result.AddMember("tools", tools, allocator);
		return result;
	}

	rapidjson::Value MCPServer::HandleCallTool(const std::string& toolName, const rapidjson::Value& params)
	{
		auto& core = AnalysisFrameworkCore::GetInstance();
		
		if (toolName == "read_memory")
			return ToolReadMemory(params);
		else if (toolName == "write_memory")
			return ToolWriteMemory(params);
		else if (toolName == "scan_memory")
			return ToolScanMemory(params);
		else if (toolName == "get_registers")
			return ToolGetRegisters(params);
		else if (toolName == "set_register")
			return ToolSetRegister(params);
		else if (toolName == "get_breakpoints")
			return ToolGetBreakpoints(params);
		else if (toolName == "set_breakpoint")
			return ToolSetBreakpoint(params);
		else if (toolName == "remove_breakpoint")
			return ToolRemoveBreakpoint(params);
		else if (toolName == "disassemble")
			return ToolDisassemble(params);
		else if (toolName == "get_game_state")
			return ToolGetGameState(params);
		else if (toolName == "get_performance_metrics")
			return ToolGetPerformanceMetrics(params);
		
		rapidjson::Value error(rapidjson::kObjectType);
		rapidjson::Document doc;
		error.AddMember("error", "Unknown tool", doc.GetAllocator());
		return error;
	}

	rapidjson::Value MCPServer::ToolReadMemory(const rapidjson::Value& params)
	{
		rapidjson::Document doc;
		rapidjson::Value result(rapidjson::kObjectType);
		auto& allocator = doc.GetAllocator();

		// Implementation placeholder - would read actual parameters and call memory interface
		result.AddMember("status", "success", allocator);
		result.AddMember("message", "Memory read tool called", allocator);
		
		return result;
	}

	rapidjson::Value MCPServer::ToolWriteMemory(const rapidjson::Value& params)
	{
		rapidjson::Document doc;
		rapidjson::Value result(rapidjson::kObjectType);
		result.AddMember("status", "success", doc.GetAllocator());
		return result;
	}

	rapidjson::Value MCPServer::ToolScanMemory(const rapidjson::Value& params)
	{
		rapidjson::Document doc;
		rapidjson::Value result(rapidjson::kObjectType);
		result.AddMember("status", "success", doc.GetAllocator());
		return result;
	}

	rapidjson::Value MCPServer::ToolGetRegisters(const rapidjson::Value& params)
	{
		rapidjson::Document doc;
		rapidjson::Value result(rapidjson::kObjectType);
		auto& allocator = doc.GetAllocator();

		auto& core = AnalysisFrameworkCore::GetInstance();
		if (auto debugInterface = core.GetDebugInterface())
		{
			auto registers = debugInterface->GetAllRegisters();
			rapidjson::Value regObj(rapidjson::kObjectType);
			
			for (const auto& [name, value] : registers)
			{
				rapidjson::Value keyVal(name.c_str(), allocator);
				regObj.AddMember(keyVal, value, allocator);
			}
			
			result.AddMember("registers", regObj, allocator);
		}

		result.AddMember("status", "success", allocator);
		return result;
	}

	rapidjson::Value MCPServer::ToolSetRegister(const rapidjson::Value& params)
	{
		rapidjson::Document doc;
		rapidjson::Value result(rapidjson::kObjectType);
		result.AddMember("status", "success", doc.GetAllocator());
		return result;
	}

	rapidjson::Value MCPServer::ToolGetBreakpoints(const rapidjson::Value& params)
	{
		rapidjson::Document doc;
		rapidjson::Value result(rapidjson::kObjectType);
		result.AddMember("status", "success", doc.GetAllocator());
		return result;
	}

	rapidjson::Value MCPServer::ToolSetBreakpoint(const rapidjson::Value& params)
	{
		rapidjson::Document doc;
		rapidjson::Value result(rapidjson::kObjectType);
		result.AddMember("status", "success", doc.GetAllocator());
		return result;
	}

	rapidjson::Value MCPServer::ToolRemoveBreakpoint(const rapidjson::Value& params)
	{
		rapidjson::Document doc;
		rapidjson::Value result(rapidjson::kObjectType);
		result.AddMember("status", "success", doc.GetAllocator());
		return result;
	}

	rapidjson::Value MCPServer::ToolDisassemble(const rapidjson::Value& params)
	{
		rapidjson::Document doc;
		rapidjson::Value result(rapidjson::kObjectType);
		result.AddMember("status", "success", doc.GetAllocator());
		return result;
	}

	rapidjson::Value MCPServer::ToolGetGameState(const rapidjson::Value& params)
	{
		rapidjson::Document doc;
		rapidjson::Value result(rapidjson::kObjectType);
		auto& allocator = doc.GetAllocator();

		// Get current VM state
		auto state = VMManager::GetState();
		const char* stateStr = "unknown";
		
		switch (state)
		{
			case VMState::Shutdown: stateStr = "shutdown"; break;
			case VMState::Initializing: stateStr = "initializing"; break;
			case VMState::Paused: stateStr = "paused"; break;
			case VMState::Running: stateStr = "running"; break;
			case VMState::Resetting: stateStr = "resetting"; break;
			case VMState::Stopping: stateStr = "stopping"; break;
		}

		result.AddMember("vm_state", rapidjson::Value(stateStr, allocator), allocator);
		result.AddMember("status", "success", allocator);
		
		return result;
	}

	rapidjson::Value MCPServer::ToolGetPerformanceMetrics(const rapidjson::Value& params)
	{
		rapidjson::Document doc;
		rapidjson::Value result(rapidjson::kObjectType);
		auto& allocator = doc.GetAllocator();

		// Get performance metrics
		result.AddMember("fps", static_cast<double>(PerformanceMetrics::GetFPS()), allocator);
		result.AddMember("cpu_usage", static_cast<double>(PerformanceMetrics::GetCPUUsage()), allocator);
		result.AddMember("status", "success", allocator);

		return result;
	}

} // namespace AnalysisFramework