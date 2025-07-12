// SPDX-FileCopyrightText: 2002-2025 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include <gtest/gtest.h>
#include "AnalysisFramework/Core/AnalysisFramework.h"
#include "AnalysisFramework/MCPServer/MCPServer.h"
#include "AnalysisFramework/IDAInterface/IDAInterface.h"
#include "AnalysisFramework/GhidraAnalyzer/GhidraAnalyzer.h"
#include "AnalysisFramework/Common/Utilities.h"

using namespace AnalysisFramework;

class AnalysisFrameworkTest : public ::testing::Test
{
protected:
	void SetUp() override
	{
		// Clean state for each test
		auto& core = AnalysisFrameworkCore::GetInstance();
		if (core.IsInitialized())
		{
			core.Shutdown();
		}
	}

	void TearDown() override
	{
		auto& core = AnalysisFrameworkCore::GetInstance();
		if (core.IsInitialized())
		{
			core.Shutdown();
		}
	}
};

TEST_F(AnalysisFrameworkTest, CoreInitialization)
{
	auto& core = AnalysisFrameworkCore::GetInstance();
	
	EXPECT_FALSE(core.IsInitialized());
	EXPECT_TRUE(core.Initialize());
	EXPECT_TRUE(core.IsInitialized());
	
	// Should have interfaces available
	EXPECT_NE(core.GetMemoryInterface(), nullptr);
	EXPECT_NE(core.GetDebugInterface(), nullptr);
}

TEST_F(AnalysisFrameworkTest, ModuleRegistration)
{
	auto& core = AnalysisFrameworkCore::GetInstance();
	ASSERT_TRUE(core.Initialize());
	
	// Register MCP Server module
	auto mcpServer = std::make_shared<MCPServer>();
	EXPECT_TRUE(core.RegisterModule(mcpServer));
	
	// Verify module is registered
	auto retrieved = core.GetModule("mcp_server");
	EXPECT_NE(retrieved, nullptr);
	EXPECT_EQ(retrieved->GetModuleId(), "mcp_server");
	
	// Register IDA Interface module
	auto idaInterface = std::make_shared<IDAInterface>();
	EXPECT_TRUE(core.RegisterModule(idaInterface));
	
	// Register Ghidra Analyzer module
	auto ghidraAnalyzer = std::make_shared<GhidraAnalyzer>();
	EXPECT_TRUE(core.RegisterModule(ghidraAnalyzer));
}

TEST_F(AnalysisFrameworkTest, MCPServerBasics)
{
	auto mcpServer = std::make_shared<MCPServer>();
	
	EXPECT_FALSE(mcpServer->IsInitialized());
	EXPECT_TRUE(mcpServer->Initialize());
	EXPECT_TRUE(mcpServer->IsInitialized());
	
	EXPECT_EQ(mcpServer->GetModuleId(), "mcp_server");
	EXPECT_EQ(mcpServer->GetModuleName(), "MCP Protocol Server");
	EXPECT_FALSE(mcpServer->GetModuleVersion().empty());
}

TEST_F(AnalysisFrameworkTest, IDAInterfaceBasics)
{
	auto idaInterface = std::make_shared<IDAInterface>();
	
	EXPECT_FALSE(idaInterface->IsInitialized());
	EXPECT_TRUE(idaInterface->Initialize());
	EXPECT_TRUE(idaInterface->IsInitialized());
	
	EXPECT_EQ(idaInterface->GetModuleId(), "ida_interface");
	EXPECT_EQ(idaInterface->GetModuleName(), "IDA Pro Interface");
}

TEST_F(AnalysisFrameworkTest, GhidraAnalyzerBasics)
{
	auto ghidraAnalyzer = std::make_shared<GhidraAnalyzer>();
	
	EXPECT_FALSE(ghidraAnalyzer->IsInitialized());
	EXPECT_TRUE(ghidraAnalyzer->Initialize());
	EXPECT_TRUE(ghidraAnalyzer->IsInitialized());
	
	EXPECT_EQ(ghidraAnalyzer->GetModuleId(), "ghidra_analyzer");
	EXPECT_EQ(ghidraAnalyzer->GetModuleName(), "Ghidra Analyzer Integration");
}

TEST_F(AnalysisFrameworkTest, UtilitiesStringUtils)
{
	// Test string utilities
	EXPECT_EQ(StringUtils::ToLower("HELLO"), "hello");
	EXPECT_EQ(StringUtils::ToUpper("hello"), "HELLO");
	
	auto parts = StringUtils::Split("a,b,c", ',');
	ASSERT_EQ(parts.size(), 3);
	EXPECT_EQ(parts[0], "a");
	EXPECT_EQ(parts[1], "b");
	EXPECT_EQ(parts[2], "c");
	
	EXPECT_EQ(StringUtils::Join({"a", "b", "c"}, ","), "a,b,c");
	
	EXPECT_TRUE(StringUtils::StartsWith("hello world", "hello"));
	EXPECT_FALSE(StringUtils::StartsWith("hello world", "world"));
	
	EXPECT_TRUE(StringUtils::EndsWith("hello world", "world"));
	EXPECT_FALSE(StringUtils::EndsWith("hello world", "hello"));
}

TEST_F(AnalysisFrameworkTest, UtilitiesHexUtils)
{
	// Test hex utilities
	EXPECT_EQ(HexUtils::ToHex(0x12345678), "0x12345678");
	EXPECT_EQ(HexUtils::ToHex(0x12345678, false), "12345678");
	
	u32 value;
	EXPECT_TRUE(HexUtils::FromHex("0x12345678", value));
	EXPECT_EQ(value, 0x12345678);
	
	EXPECT_TRUE(HexUtils::FromHex("12345678", value));
	EXPECT_EQ(value, 0x12345678);
	
	auto bytes = HexUtils::FromHexString("DEADBEEF");
	ASSERT_EQ(bytes.size(), 4);
	EXPECT_EQ(bytes[0], 0xDE);
	EXPECT_EQ(bytes[1], 0xAD);
	EXPECT_EQ(bytes[2], 0xBE);
	EXPECT_EQ(bytes[3], 0xEF);
}

TEST_F(AnalysisFrameworkTest, UtilitiesAddressUtils)
{
	// Test address utilities
	EXPECT_TRUE(AddressUtils::IsValidPS2Address(0x00000000));
	EXPECT_TRUE(AddressUtils::IsValidPS2Address(0x01FFFFFF));
	EXPECT_FALSE(AddressUtils::IsValidPS2Address(0x20000000));
	
	EXPECT_TRUE(AddressUtils::IsMainMemoryAddress(0x00000000));
	EXPECT_TRUE(AddressUtils::IsMainMemoryAddress(0x01FFFFFF));
	EXPECT_FALSE(AddressUtils::IsMainMemoryAddress(0x70000000));
	
	EXPECT_TRUE(AddressUtils::IsScratchpadAddress(0x70000000));
	EXPECT_TRUE(AddressUtils::IsScratchpadAddress(0x70003FFF));
	EXPECT_FALSE(AddressUtils::IsScratchpadAddress(0x00000000));
	
	EXPECT_EQ(AddressUtils::GetAddressRegionName(0x00000000), "Main Memory");
	EXPECT_EQ(AddressUtils::GetAddressRegionName(0x70000000), "Scratchpad");
	EXPECT_EQ(AddressUtils::GetAddressRegionName(0x1FC00000), "BIOS ROM");
}

TEST_F(AnalysisFrameworkTest, EventSystem)
{
	auto& core = AnalysisFrameworkCore::GetInstance();
	ASSERT_TRUE(core.Initialize());
	
	bool eventReceived = false;
	core.RegisterEventCallback(AnalysisEvent::MemoryRead, 
		[&eventReceived](AnalysisEvent event, const void* data, size_t size) {
			eventReceived = true;
		});
	
	core.TriggerEvent(AnalysisEvent::MemoryRead);
	EXPECT_TRUE(eventReceived);
}

// Note: Memory and debug interface tests would require a running emulator
// so they are omitted from this basic test suite