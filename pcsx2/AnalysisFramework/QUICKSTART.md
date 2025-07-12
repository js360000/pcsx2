# PCSX2 Analysis Framework - Quick Start Guide

## Overview

The PCSX2 Analysis Framework transforms PCSX2 into a comprehensive platform for PlayStation 2 game analysis, reverse engineering, and real-time debugging. This guide will help you get started quickly.

## Quick Setup

### 1. Enable the Analysis Framework

The Analysis Framework is automatically initialized when PCSX2 starts. You should see these messages in the console:

```
(AnalysisFramework) Initializing Analysis Framework...
(AnalysisFramework) Analysis Framework initialized successfully
(MCPServer) MCP Server started, integrating with PINE on slot 28011
(VMManager) Analysis Framework modules registered successfully
```

### 2. Test MCP Server Connection

Use the provided Python example to test connectivity:

```bash
cd pcsx2/AnalysisFramework/examples/
python3 mcp_client_example.py basic
```

Expected output:
```
=== PCSX2 Analysis Framework MCP Client Example ===

Connected to PCSX2 MCP server at localhost:28011
1. Listing available analysis tools...
   Tools request sent (ID: 1)
...
```

## Common Use Cases

### AI-Assisted Game Analysis

The MCP server enables AI tools to analyze PS2 games in real-time:

```python
# Example AI analysis workflow
client = PCSX2MCPClient()
client.connect()

# Discover capabilities
tools = client.list_tools()

# Analyze current state
state = client.get_game_state()
metrics = client.get_performance_metrics()

# Read key memory regions
main_memory = client.read_memory(0x00000000, 1024)
entry_point = client.read_memory(0x00100000, 512)

# Set analysis breakpoints
client.set_breakpoint(0x00100000)  # Main function
client.set_breakpoint(0x00100100)  # Init function

# Disassemble key areas
code = client.disassemble(0x00100000, 20)
```

### Memory Analysis and Cheating

Find and modify game values in real-time:

```python
# Search for player health value
client.scan_memory("64000000")  # Search for value 100

# Monitor register changes
registers = client.get_registers()

# Modify memory values
client.write_memory(0x00123456, b"\xFF\xFF\xFF\xFF")  # Max value
```

### IDA Pro Integration

Export PCSX2 analysis to IDA Pro:

```python
# In PCSX2 C++ code
auto idaInterface = core.GetModule("ida_interface");
if (idaInterface) {
    // Add symbols discovered during emulation
    SymbolInfo symbol;
    symbol.address = 0x00100000;
    symbol.name = "discovered_function";
    symbol.type = "function";
    idaInterface->AddSymbol(symbol);
    
    // Export to IDA script
    idaInterface->ExportToIDADatabase("game_analysis");
}
```

Then in IDA Pro:
1. Load the generated Python script
2. Run it to import PCSX2's analysis
3. Use the provided IDA plugin for bidirectional sync

### Ghidra Integration

Export memory dumps and analysis scripts:

```python
# Export PS2 memory for Ghidra analysis
ghidra = core.GetModule("ghidra_analyzer");
ghidra->ExportFullMemoryImage("ps2_memory.bin");

# Generate Ghidra analysis script
GhidraAnalysisConfig config;
config.enableDecompiler = true;
config.enableFunctionAnalysis = true;
ghidra->GenerateGhidraScript("ps2_analysis.py", config);
```

## Available Tools

### MCP Server Tools

| Tool | Description | Parameters |
|------|-------------|------------|
| `read_memory` | Read PS2 memory | address, size |
| `write_memory` | Write PS2 memory | address, data |
| `scan_memory` | Scan for patterns | pattern, mask |
| `get_registers` | Get CPU registers | none |
| `set_register` | Set CPU register | name, value |
| `get_breakpoints` | List breakpoints | none |
| `set_breakpoint` | Set breakpoint | address |
| `remove_breakpoint` | Remove breakpoint | address |
| `disassemble` | Disassemble code | address, count |
| `get_game_state` | Get VM state | none |
| `get_performance_metrics` | Get performance data | none |

### Memory Regions

| Region | Address Range | Description |
|--------|---------------|-------------|
| Main Memory | 0x00000000-0x01FFFFFF | 32MB system RAM |
| Scratchpad | 0x70000000-0x70003FFF | 16KB fast memory |
| I/O Registers | 0x10000000-0x1FFFFFFF | Hardware registers |
| BIOS ROM | 0x1FC00000-0x1FFFFFFF | System BIOS |

## Examples

### Basic Memory Reading

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "read_memory",
    "arguments": {
      "address": "0x00100000",
      "size": 256
    }
  },
  "id": 1
}
```

### Pattern Scanning

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "scan_memory",
    "arguments": {
      "pattern": "DEADBEEF",
      "mask": "FFFFFFFF"
    }
  },
  "id": 2
}
```

### Register Access

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "get_registers",
    "arguments": {}
  },
  "id": 3
}
```

## Troubleshooting

### Connection Issues

1. **Cannot connect to MCP server**
   - Check that PCSX2 is running
   - Verify port 28011 is not blocked
   - Check console for initialization messages

2. **Tools not responding**
   - Ensure a game is loaded
   - Check that emulation is active
   - Verify memory addresses are valid

### Performance Issues

1. **Emulation slowdown**
   - Disable unused analysis modules
   - Reduce memory scanning frequency
   - Limit real-time monitoring

2. **Memory scanning timeout**
   - Reduce scan range
   - Use more specific patterns
   - Increase timeout values

### Integration Issues

1. **IDA Pro plugin not working**
   - Check IDA Pro Python environment
   - Verify plugin installation
   - Check console for error messages

2. **Ghidra scripts failing**
   - Ensure Ghidra version compatibility
   - Check script syntax
   - Verify memory dump format

## Advanced Usage

### Custom Analysis Modules

Create your own analysis modules:

```cpp
class CustomAnalyzer : public AnalysisFramework::IAnalysisModule
{
public:
    bool Initialize() override {
        // Your initialization code
        return true;
    }
    
    void OnFrameworkEvent(AnalysisEvent event, const void* data, size_t size) override {
        // Handle framework events
        if (event == AnalysisEvent::MemoryWrite) {
            // Analyze memory writes
        }
    }
};

// Register with framework
auto analyzer = std::make_shared<CustomAnalyzer>();
AnalysisFrameworkCore::GetInstance().RegisterModule(analyzer);
```

### Real-Time Monitoring

Set up continuous monitoring:

```python
def monitor_memory_changes():
    client = PCSX2MCPClient()
    client.connect()
    
    # Set up watchpoints
    watch_addresses = [0x00123456, 0x00789ABC]
    
    while True:
        for addr in watch_addresses:
            value = client.read_memory(addr, 4)
            # Process value changes
        
        time.sleep(0.1)  # 100ms polling
```

### Automated Analysis Scripts

Create analysis workflows:

```python
def analyze_game_automatically():
    client = PCSX2MCPClient()
    client.connect()
    
    # 1. Wait for game to load
    while True:
        state = client.get_game_state()
        if state and "running" in str(state):
            break
        time.sleep(1)
    
    # 2. Scan for common patterns
    patterns = ["DEADBEEF", "12345678", "FFFFFFFF"]
    for pattern in patterns:
        results = client.scan_memory(pattern)
        # Process results
    
    # 3. Set strategic breakpoints
    entry_points = [0x00100000, 0x00100100, 0x00100200]
    for addr in entry_points:
        client.set_breakpoint(addr)
    
    # 4. Generate report
    generate_analysis_report()
```

## Next Steps

1. **Explore Examples**: Try all example scripts in the `examples/` directory
2. **Read Full Documentation**: See `README.md` for complete feature details
3. **Create Custom Tools**: Build your own analysis modules
4. **Integrate with AI**: Connect AI tools via the MCP protocol
5. **Contribute**: Help improve the framework with feedback and contributions

For complete documentation, see the main [README.md](README.md) file.