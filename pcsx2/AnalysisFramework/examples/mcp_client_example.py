#!/usr/bin/env python3
"""
PCSX2 Analysis Framework - MCP Client Example

This script demonstrates how to connect to PCSX2's MCP server
and perform basic analysis operations.

Requirements:
- PCSX2 running with Analysis Framework enabled
- Python 3.6+
- No additional dependencies (uses only stdlib)
"""

import json
import socket
import sys
from typing import Dict, Any, Optional


class PCSX2MCPClient:
    """Simple MCP client for PCSX2 Analysis Framework"""
    
    def __init__(self, host: str = "localhost", port: int = 28011):
        self.host = host
        self.port = port
        self.socket = None
        self.request_id = 0
        
    def connect(self) -> bool:
        """Connect to PCSX2 MCP server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            print(f"Connected to PCSX2 MCP server at {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"Failed to connect: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from MCP server"""
        if self.socket:
            self.socket.close()
            self.socket = None
            print("Disconnected from PCSX2 MCP server")
    
    def send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """Send MCP request and return response"""
        if not self.socket:
            print("Not connected to server")
            return None
        
        self.request_id += 1
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "id": self.request_id
        }
        
        if params:
            request["params"] = params
        
        try:
            # Send request
            request_data = json.dumps(request) + "\n"
            self.socket.send(request_data.encode('utf-8'))
            
            # Note: This is a simplified implementation
            # A real implementation would need proper JSON-RPC framing
            print(f"Sent request: {method}")
            return {"status": "sent", "id": self.request_id}
            
        except Exception as e:
            print(f"Failed to send request: {e}")
            return None
    
    def list_tools(self) -> Optional[Dict[str, Any]]:
        """Get list of available analysis tools"""
        return self.send_request("tools/list")
    
    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Call a specific analysis tool"""
        params = {
            "name": tool_name,
            "arguments": arguments
        }
        return self.send_request("tools/call", params)
    
    def read_memory(self, address: int, size: int) -> Optional[Dict[str, Any]]:
        """Read memory from PS2 emulated system"""
        return self.call_tool("read_memory", {
            "address": f"0x{address:08X}",
            "size": size
        })
    
    def write_memory(self, address: int, data: bytes) -> Optional[Dict[str, Any]]:
        """Write memory to PS2 emulated system"""
        return self.call_tool("write_memory", {
            "address": f"0x{address:08X}",
            "data": data.hex()
        })
    
    def scan_memory(self, pattern: str, mask: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Scan PS2 memory for pattern"""
        args = {"pattern": pattern}
        if mask:
            args["mask"] = mask
        return self.call_tool("scan_memory", args)
    
    def get_registers(self) -> Optional[Dict[str, Any]]:
        """Get CPU register values"""
        return self.call_tool("get_registers", {})
    
    def set_register(self, register_name: str, value: int) -> Optional[Dict[str, Any]]:
        """Set CPU register value"""
        return self.call_tool("set_register", {
            "name": register_name,
            "value": value
        })
    
    def get_breakpoints(self) -> Optional[Dict[str, Any]]:
        """Get list of active breakpoints"""
        return self.call_tool("get_breakpoints", {})
    
    def set_breakpoint(self, address: int) -> Optional[Dict[str, Any]]:
        """Set breakpoint at address"""
        return self.call_tool("set_breakpoint", {
            "address": f"0x{address:08X}"
        })
    
    def remove_breakpoint(self, address: int) -> Optional[Dict[str, Any]]:
        """Remove breakpoint"""
        return self.call_tool("remove_breakpoint", {
            "address": f"0x{address:08X}"
        })
    
    def disassemble(self, address: int, count: int = 10) -> Optional[Dict[str, Any]]:
        """Disassemble instructions at address"""
        return self.call_tool("disassemble", {
            "address": f"0x{address:08X}",
            "count": count
        })
    
    def get_game_state(self) -> Optional[Dict[str, Any]]:
        """Get current game state"""
        return self.call_tool("get_game_state", {})
    
    def get_performance_metrics(self) -> Optional[Dict[str, Any]]:
        """Get performance metrics"""
        return self.call_tool("get_performance_metrics", {})


def example_basic_usage():
    """Example of basic MCP client usage"""
    print("=== PCSX2 Analysis Framework MCP Client Example ===\n")
    
    # Create client
    client = PCSX2MCPClient()
    
    # Connect to server
    if not client.connect():
        return
    
    try:
        # List available tools
        print("1. Listing available analysis tools...")
        tools = client.list_tools()
        if tools:
            print(f"   Tools request sent (ID: {tools.get('id')})")
        
        # Get game state
        print("\n2. Getting game state...")
        state = client.get_game_state()
        if state:
            print(f"   Game state request sent (ID: {state.get('id')})")
        
        # Get performance metrics
        print("\n3. Getting performance metrics...")
        metrics = client.get_performance_metrics()
        if metrics:
            print(f"   Performance metrics request sent (ID: {metrics.get('id')})")
        
        # Read memory example
        print("\n4. Reading memory from main memory...")
        memory = client.read_memory(0x00100000, 256)
        if memory:
            print(f"   Memory read request sent (ID: {memory.get('id')})")
        
        # Get CPU registers
        print("\n5. Getting CPU registers...")
        registers = client.get_registers()
        if registers:
            print(f"   Registers request sent (ID: {registers.get('id')})")
        
        # Memory scanning example
        print("\n6. Scanning for pattern in memory...")
        scan = client.scan_memory("DEADBEEF")
        if scan:
            print(f"   Memory scan request sent (ID: {scan.get('id')})")
        
        # Disassembly example
        print("\n7. Disassembling instructions...")
        disasm = client.disassemble(0x00100000, 5)
        if disasm:
            print(f"   Disassembly request sent (ID: {disasm.get('id')})")
        
        print("\nNote: This example shows request sending only.")
        print("A complete implementation would handle responses and WebSocket framing.")
        
    finally:
        # Disconnect
        client.disconnect()


def example_memory_analysis():
    """Example of memory analysis workflow"""
    print("=== Memory Analysis Example ===\n")
    
    client = PCSX2MCPClient()
    
    if not client.connect():
        return
    
    try:
        # Search for specific value
        print("Searching for value 42 (0x2A) in memory...")
        client.scan_memory("2A000000")  # 42 as 32-bit little-endian
        
        # Search for text pattern
        print("Searching for 'SONY' string...")
        sony_pattern = "534F4E59"  # "SONY" in hex
        client.scan_memory(sony_pattern)
        
        # Set breakpoint at common entry point
        print("Setting breakpoint at 0x00100000...")
        client.set_breakpoint(0x00100000)
        
        # Monitor register changes
        print("Reading PC register...")
        client.get_registers()
        
    finally:
        client.disconnect()


def example_ai_assisted_analysis():
    """Example of AI-assisted analysis using MCP"""
    print("=== AI-Assisted Analysis Example ===\n")
    
    client = PCSX2MCPClient()
    
    if not client.connect():
        return
    
    try:
        # This is what an AI tool might do:
        
        # 1. Understand available capabilities
        print("AI: Discovering available analysis tools...")
        client.list_tools()
        
        # 2. Get current state
        print("AI: Analyzing current game state...")
        client.get_game_state()
        client.get_performance_metrics()
        
        # 3. Analyze memory layout
        print("AI: Reading memory regions for analysis...")
        # Main memory start
        client.read_memory(0x00000000, 1024)
        # Common entry points
        client.read_memory(0x00100000, 512)
        # Stack area (example)
        client.read_memory(0x01FF0000, 512)
        
        # 4. Set strategic breakpoints
        print("AI: Setting analysis breakpoints...")
        # Common function entry points
        client.set_breakpoint(0x00100000)  # Potential main()
        client.set_breakpoint(0x00100100)  # Potential init()
        
        # 5. Disassemble key areas
        print("AI: Disassembling key code sections...")
        client.disassemble(0x00100000, 20)
        
        print("\nAI analysis requests sent.")
        print("An AI tool would process the responses to provide insights.")
        
    finally:
        client.disconnect()


def main():
    """Main function with example selection"""
    if len(sys.argv) > 1:
        example_type = sys.argv[1].lower()
    else:
        print("Usage: python3 mcp_client_example.py [basic|memory|ai]")
        print("Examples:")
        print("  basic  - Basic MCP usage demonstration")
        print("  memory - Memory analysis workflow")
        print("  ai     - AI-assisted analysis example")
        print("\nRunning basic example by default...\n")
        example_type = "basic"
    
    if example_type == "basic":
        example_basic_usage()
    elif example_type == "memory":
        example_memory_analysis()
    elif example_type == "ai":
        example_ai_assisted_analysis()
    else:
        print(f"Unknown example type: {example_type}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())