"""
PCSX2 Analysis Framework - IDA Pro Plugin Example

This IDA Pro plugin demonstrates integration with PCSX2's Analysis Framework.
It provides functionality to import/export analysis data between IDA Pro and PCSX2.

Installation:
1. Copy this file to your IDA Pro plugins directory
2. Restart IDA Pro
3. The plugin will appear in the Edit > Plugins menu

Requirements:
- IDA Pro 7.0+
- PCSX2 with Analysis Framework running
- Python 3.x support in IDA Pro
"""

import ida_auto
import ida_bytes
import ida_entry
import ida_funcs
import ida_kernwin
import ida_loader
import ida_name
import ida_netnode
import ida_nalt
import ida_segment
import idaapi
import idautils
import idc

import json
import socket
import threading
import time
from typing import Dict, List, Optional, Tuple


class PCSX2AnalysisPlugin(idaapi.plugin_t):
    """Main plugin class for PCSX2 Analysis Framework integration"""
    
    flags = idaapi.PLUGIN_UNL
    comment = "PCSX2 Analysis Framework Integration"
    help = "Import/export analysis data with PCSX2"
    wanted_name = "PCSX2 Analysis Framework"
    wanted_hotkey = "Ctrl-Alt-P"

    def init(self):
        """Initialize the plugin"""
        print("PCSX2 Analysis Framework plugin loaded")
        
        # Add menu items
        self.add_menu_items()
        
        # Initialize connection state
        self.pcsx2_connected = False
        self.pcsx2_socket = None
        
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """Main plugin entry point"""
        self.show_main_dialog()

    def term(self):
        """Plugin termination"""
        if self.pcsx2_socket:
            self.pcsx2_socket.close()
        print("PCSX2 Analysis Framework plugin unloaded")

    def add_menu_items(self):
        """Add plugin menu items"""
        # Add to Edit menu
        idaapi.add_menu_item("Edit/", "PCSX2: Connect to Emulator", "", 0, 
                            self.connect_to_pcsx2, ())
        idaapi.add_menu_item("Edit/", "PCSX2: Import Analysis", "", 0, 
                            self.import_from_pcsx2, ())
        idaapi.add_menu_item("Edit/", "PCSX2: Export Analysis", "", 0, 
                            self.export_to_pcsx2, ())
        idaapi.add_menu_item("Edit/", "PCSX2: Sync Breakpoints", "", 0, 
                            self.sync_breakpoints, ())

    def show_main_dialog(self):
        """Show main plugin dialog"""
        form = """PCSX2 Analysis Framework

        Connect to PCSX2 emulator and synchronize analysis data.

        <#Connect to PCSX2 running with Analysis Framework#Connect:B:1:20::>
        <#Import symbols and functions from PCSX2#Import Analysis:B:1:20::>
        <#Export current IDA analysis to PCSX2#Export Analysis:B:1:20::>
        <#Synchronize breakpoints between IDA and PCSX2#Sync Breakpoints:B:1:20::>

        """

        compiled_form = ida_kernwin.compile_idc_text(form)
        if compiled_form:
            result = ida_kernwin.ask_form(compiled_form, 
                                        self.connect_to_pcsx2,
                                        self.import_from_pcsx2,
                                        self.export_to_pcsx2,
                                        self.sync_breakpoints)

    def connect_to_pcsx2(self):
        """Connect to PCSX2 MCP server"""
        host = ida_kernwin.ask_str("localhost", 0, "PCSX2 Host:")
        if not host:
            return

        port = ida_kernwin.ask_long(28011, "PCSX2 Port:")
        if not port:
            return

        try:
            self.pcsx2_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.pcsx2_socket.connect((host, port))
            self.pcsx2_connected = True
            
            ida_kernwin.info(f"Connected to PCSX2 at {host}:{port}")
            print(f"PCSX2: Connected to {host}:{port}")
            
        except Exception as e:
            ida_kernwin.warning(f"Failed to connect to PCSX2: {str(e)}")
            self.pcsx2_connected = False

    def send_mcp_request(self, method: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """Send MCP request to PCSX2"""
        if not self.pcsx2_connected or not self.pcsx2_socket:
            ida_kernwin.warning("Not connected to PCSX2")
            return None

        request = {
            "jsonrpc": "2.0",
            "method": method,
            "id": int(time.time())
        }
        
        if params:
            request["params"] = params

        try:
            request_data = json.dumps(request) + "\n"
            self.pcsx2_socket.send(request_data.encode('utf-8'))
            
            # Note: Simplified response handling
            # Real implementation would need proper JSON-RPC framing
            return {"status": "sent"}
            
        except Exception as e:
            ida_kernwin.warning(f"Failed to send request: {str(e)}")
            return None

    def import_from_pcsx2(self):
        """Import analysis data from PCSX2"""
        if not self.pcsx2_connected:
            ida_kernwin.warning("Not connected to PCSX2. Please connect first.")
            return

        print("PCSX2: Importing analysis data...")
        
        # Request symbols from PCSX2
        response = self.send_mcp_request("tools/call", {
            "name": "get_symbols",
            "arguments": {}
        })
        
        if response:
            ida_kernwin.info("Symbol import request sent to PCSX2")
            # In real implementation, we would process the response
            self.apply_imported_symbols()

    def apply_imported_symbols(self):
        """Apply imported symbols to IDA database"""
        # Example symbols - in real implementation, these would come from PCSX2
        example_symbols = [
            {"address": 0x00100000, "name": "main_function", "type": "function"},
            {"address": 0x00100100, "name": "init_system", "type": "function"},
            {"address": 0x00100200, "name": "game_loop", "type": "function"},
            {"address": 0x00200000, "name": "player_data", "type": "data"},
        ]

        applied_count = 0
        
        for symbol in example_symbols:
            address = symbol["address"]
            name = symbol["name"]
            symbol_type = symbol["type"]
            
            # Check if address exists in current database
            if not ida_bytes.is_loaded(address):
                continue
                
            # Apply name
            if ida_name.set_name(address, name):
                print(f"PCSX2: Applied symbol {name} at 0x{address:08X}")
                applied_count += 1
                
                # If it's a function, create function
                if symbol_type == "function":
                    if ida_funcs.add_func(address):
                        print(f"PCSX2: Created function {name}")
        
        ida_kernwin.info(f"Applied {applied_count} symbols from PCSX2")
        
        # Auto-analyze to propagate changes
        ida_auto.auto_wait()

    def export_to_pcsx2(self):
        """Export current IDA analysis to PCSX2"""
        if not self.pcsx2_connected:
            ida_kernwin.warning("Not connected to PCSX2. Please connect first.")
            return

        print("PCSX2: Exporting analysis data...")

        # Collect functions
        functions = []
        for func_addr in idautils.Functions():
            func_name = ida_funcs.get_func_name(func_addr)
            func_end = ida_funcs.get_func(func_addr).end_ea
            
            functions.append({
                "address": func_addr,
                "name": func_name,
                "end_address": func_end,
                "type": "function"
            })

        # Collect named locations
        names = []
        for addr, name in idautils.Names():
            if not ida_funcs.get_func(addr):  # Skip functions (already exported)
                names.append({
                    "address": addr,
                    "name": name,
                    "type": "data"
                })

        # Send to PCSX2
        export_data = {
            "functions": functions,
            "symbols": names
        }

        response = self.send_mcp_request("tools/call", {
            "name": "import_symbols",
            "arguments": export_data
        })

        if response:
            ida_kernwin.info(f"Exported {len(functions)} functions and {len(names)} symbols to PCSX2")

    def sync_breakpoints(self):
        """Synchronize breakpoints between IDA and PCSX2"""
        if not self.pcsx2_connected:
            ida_kernwin.warning("Not connected to PCSX2. Please connect first.")
            return

        print("PCSX2: Synchronizing breakpoints...")

        # Get IDA breakpoints
        ida_breakpoints = []
        for i in range(ida_idd.get_bpt_qty()):
            bpt = ida_idd.bpt_t()
            if ida_idd.getn_bpt(i, bpt):
                ida_breakpoints.append(bpt.ea)

        # Send to PCSX2
        for addr in ida_breakpoints:
            response = self.send_mcp_request("tools/call", {
                "name": "set_breakpoint",
                "arguments": {"address": f"0x{addr:08X}"}
            })

        # Request PCSX2 breakpoints
        response = self.send_mcp_request("tools/call", {
            "name": "get_breakpoints",
            "arguments": {}
        })

        if response:
            ida_kernwin.info(f"Synchronized {len(ida_breakpoints)} breakpoints with PCSX2")


class PCSX2AnalysisView(idaapi.simplecustviewer_t):
    """Custom view for PCSX2 analysis data"""
    
    def __init__(self):
        idaapi.simplecustviewer_t.__init__(self)
        self.plugin = None

    def Create(self, plugin):
        """Create the view"""
        self.plugin = plugin
        
        if not idaapi.simplecustviewer_t.Create(self, "PCSX2 Analysis"):
            return False

        # Add some example content
        self.AddLine("PCSX2 Analysis Framework Integration")
        self.AddLine("=====================================")
        self.AddLine("")
        self.AddLine("Status: " + ("Connected" if plugin.pcsx2_connected else "Disconnected"))
        self.AddLine("")
        self.AddLine("Available Actions:")
        self.AddLine("- Connect to PCSX2")
        self.AddLine("- Import analysis data")
        self.AddLine("- Export analysis data") 
        self.AddLine("- Sync breakpoints")
        
        return True

    def OnDblClick(self, shift):
        """Handle double-click events"""
        line = self.GetCurrentLine()
        if "Connect" in line:
            self.plugin.connect_to_pcsx2()
        elif "Import" in line:
            self.plugin.import_from_pcsx2()
        elif "Export" in line:
            self.plugin.export_to_pcsx2()
        elif "Sync" in line:
            self.plugin.sync_breakpoints()
        
        return True


def PLUGIN_ENTRY():
    """Plugin entry point"""
    return PCSX2AnalysisPlugin()


# Utility functions for PCSX2-specific analysis

def analyze_ps2_elf():
    """Analyze PS2 ELF file structure"""
    print("Analyzing PS2 ELF structure...")
    
    # Check if this is a PS2 ELF
    entry_point = ida_nalt.get_entry(0)
    if entry_point:
        print(f"Entry point: 0x{entry_point:08X}")
        
        # Common PS2 entry points
        if entry_point == 0x00100000:
            ida_name.set_name(entry_point, "ps2_main")
            ida_funcs.add_func(entry_point)
        
        # Look for common PS2 system calls
        analyze_ps2_syscalls()

def analyze_ps2_syscalls():
    """Identify PS2 system call patterns"""
    print("Analyzing PS2 system calls...")
    
    # PS2 uses specific syscall instructions
    # Look for 'syscall' instructions (0x0000000C)
    for addr in idautils.Heads():
        if ida_bytes.get_dword(addr) == 0x0000000C:
            # Check the preceding instruction for syscall number
            prev_addr = ida_bytes.prev_head(addr)
            if prev_addr != ida_idaapi.BADADDR:
                prev_insn = ida_bytes.get_dword(prev_addr)
                # If it's an immediate load to $v1 (syscall number register)
                if (prev_insn & 0xFFE00000) == 0x24600000:  # addiu $v1, $zero, imm
                    syscall_num = prev_insn & 0xFFFF
                    syscall_name = f"syscall_{syscall_num:02X}"
                    ida_name.set_name(addr, syscall_name)
                    print(f"Found syscall {syscall_num} at 0x{addr:08X}")

def setup_ps2_memory_map():
    """Set up PS2-specific memory segments and names"""
    print("Setting up PS2 memory map...")
    
    # Define PS2 memory regions
    ps2_regions = [
        (0x00000000, 0x02000000, "Main_Memory", "RAM"),
        (0x70000000, 0x70004000, "Scratchpad", "RAM"),
        (0x1FC00000, 0x20000000, "BIOS_ROM", "ROM"),
        (0x10000000, 0x1FC00000, "IO_Registers", "RAM")
    ]
    
    for start, end, name, type_name in ps2_regions:
        # Add segment if it doesn't exist
        seg = ida_segment.get_segm_by_name(name)
        if not seg:
            seg = ida_segment.segment_t()
            seg.start_ea = start
            seg.end_ea = end
            seg.bitness = 1  # 32-bit
            ida_segment.add_segm_ex(seg, name, type_name, ida_segment.ADDSEG_SPARSE)
            print(f"Added PS2 segment: {name} (0x{start:08X}-0x{end:08X})")

if __name__ == "__main__":
    # For testing outside of IDA Pro
    print("PCSX2 Analysis Framework - IDA Pro Plugin")
    print("This script should be run from within IDA Pro")