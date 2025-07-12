// SPDX-FileCopyrightText: 2002-2025 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "PrecompiledHeader.h"
#include "MemoryInterface.h"
#include "Memory.h"
#include "vtlb.h"
#include "Console.h"
#include <cstring>
#include <algorithm>

namespace AnalysisFramework
{
	bool MemoryInterface::SafeMemoryAccess(u32 address, size_t size, bool write) const
	{
		// Check if address is within valid PS2 memory ranges
		if (address >= 0x20000000) // Beyond main memory range
			return false;

		// Check for address alignment issues
		if (size > 1 && (address & (size - 1)) != 0)
			return false; // Misaligned access

		// Additional safety checks could be added here
		return true;
	}

	bool MemoryInterface::ReadMemory(u32 address, void* buffer, size_t size)
	{
		if (!buffer || size == 0)
			return false;

		if (!SafeMemoryAccess(address, size, false))
			return false;

		try
		{
			u8* dest = static_cast<u8*>(buffer);
			for (size_t i = 0; i < size; ++i)
			{
				dest[i] = ReadMemory8(address + i);
			}
			return true;
		}
		catch (...)
		{
			Console.Error("(AnalysisFramework) Memory read exception at address 0x%08X", address);
			return false;
		}
	}

	u8 MemoryInterface::ReadMemory8(u32 address)
	{
		if (!SafeMemoryAccess(address, 1, false))
			return 0;

		try
		{
			return memRead8(address);
		}
		catch (...)
		{
			Console.Error("(AnalysisFramework) Memory read8 exception at address 0x%08X", address);
			return 0;
		}
	}

	u16 MemoryInterface::ReadMemory16(u32 address)
	{
		if (!SafeMemoryAccess(address, 2, false))
			return 0;

		try
		{
			return memRead16(address);
		}
		catch (...)
		{
			Console.Error("(AnalysisFramework) Memory read16 exception at address 0x%08X", address);
			return 0;
		}
	}

	u32 MemoryInterface::ReadMemory32(u32 address)
	{
		if (!SafeMemoryAccess(address, 4, false))
			return 0;

		try
		{
			return memRead32(address);
		}
		catch (...)
		{
			Console.Error("(AnalysisFramework) Memory read32 exception at address 0x%08X", address);
			return 0;
		}
	}

	u64 MemoryInterface::ReadMemory64(u32 address)
	{
		if (!SafeMemoryAccess(address, 8, false))
			return 0;

		try
		{
			u64 low = memRead32(address);
			u64 high = memRead32(address + 4);
			return low | (high << 32);
		}
		catch (...)
		{
			Console.Error("(AnalysisFramework) Memory read64 exception at address 0x%08X", address);
			return 0;
		}
	}

	bool MemoryInterface::WriteMemory(u32 address, const void* buffer, size_t size)
	{
		if (!buffer || size == 0)
			return false;

		if (!SafeMemoryAccess(address, size, true))
			return false;

		try
		{
			const u8* src = static_cast<const u8*>(buffer);
			for (size_t i = 0; i < size; ++i)
			{
				if (!WriteMemory8(address + i, src[i]))
					return false;
			}
			return true;
		}
		catch (...)
		{
			Console.Error("(AnalysisFramework) Memory write exception at address 0x%08X", address);
			return false;
		}
	}

	bool MemoryInterface::WriteMemory8(u32 address, u8 value)
	{
		if (!SafeMemoryAccess(address, 1, true))
			return false;

		try
		{
			memWrite8(address, value);
			return true;
		}
		catch (...)
		{
			Console.Error("(AnalysisFramework) Memory write8 exception at address 0x%08X", address);
			return false;
		}
	}

	bool MemoryInterface::WriteMemory16(u32 address, u16 value)
	{
		if (!SafeMemoryAccess(address, 2, true))
			return false;

		try
		{
			memWrite16(address, value);
			return true;
		}
		catch (...)
		{
			Console.Error("(AnalysisFramework) Memory write16 exception at address 0x%08X", address);
			return false;
		}
	}

	bool MemoryInterface::WriteMemory32(u32 address, u32 value)
	{
		if (!SafeMemoryAccess(address, 4, true))
			return false;

		try
		{
			memWrite32(address, value);
			return true;
		}
		catch (...)
		{
			Console.Error("(AnalysisFramework) Memory write32 exception at address 0x%08X", address);
			return false;
		}
	}

	bool MemoryInterface::WriteMemory64(u32 address, u64 value)
	{
		if (!SafeMemoryAccess(address, 8, true))
			return false;

		try
		{
			memWrite32(address, static_cast<u32>(value));
			memWrite32(address + 4, static_cast<u32>(value >> 32));
			return true;
		}
		catch (...)
		{
			Console.Error("(AnalysisFramework) Memory write64 exception at address 0x%08X", address);
			return false;
		}
	}

	bool MemoryInterface::IsValidAddress(u32 address)
	{
		// Check if address is in valid PS2 memory range
		if (address >= 0x20000000)
			return false;

		try
		{
			// Try to read a byte to test validity
			memRead8(address);
			return true;
		}
		catch (...)
		{
			return false;
		}
	}

	bool MemoryInterface::IsWritableAddress(u32 address)
	{
		// Most PS2 memory addresses are writable except ROM areas
		if (address >= 0x1FC00000 && address < 0x20000000) // BIOS ROM
			return false;

		return IsValidAddress(address);
	}

	bool MemoryInterface::MatchesPattern(const u8* memory, const std::vector<u8>& pattern, 
										 const std::vector<bool>& mask) const
	{
		for (size_t i = 0; i < pattern.size(); ++i)
		{
			// If mask is provided and this byte should be ignored, skip it
			if (!mask.empty() && i < mask.size() && !mask[i])
				continue;

			if (memory[i] != pattern[i])
				return false;
		}
		return true;
	}

	std::vector<u32> MemoryInterface::ScanPattern(const std::vector<u8>& pattern, 
												  const std::vector<bool>& mask)
	{
		std::vector<u32> results;

		if (pattern.empty())
			return results;

		// Scan main PS2 memory (32MB)
		const u32 memoryStart = 0x00000000;
		const u32 memoryEnd = 0x02000000;
		const size_t patternSize = pattern.size();

		for (u32 address = memoryStart; address <= memoryEnd - patternSize; ++address)
		{
			if (!IsValidAddress(address))
				continue;

			// Read memory for pattern matching
			std::vector<u8> memoryData(patternSize);
			if (ReadMemory(address, memoryData.data(), patternSize))
			{
				if (MatchesPattern(memoryData.data(), pattern, mask))
				{
					results.push_back(address);
				}
			}
		}

		return results;
	}

	std::vector<u32> MemoryInterface::ScanValue(const void* value, size_t valueSize)
	{
		if (!value || valueSize == 0)
			return {};

		// Convert value to pattern
		const u8* valueBytes = static_cast<const u8*>(value);
		std::vector<u8> pattern(valueBytes, valueBytes + valueSize);

		return ScanPattern(pattern);
	}

} // namespace AnalysisFramework