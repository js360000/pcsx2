// SPDX-FileCopyrightText: 2002-2025 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "PrecompiledHeader.h"
#include "Utilities.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cctype>

namespace AnalysisFramework
{
	namespace StringUtils
	{
		std::string ToLower(const std::string& str)
		{
			std::string result = str;
			std::transform(result.begin(), result.end(), result.begin(), ::tolower);
			return result;
		}

		std::string ToUpper(const std::string& str)
		{
			std::string result = str;
			std::transform(result.begin(), result.end(), result.begin(), ::toupper);
			return result;
		}

		std::vector<std::string> Split(const std::string& str, char delimiter)
		{
			std::vector<std::string> parts;
			std::stringstream ss(str);
			std::string part;
			
			while (std::getline(ss, part, delimiter))
			{
				parts.push_back(part);
			}
			
			return parts;
		}

		std::string Join(const std::vector<std::string>& parts, const std::string& separator)
		{
			if (parts.empty())
				return "";
			
			std::stringstream ss;
			ss << parts[0];
			
			for (size_t i = 1; i < parts.size(); ++i)
			{
				ss << separator << parts[i];
			}
			
			return ss.str();
		}

		bool StartsWith(const std::string& str, const std::string& prefix)
		{
			return str.length() >= prefix.length() && 
				   str.substr(0, prefix.length()) == prefix;
		}

		bool EndsWith(const std::string& str, const std::string& suffix)
		{
			return str.length() >= suffix.length() && 
				   str.substr(str.length() - suffix.length()) == suffix;
		}
	}

	namespace HexUtils
	{
		std::string ToHex(u32 value, bool prefix)
		{
			std::stringstream ss;
			if (prefix) ss << "0x";
			ss << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << value;
			return ss.str();
		}

		std::string ToHex(u64 value, bool prefix)
		{
			std::stringstream ss;
			if (prefix) ss << "0x";
			ss << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << value;
			return ss.str();
		}

		std::string ToHex(const void* data, size_t size, bool prefix)
		{
			const u8* bytes = static_cast<const u8*>(data);
			std::stringstream ss;
			
			if (prefix) ss << "0x";
			
			for (size_t i = 0; i < size; ++i)
			{
				ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) 
				   << static_cast<int>(bytes[i]);
			}
			
			return ss.str();
		}

		bool FromHex(const std::string& hex, u32& value)
		{
			try
			{
				std::string hexStr = hex;
				if (StringUtils::StartsWith(hexStr, "0x") || StringUtils::StartsWith(hexStr, "0X"))
					hexStr = hexStr.substr(2);
				
				value = static_cast<u32>(std::stoul(hexStr, nullptr, 16));
				return true;
			}
			catch (...)
			{
				return false;
			}
		}

		bool FromHex(const std::string& hex, u64& value)
		{
			try
			{
				std::string hexStr = hex;
				if (StringUtils::StartsWith(hexStr, "0x") || StringUtils::StartsWith(hexStr, "0X"))
					hexStr = hexStr.substr(2);
				
				value = std::stoull(hexStr, nullptr, 16);
				return true;
			}
			catch (...)
			{
				return false;
			}
		}

		std::vector<u8> FromHexString(const std::string& hex)
		{
			std::vector<u8> result;
			std::string hexStr = hex;
			
			// Remove 0x prefix if present
			if (StringUtils::StartsWith(hexStr, "0x") || StringUtils::StartsWith(hexStr, "0X"))
				hexStr = hexStr.substr(2);
			
			// Ensure even number of characters
			if (hexStr.length() % 2 != 0)
				hexStr = "0" + hexStr;
			
			for (size_t i = 0; i < hexStr.length(); i += 2)
			{
				try
				{
					u8 byte = static_cast<u8>(std::stoul(hexStr.substr(i, 2), nullptr, 16));
					result.push_back(byte);
				}
				catch (...)
				{
					// Invalid hex digit, return empty vector
					return {};
				}
			}
			
			return result;
		}
	}

	namespace AddressUtils
	{
		bool IsValidPS2Address(u32 address)
		{
			// PS2 addresses are typically within 32MB main memory or specific regions
			return address < 0x20000000;
		}

		bool IsMainMemoryAddress(u32 address)
		{
			// Main memory: 0x00000000 - 0x01FFFFFF (32MB)
			return address < 0x02000000;
		}

		bool IsScratchpadAddress(u32 address)
		{
			// Scratchpad: 0x70000000 - 0x70003FFF (16KB)
			return address >= 0x70000000 && address < 0x70004000;
		}

		bool IsIOAddress(u32 address)
		{
			// I/O registers: 0x10000000 - 0x1FFFFFFF
			return address >= 0x10000000 && address < 0x20000000;
		}

		bool IsROMAddress(u32 address)
		{
			// BIOS ROM: 0x1FC00000 - 0x1FFFFFFF
			return address >= 0x1FC00000 && address < 0x20000000;
		}

		std::string GetAddressRegionName(u32 address)
		{
			if (IsMainMemoryAddress(address))
				return "Main Memory";
			else if (IsScratchpadAddress(address))
				return "Scratchpad";
			else if (IsROMAddress(address))
				return "BIOS ROM";
			else if (IsIOAddress(address))
				return "I/O Registers";
			else
				return "Unknown";
		}
	}

	namespace ValidationUtils
	{
		bool IsValidPattern(const std::vector<u8>& pattern)
		{
			return !pattern.empty() && pattern.size() <= 1024; // Reasonable size limit
		}

		bool IsValidMask(const std::vector<bool>& mask, size_t patternSize)
		{
			return mask.empty() || mask.size() == patternSize;
		}

		bool IsAlignedAddress(u32 address, size_t alignment)
		{
			return alignment > 0 && (address % alignment) == 0;
		}

		bool IsValidMemoryRange(u32 startAddress, u32 endAddress)
		{
			return startAddress <= endAddress && 
				   AddressUtils::IsValidPS2Address(startAddress) &&
				   AddressUtils::IsValidPS2Address(endAddress);
		}
	}

} // namespace AnalysisFramework