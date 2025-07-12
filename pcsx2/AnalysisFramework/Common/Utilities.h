// SPDX-FileCopyrightText: 2002-2025 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include "Common.h"
#include <string>
#include <vector>

namespace AnalysisFramework
{
	/// Common utilities for the analysis framework

	/// String utilities
	namespace StringUtils
	{
		std::string ToLower(const std::string& str);
		std::string ToUpper(const std::string& str);
		std::vector<std::string> Split(const std::string& str, char delimiter);
		std::string Join(const std::vector<std::string>& parts, const std::string& separator);
		bool StartsWith(const std::string& str, const std::string& prefix);
		bool EndsWith(const std::string& str, const std::string& suffix);
	}

	/// Hex utilities
	namespace HexUtils
	{
		std::string ToHex(u32 value, bool prefix = true);
		std::string ToHex(u64 value, bool prefix = true);
		std::string ToHex(const void* data, size_t size, bool prefix = true);
		bool FromHex(const std::string& hex, u32& value);
		bool FromHex(const std::string& hex, u64& value);
		std::vector<u8> FromHexString(const std::string& hex);
	}

	/// Address utilities
	namespace AddressUtils
	{
		bool IsValidPS2Address(u32 address);
		bool IsMainMemoryAddress(u32 address);
		bool IsScratchpadAddress(u32 address);
		bool IsIOAddress(u32 address);
		bool IsROMAddress(u32 address);
		std::string GetAddressRegionName(u32 address);
	}

	/// Data validation utilities
	namespace ValidationUtils
	{
		bool IsValidPattern(const std::vector<u8>& pattern);
		bool IsValidMask(const std::vector<bool>& mask, size_t patternSize);
		bool IsAlignedAddress(u32 address, size_t alignment);
		bool IsValidMemoryRange(u32 startAddress, u32 endAddress);
	}

} // namespace AnalysisFramework