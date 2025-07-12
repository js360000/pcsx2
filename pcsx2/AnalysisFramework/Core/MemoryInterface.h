// SPDX-FileCopyrightText: 2002-2025 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include "AnalysisFramework.h"
#include "Memory.h"

namespace AnalysisFramework
{
	/// Implementation of IMemoryInterface that integrates with PCSX2's memory system
	class MemoryInterface : public IMemoryInterface
	{
	public:
		MemoryInterface() = default;
		virtual ~MemoryInterface() = default;

		/// Memory reading implementations
		bool ReadMemory(u32 address, void* buffer, size_t size) override;
		u8 ReadMemory8(u32 address) override;
		u16 ReadMemory16(u32 address) override;
		u32 ReadMemory32(u32 address) override;
		u64 ReadMemory64(u32 address) override;

		/// Memory writing implementations
		bool WriteMemory(u32 address, const void* buffer, size_t size) override;
		bool WriteMemory8(u32 address, u8 value) override;
		bool WriteMemory16(u32 address, u16 value) override;
		bool WriteMemory32(u32 address, u32 value) override;
		bool WriteMemory64(u32 address, u64 value) override;

		/// Memory validation implementations
		bool IsValidAddress(u32 address) override;
		bool IsWritableAddress(u32 address) override;

		/// Memory scanning implementations
		std::vector<u32> ScanPattern(const std::vector<u8>& pattern, 
									 const std::vector<bool>& mask = {}) override;
		std::vector<u32> ScanValue(const void* value, size_t valueSize) override;

	private:
		/// Helper to safely access memory through PCSX2's memory system
		bool SafeMemoryAccess(u32 address, size_t size, bool write = false) const;

		/// Pattern matching helper
		bool MatchesPattern(const u8* memory, const std::vector<u8>& pattern, 
							const std::vector<bool>& mask) const;
	};

} // namespace AnalysisFramework