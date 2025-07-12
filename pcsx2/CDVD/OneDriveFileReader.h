// SPDX-FileCopyrightText: 2002-2025 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include "CDVD/ThreadedFileReader.h"
#include "OneDriveAPI.h"

#include <unordered_map>

class Error;

/// ThreadedFileReader implementation for OneDrive streaming
class OneDriveFileReader final : public ThreadedFileReader
{
	DeclareNoncopyableObject(OneDriveFileReader);

public:
	OneDriveFileReader();
	~OneDriveFileReader() override;

	bool Open2(std::string filename, Error* error) override;
	bool Precache2(ProgressCallback* progress, Error* error) override;
	void Close2() override;

	Chunk ChunkForOffset(u64 offset) override;
	int ReadChunk(void* dst, s64 chunkID) override;

	u32 GetBlockCount() const override;

	/// Configure OneDrive API settings
	static void SetOneDriveConfig(const OneDriveConfig& config);
	static const OneDriveConfig& GetOneDriveConfig();

private:
	struct CacheEntry
	{
		std::unique_ptr<u8[]> data;
		u64 offset = 0;
		u32 size = 0;
		bool valid = false;
	};

	std::unique_ptr<OneDriveAPI> m_api;
	OneDriveAPI::FileInfo m_file_info;
	
	// Cache for downloaded chunks
	std::unordered_map<s64, CacheEntry> m_cache;
	u32 m_max_cache_entries = 0;
	u32 m_chunk_size = 1024 * 1024; // 1MB chunks
	
	static OneDriveConfig s_config;

	bool InitializeAPI(Error* error);
	bool DownloadChunk(s64 chunkID, void* dst, Error* error);
	void EvictOldestCacheEntry();
	std::string GetCacheKey(s64 chunkID) const;
};