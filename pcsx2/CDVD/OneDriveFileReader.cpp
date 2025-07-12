// SPDX-FileCopyrightText: 2002-2025 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "PrecompiledHeader.h"

#include "OneDriveFileReader.h"
#include "common/Error.h"
#include "common/Console.h"
#include "common/StringUtil.h"
#include "Host.h"

OneDriveConfig OneDriveFileReader::s_config;

OneDriveFileReader::OneDriveFileReader()
{
	// Load configuration from settings
	OneDriveConfig config;
	config.enabled = Host::GetBaseBoolSettingValue("OneDrive", "Enabled", false);
	config.client_id = Host::GetBaseStringSettingValue("OneDrive", "ClientID", "");
	config.client_secret = Host::GetBaseStringSettingValue("OneDrive", "ClientSecret", "");
	config.access_token = Host::GetBaseStringSettingValue("OneDrive", "AccessToken", "");
	config.refresh_token = Host::GetBaseStringSettingValue("OneDrive", "RefreshToken", "");
	config.cache_size_mb = Host::GetBaseUIntSettingValue("OneDrive", "CacheSizeMB", 64);
	config.prefetch_size_mb = Host::GetBaseUIntSettingValue("OneDrive", "PrefetchSizeMB", 8);
	
	SetOneDriveConfig(config);

	// Calculate cache size based on configuration
	m_max_cache_entries = (s_config.cache_size_mb * 1024 * 1024) / m_chunk_size;
	if (m_max_cache_entries == 0)
		m_max_cache_entries = 64; // Minimum 64 chunks
}

OneDriveFileReader::~OneDriveFileReader()
{
	Close2();
}

bool OneDriveFileReader::Open2(std::string filename, Error* error)
{
	if (!OneDriveAPI::IsOneDriveURL(filename))
	{
		Error::SetStringView(error, "Not a valid OneDrive URL");
		return false;
	}

	if (!s_config.enabled)
	{
		Error::SetStringView(error, "OneDrive streaming is disabled in settings");
		return false;
	}

	m_filename = std::move(filename);
	
	if (!InitializeAPI(error))
		return false;

	// Get file information
	if (!m_api->GetFileInfo(m_filename, m_file_info, error))
		return false;

	if (m_file_info.size == 0)
	{
		Error::SetStringView(error, "File size is zero or unknown");
		return false;
	}

	// Check file extension to ensure it's an ISO
	const std::string& name = m_file_info.name;
	const bool is_iso = StringUtil::EndsWith(name, ".iso") || 
		               StringUtil::EndsWith(name, ".ISO") ||
		               StringUtil::EndsWith(name, ".bin") ||
		               StringUtil::EndsWith(name, ".BIN");
	
	if (!is_iso)
	{
		Console.Warning("OneDriveFileReader: File '{}' may not be a valid disc image", name);
	}

	Console.WriteLn("OneDriveFileReader: Opened '{}' ({} bytes)", m_file_info.name, m_file_info.size);
	Console.WriteLn("OneDriveFileReader: {}", OneDriveAPI::GetBandwidthRequirements());

	return true;
}

bool OneDriveFileReader::Precache2(ProgressCallback* progress, Error* error)
{
	// For OneDrive streaming, we don't precache the entire file
	// Instead, we might prefetch the first few chunks
	const u32 prefetch_size = s_config.prefetch_size_mb * 1024 * 1024;
	const u32 chunks_to_prefetch = (prefetch_size + m_chunk_size - 1) / m_chunk_size;

	if (progress)
		progress->SetStatusText("Prefetching OneDrive content...");

	for (u32 i = 0; i < chunks_to_prefetch && i < GetBlockCount(); ++i)
	{
		if (progress && progress->IsCancelled())
			return false;

		// Download chunk to cache
		CacheEntry& entry = m_cache[i];
		entry.data = std::make_unique<u8[]>(m_chunk_size);
		entry.offset = static_cast<u64>(i) * m_chunk_size;
		entry.size = m_chunk_size;

		Error chunk_error;
		const size_t bytes_read = m_api->DownloadRange(m_file_info.id, entry.offset, entry.size, entry.data.get(), &chunk_error);
		
		if (bytes_read > 0)
		{
			entry.size = static_cast<u32>(bytes_read);
			entry.valid = true;
		}
		else
		{
			Console.Warning("OneDriveFileReader: Failed to prefetch chunk {}: {}", i, chunk_error.GetDescription());
		}

		if (progress)
			progress->SetProgressValue(i, chunks_to_prefetch);
	}

	return true;
}

void OneDriveFileReader::Close2()
{
	m_cache.clear();
	m_api.reset();
	m_file_info = {};
}

ThreadedFileReader::Chunk OneDriveFileReader::ChunkForOffset(u64 offset)
{
	Chunk chunk;
	chunk.chunkID = static_cast<s64>(offset / m_chunk_size);
	chunk.offset = static_cast<u64>(chunk.chunkID) * m_chunk_size;
	chunk.length = m_chunk_size;

	// Adjust length for the last chunk
	if (chunk.offset + chunk.length > m_file_info.size)
	{
		chunk.length = static_cast<u32>(m_file_info.size - chunk.offset);
	}

	return chunk;
}

int OneDriveFileReader::ReadChunk(void* dst, s64 chunkID)
{
	// Check if chunk is in cache
	auto it = m_cache.find(chunkID);
	if (it != m_cache.end() && it->second.valid)
	{
		std::memcpy(dst, it->second.data.get(), it->second.size);
		return it->second.size;
	}

	// Download chunk
	Error error;
	if (!DownloadChunk(chunkID, dst, &error))
	{
		Console.Error("OneDriveFileReader: Failed to download chunk {}: {}", chunkID, error.GetDescription());
		return -1;
	}

	return m_chunk_size;
}

u32 OneDriveFileReader::GetBlockCount() const
{
	return static_cast<u32>((m_file_info.size + m_blocksize - 1) / m_blocksize);
}

void OneDriveFileReader::SetOneDriveConfig(const OneDriveConfig& config)
{
	s_config = config;
}

const OneDriveConfig& OneDriveFileReader::GetOneDriveConfig()
{
	return s_config;
}

bool OneDriveFileReader::InitializeAPI(Error* error)
{
	m_api = std::make_unique<OneDriveAPI>();
	
	OneDriveAPI::AuthInfo auth_info;
	auth_info.access_token = s_config.access_token;
	auth_info.refresh_token = s_config.refresh_token;
	auth_info.client_id = s_config.client_id;
	auth_info.client_secret = s_config.client_secret;

	return m_api->Initialize(auth_info, error);
}

bool OneDriveFileReader::DownloadChunk(s64 chunkID, void* dst, Error* error)
{
	const u64 offset = static_cast<u64>(chunkID) * m_chunk_size;
	u32 size = m_chunk_size;

	// Adjust size for the last chunk
	if (offset + size > m_file_info.size)
	{
		size = static_cast<u32>(m_file_info.size - offset);
	}

	const size_t bytes_read = m_api->DownloadRange(m_file_info.id, offset, size, dst, error);
	
	if (bytes_read == 0)
		return false;

	// Cache the downloaded chunk
	if (m_cache.size() >= m_max_cache_entries)
	{
		EvictOldestCacheEntry();
	}

	CacheEntry& entry = m_cache[chunkID];
	entry.data = std::make_unique<u8[]>(m_chunk_size);
	entry.offset = offset;
	entry.size = static_cast<u32>(bytes_read);
	entry.valid = true;
	std::memcpy(entry.data.get(), dst, bytes_read);

	return bytes_read == size;
}

void OneDriveFileReader::EvictOldestCacheEntry()
{
	if (m_cache.empty())
		return;

	// Simple LRU: remove the first entry
	// In a more sophisticated implementation, we could track access times
	auto it = m_cache.begin();
	m_cache.erase(it);
}

std::string OneDriveFileReader::GetCacheKey(s64 chunkID) const
{
	return fmt::format("{}_{}", m_file_info.id, chunkID);
}