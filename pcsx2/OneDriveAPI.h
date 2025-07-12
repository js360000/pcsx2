// SPDX-FileCopyrightText: 2002-2025 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#pragma once

#include "common/Pcsx2Defs.h"

#include <string>
#include <memory>
#include <functional>
#include <vector>

class Error;

/// OneDrive API client for streaming file access
/// Supports both personal OneDrive and OneDrive for Business
class OneDriveAPI
{
public:
	struct FileInfo
	{
		std::string id;
		std::string name;
		std::string download_url;
		u64 size = 0;
		std::string etag;
	};

	struct AuthInfo
	{
		std::string access_token;
		std::string refresh_token;
		std::string client_id;
		std::string client_secret;
		bool is_authenticated = false;
	};

	OneDriveAPI();
	~OneDriveAPI();

	/// Initialize the API client with authentication
	bool Initialize(const AuthInfo& auth_info, Error* error);

	/// Get file information from OneDrive URL or file ID
	bool GetFileInfo(const std::string& url_or_id, FileInfo& file_info, Error* error);

	/// Download a range of bytes from a OneDrive file
	/// Returns the number of bytes actually read
	size_t DownloadRange(const std::string& file_id, u64 offset, u64 size, void* buffer, Error* error);

	/// Check if the API client is properly authenticated
	bool IsAuthenticated() const { return m_auth_info.is_authenticated; }

	/// Get minimum bandwidth requirement warning text
	static std::string GetBandwidthRequirements();

	/// Parse OneDrive URL to extract file ID
	static bool ParseOneDriveURL(const std::string& url, std::string& file_id, Error* error);

	/// Validate if URL is a supported OneDrive URL
	static bool IsOneDriveURL(const std::string& url);

private:
	struct Impl;
	std::unique_ptr<Impl> m_impl;
	AuthInfo m_auth_info;

	bool RefreshAccessToken(Error* error);
	std::string BuildGraphAPIURL(const std::string& endpoint) const;
};

/// Configuration for OneDrive settings
struct OneDriveConfig
{
	bool enabled = false;
	std::string client_id;
	std::string client_secret;
	std::string access_token;
	std::string refresh_token;
	u32 cache_size_mb = 64; // Size of local cache in MB
	u32 prefetch_size_mb = 8; // Amount to prefetch ahead in MB
};