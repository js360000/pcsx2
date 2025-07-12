// SPDX-FileCopyrightText: 2002-2025 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "PrecompiledHeader.h"

#include "OneDriveAPI.h"
#include "common/Error.h"
#include "common/StringUtil.h"
#include "common/Console.h"

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#include <wininet.h>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wininet.lib")
#else
#include <curl/curl.h>
#endif

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>

/// Implementation details for OneDriveAPI
struct OneDriveAPI::Impl
{
#ifdef _WIN32
	HINTERNET session = nullptr;
#else
	CURL* curl = nullptr;
#endif
	std::string response_buffer;

	static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp);
#ifdef _WIN32
	bool MakeHttpRequest(const std::string& url, const std::string& auth_header, std::string& response);
	bool DownloadHttpRange(const std::string& url, u64 offset, u64 size, void* buffer, size_t* bytes_read);
#endif
};

#ifndef _WIN32
size_t OneDriveAPI::Impl::WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
	const size_t total_size = size * nmemb;
	std::string* buffer = static_cast<std::string*>(userp);
	buffer->append(static_cast<char*>(contents), total_size);
	return total_size;
}
#else
size_t OneDriveAPI::Impl::WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
	const size_t total_size = size * nmemb;
	std::string* buffer = static_cast<std::string*>(userp);
	buffer->append(static_cast<char*>(contents), total_size);
	return total_size;
}

bool OneDriveAPI::Impl::MakeHttpRequest(const std::string& url, const std::string& auth_header, std::string& response)
{
	// Parse URL
	URL_COMPONENTSA url_comp = {};
	url_comp.dwStructSize = sizeof(url_comp);
	url_comp.dwHostNameLength = 1;
	url_comp.dwUrlPathLength = 1;
	url_comp.dwSchemeLength = 1;
	
	std::string url_copy = url;
	if (!InternetCrackUrlA(url_copy.c_str(), static_cast<DWORD>(url_copy.length()), 0, &url_comp))
		return false;

	std::string hostname(url_comp.lpszHostName, url_comp.dwHostNameLength);
	std::string path(url_comp.lpszUrlPath, url_comp.dwUrlPathLength);
	
	// Create connection to the specific host
	HINTERNET temp_connection = WinHttpConnect(session, StringUtil::UTF8StringToWideString(hostname).c_str(), 
		url_comp.nPort, 0);
	if (!temp_connection)
		return false;

	HINTERNET request = WinHttpOpenRequest(temp_connection, L"GET", 
		StringUtil::UTF8StringToWideString(path).c_str(), nullptr,
		WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 
		(url_comp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
	
	if (!request)
	{
		WinHttpCloseHandle(temp_connection);
		return false;
	}

	// Add authorization header
	std::wstring auth_header_wide = StringUtil::UTF8StringToWideString(auth_header);
	WinHttpAddRequestHeaders(request, auth_header_wide.c_str(), static_cast<DWORD>(-1), WINHTTP_ADDREQ_FLAG_ADD);

	// Send request
	if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
	{
		WinHttpCloseHandle(request);
		WinHttpCloseHandle(temp_connection);
		return false;
	}

	// Receive response
	if (!WinHttpReceiveResponse(request, nullptr))
	{
		WinHttpCloseHandle(request);
		WinHttpCloseHandle(temp_connection);
		return false;
	}

	// Check status code
	DWORD status_code = 0;
	DWORD size = sizeof(status_code);
	WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
		WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &size, WINHTTP_NO_HEADER_INDEX);

	if (status_code != 200)
	{
		WinHttpCloseHandle(request);
		WinHttpCloseHandle(temp_connection);
		return false;
	}

	// Read response data
	response.clear();
	DWORD bytes_available = 0;
	while (WinHttpQueryDataAvailable(request, &bytes_available) && bytes_available > 0)
	{
		std::vector<char> buffer(bytes_available);
		DWORD bytes_read = 0;
		if (WinHttpReadData(request, buffer.data(), bytes_available, &bytes_read))
		{
			response.append(buffer.data(), bytes_read);
		}
	}

	WinHttpCloseHandle(request);
	WinHttpCloseHandle(temp_connection);
	return true;
}

bool OneDriveAPI::Impl::DownloadHttpRange(const std::string& url, u64 offset, u64 size, void* buffer, size_t* bytes_read)
{
	// Parse URL
	URL_COMPONENTSA url_comp = {};
	url_comp.dwStructSize = sizeof(url_comp);
	url_comp.dwHostNameLength = 1;
	url_comp.dwUrlPathLength = 1;
	url_comp.dwSchemeLength = 1;
	
	std::string url_copy = url;
	if (!InternetCrackUrlA(url_copy.c_str(), static_cast<DWORD>(url_copy.length()), 0, &url_comp))
		return false;

	std::string hostname(url_comp.lpszHostName, url_comp.dwHostNameLength);
	std::string path(url_comp.lpszUrlPath, url_comp.dwUrlPathLength);

	// Create connection to the specific host  
	HINTERNET temp_connection = WinHttpConnect(session, StringUtil::UTF8StringToWideString(hostname).c_str(), 
		url_comp.nPort, 0);
	if (!temp_connection)
		return false;

	HINTERNET request = WinHttpOpenRequest(temp_connection, L"GET", 
		StringUtil::UTF8StringToWideString(path).c_str(), nullptr,
		WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 
		(url_comp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);
	
	if (!request)
	{
		WinHttpCloseHandle(temp_connection);
		return false;
	}

	// Add range header
	std::string range_header = fmt::format("Range: bytes={}-{}", offset, offset + size - 1);
	std::wstring range_header_wide = StringUtil::UTF8StringToWideString(range_header);
	WinHttpAddRequestHeaders(request, range_header_wide.c_str(), static_cast<DWORD>(-1), WINHTTP_ADDREQ_FLAG_ADD);

	// Send request
	if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
	{
		WinHttpCloseHandle(request);
		WinHttpCloseHandle(temp_connection);
		return false;
	}

	// Receive response
	if (!WinHttpReceiveResponse(request, nullptr))
	{
		WinHttpCloseHandle(request);
		WinHttpCloseHandle(temp_connection);
		return false;
	}

	// Read response data directly to buffer
	*bytes_read = 0;
	DWORD bytes_available = 0;
	char* dest = static_cast<char*>(buffer);
	
	while (WinHttpQueryDataAvailable(request, &bytes_available) && bytes_available > 0 && *bytes_read < size)
	{
		DWORD to_read = std::min(bytes_available, static_cast<DWORD>(size - *bytes_read));
		DWORD read_this_time = 0;
		if (WinHttpReadData(request, dest + *bytes_read, to_read, &read_this_time))
		{
			*bytes_read += read_this_time;
		}
		else
		{
			break;
		}
	}

	WinHttpCloseHandle(request);
	WinHttpCloseHandle(temp_connection);
	return *bytes_read > 0;
}
#endif

OneDriveAPI::OneDriveAPI() : m_impl(std::make_unique<Impl>())
{
#ifdef _WIN32
	m_impl->session = WinHttpOpen(L"PCSX2 OneDrive Client/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
#else
	curl_global_init(CURL_GLOBAL_DEFAULT);
	m_impl->curl = curl_easy_init();
#endif
}

OneDriveAPI::~OneDriveAPI()
{
#ifdef _WIN32
	if (m_impl->session)
	{
		WinHttpCloseHandle(m_impl->session);
	}
#else
	if (m_impl->curl)
	{
		curl_easy_cleanup(m_impl->curl);
	}
	curl_global_cleanup();
#endif
}

bool OneDriveAPI::Initialize(const AuthInfo& auth_info, Error* error)
{
	m_auth_info = auth_info;

#ifdef _WIN32
	if (!m_impl->session)
	{
		Error::SetStringView(error, "Failed to initialize WinHTTP for OneDrive API");
		return false;
	}
#else
	if (!m_impl->curl)
	{
		Error::SetStringView(error, "Failed to initialize CURL for OneDrive API");
		return false;
	}
#endif

	if (auth_info.access_token.empty())
	{
		Error::SetStringView(error, "OneDrive access token is required");
		return false;
	}

	m_auth_info.is_authenticated = true;
	return true;
}

bool OneDriveAPI::GetFileInfo(const std::string& url_or_id, FileInfo& file_info, Error* error)
{
	if (!IsAuthenticated())
	{
		Error::SetStringView(error, "OneDrive API not authenticated");
		return false;
	}

	std::string file_id;
	if (IsOneDriveURL(url_or_id))
	{
		if (!ParseOneDriveURL(url_or_id, file_id, error))
			return false;
	}
	else
	{
		file_id = url_or_id;
	}

	const std::string api_url = BuildGraphAPIURL(fmt::format("items/{}", file_id));
	const std::string auth_header = fmt::format("Authorization: Bearer {}", m_auth_info.access_token);
	
	m_impl->response_buffer.clear();

#ifdef _WIN32
	if (!m_impl->MakeHttpRequest(api_url, auth_header, m_impl->response_buffer))
	{
		Error::SetStringView(error, "Failed to make HTTP request to OneDrive API");
		return false;
	}
#else
	curl_easy_setopt(m_impl->curl, CURLOPT_URL, api_url.c_str());
	curl_easy_setopt(m_impl->curl, CURLOPT_WRITEFUNCTION, Impl::WriteCallback);
	curl_easy_setopt(m_impl->curl, CURLOPT_WRITEDATA, &m_impl->response_buffer);
	curl_easy_setopt(m_impl->curl, CURLOPT_FOLLOWLOCATION, 1L);
	
	struct curl_slist* headers = nullptr;
	headers = curl_slist_append(headers, auth_header.c_str());
	curl_easy_setopt(m_impl->curl, CURLOPT_HTTPHEADER, headers);

	const CURLcode res = curl_easy_perform(m_impl->curl);
	curl_slist_free_all(headers);

	if (res != CURLE_OK)
	{
		Error::SetStringFmt(error, "CURL error: {}", curl_easy_strerror(res));
		return false;
	}

	long response_code;
	curl_easy_getinfo(m_impl->curl, CURLINFO_RESPONSE_CODE, &response_code);
	
	if (response_code != 200)
	{
		Error::SetStringFmt(error, "OneDrive API error: HTTP {}", response_code);
		return false;
	}
#endif

	// Parse JSON response (same for both platforms)
	rapidjson::Document doc;
	if (doc.Parse(m_impl->response_buffer.c_str()).HasParseError())
	{
		Error::SetStringFmt(error, "Failed to parse OneDrive API response: {}", 
			rapidjson::GetParseError_En(doc.GetParseError()));
		return false;
	}

	if (!doc.IsObject())
	{
		Error::SetStringView(error, "Invalid OneDrive API response format");
		return false;
	}

	// Extract file information
	if (doc.HasMember("id") && doc["id"].IsString())
		file_info.id = doc["id"].GetString();
	
	if (doc.HasMember("name") && doc["name"].IsString())
		file_info.name = doc["name"].GetString();
	
	if (doc.HasMember("size") && doc["size"].IsUint64())
		file_info.size = doc["size"].GetUint64();
	
	if (doc.HasMember("eTag") && doc["eTag"].IsString())
		file_info.etag = doc["eTag"].GetString();

	if (doc.HasMember("@microsoft.graph.downloadUrl") && doc["@microsoft.graph.downloadUrl"].IsString())
		file_info.download_url = doc["@microsoft.graph.downloadUrl"].GetString();

	return true;
}

size_t OneDriveAPI::DownloadRange(const std::string& file_id, u64 offset, u64 size, void* buffer, Error* error)
{
	if (!IsAuthenticated())
	{
		Error::SetStringView(error, "OneDrive API not authenticated");
		return 0;
	}

	// First get file info to get download URL
	FileInfo file_info;
	if (!GetFileInfo(file_id, file_info, error))
		return 0;

	if (file_info.download_url.empty())
	{
		Error::SetStringView(error, "No download URL available for file");
		return 0;
	}

#ifdef _WIN32
	size_t bytes_read = 0;
	if (!m_impl->DownloadHttpRange(file_info.download_url, offset, size, buffer, &bytes_read))
	{
		Error::SetStringView(error, "Failed to download range from OneDrive");
		return 0;
	}
	return bytes_read;
#else
	// Create a separate CURL handle for downloads to avoid conflicts
	CURL* download_curl = curl_easy_init();
	if (!download_curl)
	{
		Error::SetStringView(error, "Failed to create CURL handle for download");
		return 0;
	}

	std::string download_buffer;
	
	curl_easy_setopt(download_curl, CURLOPT_URL, file_info.download_url.c_str());
	curl_easy_setopt(download_curl, CURLOPT_WRITEFUNCTION, Impl::WriteCallback);
	curl_easy_setopt(download_curl, CURLOPT_WRITEDATA, &download_buffer);
	curl_easy_setopt(download_curl, CURLOPT_FOLLOWLOCATION, 1L);
	
	// Set range header for partial content
	const std::string range_header = fmt::format("Range: bytes={}-{}", offset, offset + size - 1);
	struct curl_slist* headers = nullptr;
	headers = curl_slist_append(headers, range_header.c_str());
	curl_easy_setopt(download_curl, CURLOPT_HTTPHEADER, headers);

	const CURLcode res = curl_easy_perform(download_curl);
	curl_slist_free_all(headers);
	curl_easy_cleanup(download_curl);

	if (res != CURLE_OK)
	{
		Error::SetStringFmt(error, "CURL download error: {}", curl_easy_strerror(res));
		return 0;
	}

	const size_t bytes_read = std::min(download_buffer.size(), static_cast<size_t>(size));
	std::memcpy(buffer, download_buffer.data(), bytes_read);
	
	return bytes_read;
#endif
}

std::string OneDriveAPI::GetBandwidthRequirements()
{
	return "OneDrive streaming requires a stable internet connection with minimum 10 Mbps download speed for smooth gameplay. "
		   "Higher bandwidth (25+ Mbps) is recommended for optimal performance. "
		   "Unstable connections may cause loading delays, audio stuttering, or game freezing. "
		   "Consider downloading the ISO locally if your connection is unreliable.";
}

bool OneDriveAPI::ParseOneDriveURL(const std::string& url, std::string& file_id, Error* error)
{
	// Support various OneDrive URL formats:
	// https://1drv.ms/u/s!AXX-XXX-XXX
	// https://domain-my.sharepoint.com/personal/user_domain_onmicrosoft_com/_layouts/15/download.aspx?SourceUrl=/personal/user_domain_onmicrosoft_com/Documents/file.iso
	// https://graph.microsoft.com/v1.0/me/drive/items/ITEM_ID
	
	if (url.find("1drv.ms") != std::string::npos)
	{
		// Extract short URL and resolve to full Graph API URL
		// This would require additional API call to resolve the short URL
		Error::SetStringView(error, "Short OneDrive URLs (1drv.ms) are not yet supported. Please use the direct file link from OneDrive.");
		return false;
	}
	else if (url.find("sharepoint.com") != std::string::npos)
	{
		// Extract from SharePoint URLs - this would need more complex parsing
		Error::SetStringView(error, "SharePoint URLs are not yet supported. Please use direct OneDrive file links.");
		return false;
	}
	else if (url.find("graph.microsoft.com") != std::string::npos)
	{
		// Extract item ID from Graph API URL
		const size_t items_pos = url.find("/items/");
		if (items_pos != std::string::npos)
		{
			file_id = url.substr(items_pos + 7); // Skip "/items/"
			// Remove any query parameters
			const size_t query_pos = file_id.find('?');
			if (query_pos != std::string::npos)
				file_id = file_id.substr(0, query_pos);
			return true;
		}
	}

	Error::SetStringView(error, "Unsupported OneDrive URL format. Please use a direct file link or Graph API URL.");
	return false;
}

bool OneDriveAPI::IsOneDriveURL(const std::string& url)
{
	return url.find("1drv.ms") != std::string::npos ||
		   url.find("sharepoint.com") != std::string::npos ||
		   url.find("onedrive.live.com") != std::string::npos ||
		   url.find("graph.microsoft.com") != std::string::npos;
}

std::string OneDriveAPI::BuildGraphAPIURL(const std::string& endpoint) const
{
	return fmt::format("https://graph.microsoft.com/v1.0/me/drive/{}", endpoint);
}

bool OneDriveAPI::RefreshAccessToken(Error* error)
{
	// TODO: Implement token refresh logic
	Error::SetStringView(error, "Token refresh not yet implemented");
	return false;
}