#include "framework.h"

#pragma comment(lib, "hid.lib")

#include <codecvt>
#include <locale>
#include <map>

//
// Change this to filter other devices, currently matches Sony VID
// 
std::string g_match("054C_PID");

using convert_t = std::codecvt_utf8<wchar_t>;
std::wstring_convert<convert_t, wchar_t> strconverter;

static std::map<HANDLE, std::string> g_handleToPath;

static decltype(CreateFileA)* real_CreateFileA = CreateFileA;
static decltype(CreateFileW)* real_CreateFileW = CreateFileW;
static decltype(WriteFile)* real_WriteFile = WriteFile;
static decltype(CloseHandle)* real_CloseHandle = CloseHandle;
static decltype(HidD_SetFeature)* real_HidD_SetFeature = HidD_SetFeature;
static decltype(HidD_SetOutputReport)* real_HidD_SetOutputReport = HidD_SetOutputReport;


//
// Hooks CreateFileA() API
// 
HANDLE WINAPI DetourCreateFileA(
	LPCSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
)
{
	const std::shared_ptr<spdlog::logger> _logger = spdlog::get("ds4sniffer")->clone("ds4sniffer-CreateFileA");
	std::string path(lpFileName);

	std::transform(path.begin(), path.end(), path.begin(), ::toupper);

	const bool isOfInterest = (path.find(g_match, 0) != std::string::npos);

	if (isOfInterest)
		_logger->info("lpFileName = {}", path);

	const auto handle = real_CreateFileA(
		lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile
	);

	if (handle != INVALID_HANDLE_VALUE)
	{
		if (isOfInterest)
		{
			g_handleToPath[handle] = path;
			_logger->info("handle = {}, lpFileName = {}", handle, path);
		}
	}

	return handle;
}

//
// Hooks CreateFileW() API
// 
HANDLE WINAPI DetourCreateFileW(
	LPCWSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
)
{
	const std::shared_ptr<spdlog::logger> _logger = spdlog::get("ds4sniffer")->clone("ds4sniffer-CreateFileW");
	std::string path(strconverter.to_bytes(lpFileName));

	std::transform(path.begin(), path.end(), path.begin(), ::toupper);

	const bool isOfInterest = (path.find(g_match, 0) != std::string::npos);

	if (isOfInterest)
		_logger->info("lpFileName = {}", path);

	const auto handle = real_CreateFileW(
		lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile
	);

	if (handle != INVALID_HANDLE_VALUE)
	{
		if (isOfInterest)
		{
			g_handleToPath[handle] = path;
			_logger->info("handle = {}, lpFileName = {}", handle, path);
		}
	}

	return handle;
}

//
// Hooks WriteFile() API
// 
BOOL WINAPI DetourWriteFile(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
)
{
	const std::shared_ptr<spdlog::logger> _logger = spdlog::get("ds4sniffer")->clone("ds4sniffer-WriteFile");

	const PUCHAR charInBuf = PUCHAR(lpBuffer);
	const std::vector<char> inBuffer(charInBuf, charInBuf + nNumberOfBytesToWrite);

	const auto ret = real_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
	const auto error = GetLastError();

	//
	// Only log if handle of interest
	// 
	if (g_handleToPath.find(hFile) != g_handleToPath.end())
	{
		_logger->info("ret={}, lastError={} ({:04d}) -> {:Xpn}",
			ret,
			error,
			nNumberOfBytesToWrite,
			spdlog::to_hex(inBuffer)
		);
	}

	return ret;
}

//
// Hooks CloseHandle() API
// 
BOOL WINAPI DetourCloseHandle(
	HANDLE hObject
)
{
	const std::shared_ptr<spdlog::logger> _logger = spdlog::get("ds4sniffer")->clone("ds4sniffer-CloseHandle");

	const auto it = g_handleToPath.find(hObject);

	if (it != g_handleToPath.end())
	{
		_logger->info("Closing tracked handle {}", g_handleToPath[hObject]);
		g_handleToPath.erase(it);
	}

	return real_CloseHandle(hObject);
}

//
// Hooks HidD_SetFeature() API
// 
BOOLEAN DetourHidD_SetFeature(
	HANDLE HidDeviceObject,
	PVOID  ReportBuffer,
	ULONG  ReportBufferLength
)
{
	const std::shared_ptr<spdlog::logger> _logger = spdlog::get("ds4sniffer")->clone("ds4sniffer-HidD_SetFeature");

	const PUCHAR charInBuf = PUCHAR(ReportBuffer);
	const std::vector<char> inBuffer(charInBuf, charInBuf + ReportBufferLength);

	const auto ret = real_HidD_SetFeature(HidDeviceObject, ReportBuffer, ReportBufferLength);
	const auto error = GetLastError();

	//
	// Only log if handle of interest
	// 
	if (g_handleToPath.find(HidDeviceObject) != g_handleToPath.end())
	{
		_logger->info("ret={}, lastError={} ({:04d}) -> {:Xpn}",
			ret,
			error,
			ReportBufferLength,
			spdlog::to_hex(inBuffer)
		);
	}

	return ret;
}

//
// Hooks HidD_SetOutputReport() API
// 
BOOLEAN DetourHidD_SetOutputReport(
	HANDLE HidDeviceObject,
	PVOID  ReportBuffer,
	ULONG  ReportBufferLength
)
{
	const std::shared_ptr<spdlog::logger> _logger = spdlog::get("ds4sniffer")->clone("ds4sniffer-HidD_SetOutputReport");

	const PUCHAR charInBuf = PUCHAR(ReportBuffer);
	const std::vector<char> inBuffer(charInBuf, charInBuf + ReportBufferLength);

	const auto ret = real_HidD_SetOutputReport(HidDeviceObject, ReportBuffer, ReportBufferLength);
	const auto error = GetLastError();

	//
	// Only log if handle of interest
	// 
	if (g_handleToPath.find(HidDeviceObject) != g_handleToPath.end())
	{
		_logger->info("ret={}, lastError={} ({:04d}) -> {:Xpn}",
			ret,
			error,
			ReportBufferLength,
			spdlog::to_hex(inBuffer)
		);
	}

	return ret;
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	UNREFERENCED_PARAMETER(lpReserved);

	if (DetourIsHelperProcess())
	{
		return TRUE;
	}

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		//
		// Observe best with https://github.com/CobaltFusion/DebugViewPP
		// 
		auto sink = std::make_shared<spdlog::sinks::msvc_sink_mt>();
#ifdef _DEBUG
		sink->set_level(spdlog::level::debug);
#else
		sink->set_level(spdlog::level::info);
#endif

		auto logger = std::make_shared<spdlog::logger>("ds4sniffer", sink);

#ifdef _DEBUG
		logger->set_level(spdlog::level::debug);
#else
		logger->set_level(spdlog::level::info);
#endif

		logger->flush_on(spdlog::level::info);

		set_default_logger(logger);

		spdlog::info("Attaching to process with PID {}", GetCurrentProcessId());

		DisableThreadLibraryCalls(hModule);
		DetourRestoreAfterWith();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach((void**)&real_CreateFileA, DetourCreateFileA);
		DetourAttach((void**)&real_CreateFileW, DetourCreateFileW);
		DetourAttach((void**)&real_WriteFile, DetourWriteFile);
		DetourAttach((void**)&real_CloseHandle, DetourCloseHandle);
		DetourAttach((void**)&real_HidD_SetFeature, DetourHidD_SetFeature);
		DetourAttach((void**)&real_HidD_SetOutputReport, DetourHidD_SetOutputReport);
		DetourTransactionCommit();

		break;
	}
	case DLL_PROCESS_DETACH:

		spdlog::info("Detaching from process with PID {}", GetCurrentProcessId());

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach((void**)&real_CreateFileA, DetourCreateFileA);
		DetourDetach((void**)&real_CreateFileW, DetourCreateFileW);
		DetourDetach((void**)&real_WriteFile, DetourWriteFile);
		DetourDetach((void**)&real_CloseHandle, DetourCloseHandle);
		DetourDetach((void**)&real_HidD_SetFeature, DetourHidD_SetFeature);
		DetourDetach((void**)&real_HidD_SetOutputReport, DetourHidD_SetOutputReport);
		DetourTransactionCommit();

		break;
	}
	return TRUE;
}
