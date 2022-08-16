#include "framework.h"

#include <codecvt>
#include <locale>

using convert_t = std::codecvt_utf8<wchar_t>;
std::wstring_convert<convert_t, wchar_t> strconverter;

static decltype(CreateFileA)* real_CreateFileA = CreateFileA;
static decltype(CreateFileW)* real_CreateFileW = CreateFileW;

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
	const std::shared_ptr<spdlog::logger> _logger = spdlog::get("ds4sniffer")->clone("CreateFileA");
	std::string path(lpFileName);

	const bool isOfInterest = (path.rfind("\\\\", 0) == 0);

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
			_logger->info("handle = {}, lpFileName = {}", handle, path);
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
	const std::shared_ptr<spdlog::logger> _logger = spdlog::get("ds4sniffer")->clone("CreateFileW");
	std::string path(strconverter.to_bytes(lpFileName));

	const bool isOfInterest = (path.rfind("\\\\", 0) == 0);

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
			_logger->info("handle = {}, lpFileName = {}", handle, path);
	}

	return handle;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
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
		DetourTransactionCommit();

		break;
	}
	case DLL_PROCESS_DETACH:

		spdlog::info("Detaching from process with PID {}", GetCurrentProcessId());

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach((void**)&real_CreateFileA, DetourCreateFileA);
		DetourDetach((void**)&real_CreateFileW, DetourCreateFileW);
		DetourTransactionCommit();

		break;
	}
	return TRUE;
}

