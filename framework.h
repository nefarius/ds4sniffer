// header.h : include file for standard system include files,
// or project specific include files
//

#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>
#include <hidsdi.h>
#include <detours/detours.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/msvc_sink.h>
#include <spdlog/fmt/bin_to_hex.h>
