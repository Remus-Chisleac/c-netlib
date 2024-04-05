#pragma once

#ifndef NET_COMMON
#define NET_COMMON



#include "Includes.h"
/// ASIO
#ifdef _WIN32
#define _WIN32_WININT 0x0A00
#endif

#include <asio.hpp>
#include <asio/ts/buffer.hpp>
#include <asio/ts/internet.hpp>

#include <crtdbg.h>
#include <netfw.h>
#include <objbase.h>
#include <oleauto.h>

#endif // !NET_COMMON

