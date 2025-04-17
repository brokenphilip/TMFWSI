#pragma once

// Simple RAII implementation of GetLastError
class LastError
{
	LPSTR message = nullptr;
public:
	LastError(DWORD last_error)
	{
		FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK, NULL, last_error,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&message, 0, NULL);
	}
	LastError() : LastError(GetLastError()) {}

	~LastError()
	{
		if (message)
		{
			LocalFree(message);
		}
	}

	const char* Message()
	{
		return message ? message : "Unknown error (FormatMessageA failed).";
	}
};