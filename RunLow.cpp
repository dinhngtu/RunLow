#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <iostream>
#include <sstream>

static std::wstring QuoteArgument(std::wstring inp) {
    std::wstring out;
    for (wchar_t c : inp) {
        if (c == L'"') {
            out.append(L"\\\"");
        } else {
            out.append({ c });
        }
    }
    return out;
}

static PSID AllocWellKnownSid(WELL_KNOWN_SID_TYPE sidType) {
    DWORD sid_sz = SECURITY_MAX_SID_SIZE;
    PSID sid = calloc(1, sid_sz);
    if (!sid || !CreateWellKnownSid(sidType, NULL, sid, &sid_sz)) {
        std::wcerr << L"CreateWellKnownSid failed: " << GetLastError() << std::endl;
        return NULL;
    }
    return sid;
}

int wmain(int argc, wchar_t* argv[], wchar_t* envp[]) {
    if (argc < 2) {
        std::wcerr << L"usage: runlow <program> [arguments]" << std::endl;
        return 1;
    }
    argc--;
    argv++;
    std::wstringstream args;
    for (int i = 0; i < argc; i++) {
        if (i) {
            args << L" ";
        }
        args << L'"' << QuoteArgument(argv[i]) << L'"';
    }

    HANDLE ptok = INVALID_HANDLE_VALUE;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &ptok)) {
        std::wcerr << L"OpenProcessToken failed: " << GetLastError() << std::endl;
        return 2;
    }

    HANDLE rtok = INVALID_HANDLE_VALUE;
    if (!CreateRestrictedToken(ptok, LUA_TOKEN, 0, NULL, 0, NULL, 0, NULL, &rtok)) {
        std::wcerr << L"CreateRestrictedToken failed: " << GetLastError() << std::endl;
        return 2;
    }
    CloseHandle(ptok);

    PSID sid_il = AllocWellKnownSid(WinMediumLabelSid);
    if (!sid_il) {
        return 2;
    }

    TOKEN_MANDATORY_LABEL label{};
    label.Label.Sid = sid_il;
    label.Label.Attributes = SE_GROUP_INTEGRITY;

    if (!SetTokenInformation(rtok, TokenIntegrityLevel, &label, sizeof(label))) {
        std::wcerr << L"SetTokenInformation on restricted token failed: " << GetLastError() << std::endl;
        return 2;
    }
    free(sid_il);

    STARTUPINFOW si{ sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

    PROCESS_INFORMATION pi{};

    wchar_t* cmdline = _wcsdup(args.str().c_str());
    if (!CreateProcessAsUserW(rtok, NULL, cmdline, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        std::wcerr << L"CreateProcessAsUserW failed: " << GetLastError() << std::endl;
        return 2;
    }
    free(cmdline);
    CloseHandle(pi.hThread);

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);

    return 0;
}
