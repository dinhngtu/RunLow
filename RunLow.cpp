#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <array>

static constexpr bool do_duplicate = false;
static constexpr bool do_restrict = true;
static constexpr bool do_set_il = true;
static constexpr bool do_set_linked = true;
static constexpr bool do_impersonate = false;

static std::wstring quote(std::wstring inp) {
    std::wstring out;
    for (auto c : inp) {
        if (c == L'"') {
            out.append(L"\\\"");
        } else {
            out.append({ c });
        }
    }
    return out;
}

int wmain(int argc, wchar_t* argv[], wchar_t* envp[]) {
    if (argc < 2) {
        std::wcout << L"usage: runlow <program> [arguments]" << std::endl;
        return 1;
    }
    argc--;
    argv++;
    std::wstringstream args;
    for (int i = 0; i < argc; i++) {
        if (i) {
            args << " ";
        }
        args << L'"' << quote(argv[i]) << L'"';
    }
    //std::wcout << args.str() << std::endl;

    HANDLE ptok = INVALID_HANDLE_VALUE;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &ptok)) {
        std::wcout << L"OpenProcessToken failed: " << GetLastError() << std::endl;
        return 2;
    }

    HANDLE dtok = INVALID_HANDLE_VALUE;
    if (do_duplicate) {
        if (!DuplicateTokenEx(ptok, TOKEN_ALL_ACCESS, NULL, SECURITY_MAX_IMPERSONATION_LEVEL, TokenPrimary, &dtok)) {
            std::wcout << L"DuplicateTokenEx on process token failed: " << GetLastError() << std::endl;
            return 2;
        }
        CloseHandle(ptok);
    } else {
        dtok = ptok;
        ptok = INVALID_HANDLE_VALUE;
    }

    HANDLE rtok = INVALID_HANDLE_VALUE;
    if (do_restrict) {
        DWORD sid_la_sz = SECURITY_MAX_SID_SIZE;
        PSID sid_la = calloc(2, sid_la_sz);
        if (!sid_la || !CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, sid_la, &sid_la_sz)) {
            std::wcout << L"CreateWellKnownSid failed: " << GetLastError() << std::endl;
            return 2;
        }

        DWORD sid_ba_sz = SECURITY_MAX_SID_SIZE;
        PSID sid_ba = calloc(1, sid_la_sz);
        if (!sid_ba || !CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, sid_ba, &sid_ba_sz)) {
            std::wcout << L"CreateWellKnownSid failed: " << GetLastError() << std::endl;
            return 2;
        }

        std::array<SID_AND_ATTRIBUTES, 2> nosids = { SID_AND_ATTRIBUTES{sid_la}, SID_AND_ATTRIBUTES{sid_ba} };

        //if (!CreateRestrictedToken(dtok, LUA_TOKEN, nosids.size(), nosids.data(), 0, NULL, 0, NULL, &rtok)) {
        if (!CreateRestrictedToken(dtok, LUA_TOKEN, 0, NULL, 0, NULL, 0, NULL, &rtok)) {
            std::wcout << L"CreateRestrictedToken failed: " << GetLastError() << std::endl;
            return 2;
        }
        free(sid_la);
        free(sid_ba);
        CloseHandle(dtok);
    } else {
        rtok = dtok;
        dtok = INVALID_HANDLE_VALUE;
    }

    if (do_set_il) {
        DWORD sid_il_sz = SECURITY_MAX_SID_SIZE;
        PSID sid_il = calloc(2, sid_il_sz);
        if (!sid_il || !CreateWellKnownSid(WinMediumLabelSid, NULL, sid_il, &sid_il_sz)) {
            std::wcout << L"CreateWellKnownSid failed: " << GetLastError() << std::endl;
            return 2;
        }

        TOKEN_MANDATORY_LABEL label{};
        label.Label.Sid = sid_il;
        label.Label.Attributes = SE_GROUP_INTEGRITY;

        if (!SetTokenInformation(rtok, TokenIntegrityLevel, &label, sizeof(label) + sid_il_sz)) {
            std::wcout << L"SetTokenInformation on restricted token failed: " << GetLastError() << std::endl;
            return 2;
        }
        free(sid_il);
    }

    if (do_set_linked) {
        TOKEN_LINKED_TOKEN link{};
        DWORD linksz = sizeof(link);

        if (!GetTokenInformation(rtok, TokenLinkedToken, &link, linksz, &linksz)) {
            std::wcout << L"GetTokenInformation failed: " << GetLastError() << std::endl;
            return 2;
        }

        DWORD sid_il_sz = SECURITY_MAX_SID_SIZE;
        PSID sid_il = calloc(2, sid_il_sz);
        if (!sid_il || !CreateWellKnownSid(WinHighLabelSid, NULL, sid_il, &sid_il_sz)) {
            std::wcout << L"CreateWellKnownSid failed: " << GetLastError() << std::endl;
            return 2;
        }

        TOKEN_MANDATORY_LABEL label{};
        label.Label.Sid = sid_il;
        label.Label.Attributes = SE_GROUP_INTEGRITY;

        TOKEN_ELEVATION elev;
        DWORD elev_sz = sizeof(elev);
        if (!GetTokenInformation(rtok, TokenElevation, &elev, elev_sz, &elev_sz)) {
            std::wcout << L"GetTokenInformation(TokenElevation) on restricted token failed: " << GetLastError() << std::endl;
            return 2;
        }
        std::wcout << L"elev = " << elev.TokenIsElevated << std::endl;

        TOKEN_ELEVATION_TYPE elevtype;
        DWORD elevtype_sz = sizeof(elevtype);
        if (!GetTokenInformation(rtok, TokenElevationType, &elevtype, elevtype_sz, &elevtype_sz)) {
            std::wcout << L"GetTokenInformation(TokenElevationType) on restricted token failed: " << GetLastError() << std::endl;
            return 2;
        }
        std::wcout << L"elevtype = " << elevtype << std::endl;

        if (false && !SetTokenInformation(link.LinkedToken, TokenIntegrityLevel, &label, sizeof(label) + sid_il_sz)) {
            std::wcout << L"SetTokenInformation on linked token failed: " << GetLastError() << std::endl;
            return 2;
        }
        free(sid_il);
    }

    if (do_impersonate) {
        if (!ImpersonateSelf(SecurityImpersonation)) {
            std::wcout << L"ImpersonateSelf failed: " << GetLastError() << std::endl;
            return 2;
        }

        HANDLE ttok = INVALID_HANDLE_VALUE;
        if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &ttok)) {
            std::wcout << L"OpenThreadToken failed: " << GetLastError() << std::endl;
            return 2;
        }

        TOKEN_PRIVILEGES privs{ 1 };
        privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (!LookupPrivilegeValueW(NULL, SE_INCREASE_QUOTA_NAME, &privs.Privileges[0].Luid)) {
            std::wcout << L"LookupPrivilegeValueW failed: " << GetLastError() << std::endl;
            return 2;
        }

        if (!AdjustTokenPrivileges(ttok, FALSE, &privs, 0, NULL, NULL)) {
            std::wcout << L"AdjustTokenPrivileges on current thread failed: " << GetLastError() << std::endl;
            return 2;
        }
    }

    STARTUPINFOW si{ sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

    PROCESS_INFORMATION pi{};

    wchar_t* cmdline = _wcsdup(args.str().c_str());
    if (!CreateProcessAsUserW(rtok, NULL, cmdline, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        std::wcout << L"CreateProcessAsUserW failed: " << GetLastError() << std::endl;
        return 2;
    }
    if (do_impersonate) {
        RevertToSelf();
    }
    free(cmdline);
    CloseHandle(pi.hThread);

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);

    return 0;
}
