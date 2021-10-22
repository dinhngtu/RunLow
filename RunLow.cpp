#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <array>
#include <winsafer.h>

static constexpr bool do_duplicate = false;
static constexpr bool do_restrict = true;
static constexpr bool do_restrict_safer = false;
static constexpr bool do_set_il = true;
static constexpr bool do_set_elev = false;
static constexpr bool do_set_linked = false;
static constexpr bool do_set_linked_il = true;
static constexpr bool do_set_linked_elev = false;
static constexpr bool do_enable_increase_quota = false;

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

static int ShowTokenElevation(HANDLE token) {
    TOKEN_ELEVATION elev;
    DWORD elev_sz = sizeof(elev);
    if (!GetTokenInformation(token, TokenElevation, &elev, elev_sz, &elev_sz)) {
        std::wcout << L"GetTokenInformation(TokenElevation) on token " << token << " failed: " << GetLastError() << std::endl;
        return 2;
    }
    std::wcout << L"elev = " << elev.TokenIsElevated << std::endl;

    TOKEN_ELEVATION_TYPE elevtype;
    DWORD elevtype_sz = sizeof(elevtype);
    if (!GetTokenInformation(token, TokenElevationType, &elevtype, elevtype_sz, &elevtype_sz)) {
        std::wcout << L"GetTokenInformation(TokenElevationType) on token " << token << " failed: " << GetLastError() << std::endl;
        return 2;
    }
    std::wcout << L"elevtype = " << elevtype << std::endl;
    return 0;
}

static PSID AllocWellKnownSid(WELL_KNOWN_SID_TYPE sidType) {
    DWORD sid_sz = SECURITY_MAX_SID_SIZE;
    PSID sid = calloc(1, sid_sz);
    if (!sid || !CreateWellKnownSid(sidType, NULL, sid, &sid_sz)) {
        std::wcout << L"CreateWellKnownSid failed: " << GetLastError() << std::endl;
        return NULL;
    }
    return sid;
}

int EnablePrivilege(LPCWSTR priv) {
    HANDLE ttok = INVALID_HANDLE_VALUE;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &ttok)) {
        std::wcout << L"OpenThreadToken failed: " << GetLastError() << std::endl;
        return 2;
    }

    TOKEN_PRIVILEGES privs{ 1 };
    privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueW(NULL, priv, &privs.Privileges[0].Luid)) {
        std::wcout << L"LookupPrivilegeValueW failed: " << GetLastError() << std::endl;
        return 2;
    }

    if (!AdjustTokenPrivileges(ttok, FALSE, &privs, 0, NULL, NULL)) {
        std::wcout << L"AdjustTokenPrivileges on current thread failed: " << GetLastError() << std::endl;
        return 2;
    }
    return 0;
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
            args << L" ";
        }
        args << L'"' << quote(argv[i]) << L'"';
    }
    //std::wcout << args.str() << std::endl;

    HANDLE ptok = INVALID_HANDLE_VALUE;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &ptok)) {
        std::wcout << L"OpenProcessToken failed: " << GetLastError() << std::endl;
        return 2;
    }
    std::wcout << L"current process token = " << ptok << std::endl;

    std::wcout << L"my token elevation:" << std::endl;
    ShowTokenElevation(ptok);

    HANDLE dtok = INVALID_HANDLE_VALUE;
    if (do_duplicate) {
        if (!DuplicateTokenEx(ptok, TOKEN_ALL_ACCESS, NULL, SECURITY_MAX_IMPERSONATION_LEVEL, TokenPrimary, &dtok)) {
            std::wcout << L"DuplicateTokenEx on process token failed: " << GetLastError() << std::endl;
            return 2;
        }
        //CloseHandle(ptok);
        std::wcout << L"duplicated process token = " << dtok << std::endl;
    } else {
        dtok = ptok;
        ptok = INVALID_HANDLE_VALUE;
    }

    HANDLE rtok = INVALID_HANDLE_VALUE;
    if (do_restrict) {
        PSID sid_la = AllocWellKnownSid(WinBuiltinAdministratorsSid);
        if (!sid_la) {
            return 2;
        }

        PSID sid_ba = AllocWellKnownSid(WinBuiltinAdministratorsSid);
        if (!sid_ba) {
            return 2;
        }

        std::array<SID_AND_ATTRIBUTES, 2> nosids = { SID_AND_ATTRIBUTES{sid_la}, SID_AND_ATTRIBUTES{sid_ba} };

        //if (!CreateRestrictedToken(dtok, LUA_TOKEN, nosids.size(), nosids.data(), 0, NULL, 0, NULL, &token)) {
        if (!CreateRestrictedToken(dtok, LUA_TOKEN, 0, NULL, 0, NULL, 0, NULL, &rtok)) {
            std::wcout << L"CreateRestrictedToken failed: " << GetLastError() << std::endl;
            return 2;
        }
        free(sid_la);
        free(sid_ba);
        CloseHandle(dtok);
        std::wcout << L"restricted process token = " << rtok << std::endl;
    } else if (do_restrict_safer) {
        SAFER_LEVEL_HANDLE safer;
        if (!SaferCreateLevel(SAFER_SCOPEID_USER, SAFER_LEVELID_NORMALUSER, SAFER_LEVEL_OPEN, &safer, NULL)) {
            std::wcout << L"SaferCreateLevel failed: " << GetLastError() << std::endl;
            return 2;
        }

        if (!SaferComputeTokenFromLevel(safer, dtok, &rtok, 0, NULL)) {
            std::wcout << L"SaferComputeTokenFromLevel failed: " << GetLastError() << std::endl;
            return 2;
        }
        CloseHandle(dtok);

        SaferCloseLevel(safer);
        std::wcout << L"restricted process token = " << rtok << std::endl;
    } else {
        rtok = dtok;
        dtok = INVALID_HANDLE_VALUE;
    }

    if (do_enable_increase_quota) {
        if (!ImpersonateSelf(SecurityImpersonation)) {
            std::wcout << L"ImpersonateSelf failed: " << GetLastError() << std::endl;
            return 2;
        }
    }

    if (do_set_elev) {
        TOKEN_ELEVATION_TYPE elevtype = TokenElevationTypeLimited;
        DWORD elevtype_sz = sizeof(elevtype);
        if (!SetTokenInformation(rtok, TokenElevationType, &elevtype, elevtype_sz)) {
            std::wcout << L"SetTokenInformation(TokenElevationType) on restricted token failed: " << GetLastError() << std::endl;
            return 2;
        }
    }

    if (do_set_il) {
        PSID sid_il = AllocWellKnownSid(WinMediumLabelSid);
        if (!sid_il) {
            return 2;
        }

        TOKEN_MANDATORY_LABEL label{};
        label.Label.Sid = sid_il;
        label.Label.Attributes = SE_GROUP_INTEGRITY;

        if (!SetTokenInformation(rtok, TokenIntegrityLevel, &label, sizeof(label) + GetLengthSid(sid_il))) {
            std::wcout << L"SetTokenInformation on restricted token failed: " << GetLastError() << std::endl;
            return 2;
        }
        free(sid_il);
    }

    std::wcout << L"restricted token elevation:" << std::endl;
    ShowTokenElevation(rtok);

    if (do_set_linked) {
        TOKEN_LINKED_TOKEN link{ ptok };
        if (!SetTokenInformation(rtok, TokenLinkedToken, &link, sizeof(link))) {
            std::wcout << L"SetTokenInformation(TokenLinkedToken) on restricted token failed: " << GetLastError() << std::endl;
            return 2;
        }
    }

    if (do_set_linked_il) {
        TOKEN_LINKED_TOKEN link{};
        DWORD linksz = sizeof(link);

        if (!GetTokenInformation(rtok, TokenLinkedToken, &link, linksz, &linksz)) {
            std::wcout << L"GetTokenInformation failed: " << GetLastError() << std::endl;
            return 2;
        }

        std::wcout << L"linked token elevation:" << std::endl;
        ShowTokenElevation(link.LinkedToken);

        PSID sid_il = AllocWellKnownSid(WinMediumLabelSid);
        if (!sid_il) {
            return 2;
        }

        TOKEN_MANDATORY_LABEL label{};
        label.Label.Sid = sid_il;
        label.Label.Attributes = SE_GROUP_INTEGRITY;

        if (!SetTokenInformation(link.LinkedToken, TokenIntegrityLevel, &label, sizeof(label) + GetLengthSid(sid_il))) {
            std::wcout << L"SetTokenInformation on linked token failed: " << GetLastError() << std::endl;
            return 2;
        }
        free(sid_il);

        if (do_set_linked_elev) {
            TOKEN_ELEVATION_TYPE elevtype = TokenElevationTypeFull;
            DWORD elevtype_sz = sizeof(elevtype);
            if (!SetTokenInformation(link.LinkedToken, TokenElevationType, &elevtype, elevtype_sz)) {
                std::wcout << L"SetTokenInformation(TokenElevationType) on linked token failed: " << GetLastError() << std::endl;
                return 2;
            }
        }
    }

    if (do_enable_increase_quota) {
        int ret = EnablePrivilege(SE_INCREASE_QUOTA_NAME);
        if (ret) {
            return ret;
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
    if (do_enable_increase_quota) {
        RevertToSelf();
    }
    free(cmdline);
    CloseHandle(pi.hThread);

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);

    return 0;
}
