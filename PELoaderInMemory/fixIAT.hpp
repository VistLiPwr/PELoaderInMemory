#include<string>
#include<windows.h>
#include"peBase.hpp"
using namespace std;


bool hijackCmd = false;
//ANSI
char* masqCmd_Ansi = NULL;
char* masqCmd_ArgvAnsi[100] = {};
//宽字节
wchar_t* masqCmd_Width = NULL;
wchar_t* masqCmd_ArgvWidth[100] = {};
//伪装命令行的参数
int masqCmd_Argc = 0;
//劫持GetCommandLine函数
LPSTR hookGetCommandLineA() { return masqCmd_Ansi; }
LPWSTR hookGetCommandLineW() { return masqCmd_Width; }

int __getmainargs(int* argc, char*** argv, char*** env, int doWildCard, PVOID startInfo) {
    *argc = masqCmd_Argc;
    *argv = (char**)masqCmd_ArgvAnsi;
    return 0;
}

int __wgetmainargs(int* argc, wchar_t*** argv, wchar_t*** env, int doWildCard, PVOID startInfo) {
    *argc = masqCmd_Argc;
    *argv = (wchar_t**)masqCmd_ArgvWidth;
    return 0;
}

//伪装命令行

inline void masqCmdLine(const wchar_t* cmdline)
{
    if (!cmdline) return ;
    auto sz_wcmdline = wstring(cmdline);

    //分配内存并复制伪装的命令行
    masqCmd_Width = new wchar_t[sz_wcmdline.size() + 1];  //堆上分配，保证存活
    lstrcpyW(masqCmd_Width, sz_wcmdline.c_str());

    auto k = string(sz_wcmdline.begin(), sz_wcmdline.end());
    masqCmd_Ansi = new char[k.size() + 1];
    lstrcpyA(masqCmd_Ansi, k.c_str());

    LPWSTR* Arglist = CommandLineToArgvW(cmdline, &masqCmd_Argc);
    for (size_t i = 0; i < masqCmd_Argc;i++)
    {
        masqCmd_ArgvWidth[i] = new wchar_t[lstrlenW(Arglist[i]) + 1];
        lstrcpyW(masqCmd_ArgvWidth[i], Arglist[i]);

        auto k = string(wstring(masqCmd_ArgvWidth[i]).begin(), wstring(masqCmd_ArgvWidth[i]).end());
        masqCmd_ArgvAnsi[i] = new char[k.size() + 1];
        lstrcpyA(masqCmd_ArgvAnsi[i], k.c_str());
    }

    hijackCmd = true;
}


//修复IAT
inline bool fixIAT(PVOID moduleptr)
{
    printf("Fix Import Address Table \n");
    IMAGE_DATA_DIRECTORY* importsDir = getPeDirectory(moduleptr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importsDir == NULL) return false;

    size_t maxSize = importsDir->Size;
    size_t impAddr = importsDir->VirtualAddress;
    IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL; //准备挨个读取
    size_t parsedSize = 0;

    for (; parsedSize < maxSize; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR))
    {
        lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR)moduleptr);
        if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) break;
        LPSTR lib_name = (LPSTR)((ULONG_PTR)moduleptr + lib_desc->Name);
        printf("Import DLL: %s\n", lib_name);

        size_t call_via = lib_desc->FirstThunk;
        size_t thunk_addr = lib_desc->OriginalFirstThunk;
        //经过混淆之类的操作的PE文件，OriginalFirstThunk可能会为空
        if (thunk_addr == NULL) thunk_addr = lib_desc->FirstThunk;

        size_t offsetField = 0; //IAT
        size_t offsetThunk = 0; //INTD
        while (true)
        {
            IMAGE_THUNK_DATA* fieldThunk =(IMAGE_THUNK_DATA*) ((size_t)moduleptr + call_via + offsetField);
            IMAGE_THUNK_DATA* originThunk = (IMAGE_THUNK_DATA*)(size_t(moduleptr) + offsetThunk + thunk_addr);

            if (originThunk->u1.Function == NULL) break;  //为空遍历完成，跳出

            HMODULE hmodule = LoadLibraryA(lib_name);
            if (!hmodule) break;

            //好像按序号导入无法劫持到了
            if (originThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32 || originThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
            {
                // === 按序号导入 ===
                size_t addr = (size_t)GetProcAddress(hmodule, (char*)(originThunk->u1.Ordinal & 0xFFFF));
                printf("  API by Ordinal %x at %Ix\n", (originThunk->u1.Ordinal & 0xFFFF), addr);
                fieldThunk->u1.Function = addr;
            }
            else
            {
                PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)(size_t(moduleptr) + originThunk->u1.AddressOfData);
                LPSTR func_name = (LPSTR)by_name->Name;
                size_t addr = (size_t)GetProcAddress(hmodule, func_name);
                printf("  API %s at %Ix\n", func_name, addr);

                if (hijackCmd && strcmpi(func_name, "GetCommandLineA") == 0)
                    fieldThunk->u1.Function = (size_t)hookGetCommandLineA;
                else if (hijackCmd && strcmpi(func_name, "GetCommandLineW") == 0)
                    fieldThunk->u1.Function = (size_t)hookGetCommandLineW;
                else if (hijackCmd && strcmpi(func_name, "__wgetmainargs") == 0)
                    fieldThunk->u1.Function = (size_t)__wgetmainargs;
                else if (hijackCmd && strcmpi(func_name, "__getmainargs") == 0)
                    fieldThunk->u1.Function = (size_t)__getmainargs;
                else
                    fieldThunk->u1.Function = addr;
            }
            offsetField += sizeof(IMAGE_THUNK_DATA);
            offsetThunk += sizeof(IMAGE_THUNK_DATA);
        }
    }
    return true;
}