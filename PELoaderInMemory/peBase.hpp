#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include<windows.h>
#include<fstream>
#pragma warning( disable : 4996 )
//内存加载模块

//把文件内容读入内存
inline BYTE* ReadFileToMemory(LPCSTR filename, LONGLONG &filelen)
{
	FILE* fileptr;
	BYTE* buffer;

    fileptr = fopen(filename, "rb");
    if (fileptr == NULL) return NULL;
	fseek(fileptr, 0, SEEK_END);
	filelen = ftell(fileptr);
	rewind(fileptr);

	buffer = (BYTE*)malloc((filelen + 1) * sizeof(char));
	fread(buffer, filelen, 1 , fileptr);
	fclose(fileptr);

	return buffer;
}


//获取文件的NT头
inline BYTE* getNtHdrs(BYTE* pe_buffer)
{
    if (pe_buffer == NULL) return NULL;
    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)pe_buffer;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    const LONG MaxOffset = 1024;
    LONG pe_offset = idh->e_lfanew;
    if (pe_offset > MaxOffset) return NULL;
    PIMAGE_NT_HEADERS inh = (PIMAGE_NT_HEADERS)(pe_buffer + pe_offset);
    if (inh->Signature != IMAGE_NT_SIGNATURE) return NULL;
    return (BYTE*)inh;
  
}

//获取PE文件指定目录

inline IMAGE_DATA_DIRECTORY* getPeDirectory(PVOID pe_buffer, size_t dir_id)
{
    if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;
    BYTE* nt_headers = getNtHdrs((BYTE*)pe_buffer);
    if (nt_headers == NULL) return NULL;
    IMAGE_DATA_DIRECTORY* peDir = NULL;
    IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)nt_headers;
    peDir = &(nt_header->OptionalHeader.DataDirectory[dir_id]);
    if (peDir->VirtualAddress == NULL) {
        return NULL;
    }
    return peDir;
}


