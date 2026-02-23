#pragma once
#include<windows.h>
#include"peBase.hpp"
typedef struct _BASE_RELOCATION_ENTRY {
	WORD Offset : 12; 
	WORD Type : 4;
}BASE_RELOCATION_ENTRY;

#define RELOC_32BIT_FIELD 3
#define RELOC_64BIT_FIELD 10

inline bool applyReloc(ULONGLONG newBase, ULONGLONG oldBase, PVOID moduleptr, SIZE_T modulesize)
{
	IMAGE_DATA_DIRECTORY* relocDir = getPeDirectory(moduleptr, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	if (relocDir == NULL) return false;

	size_t maxsize = relocDir->Size;
	size_t relocAddress = relocDir->VirtualAddress;
	IMAGE_BASE_RELOCATION* reloc = NULL;

	//遍历重定位表中的每一块
	size_t parsedSize = 0;
	for (; parsedSize < maxsize; parsedSize += reloc->SizeOfBlock)
	{
		reloc = (IMAGE_BASE_RELOCATION*)(relocAddress + parsedSize + (size_t)moduleptr);
		if (reloc->VirtualAddress == NULL || reloc->SizeOfBlock == 0) break;


		size_t entryiesNum = ((reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY));
		size_t page = reloc->VirtualAddress; //起始地址
		//跳过头部找数据区
		BASE_RELOCATION_ENTRY* entry = (BASE_RELOCATION_ENTRY*)(size_t(reloc) + sizeof(IMAGE_BASE_RELOCATION));
		for (size_t i = 0; i < entryiesNum; i++)
		{
			size_t offset = entry->Offset;
			size_t type = entry->Type;

			size_t reloc_field = page + offset; //需要重定位地址
			if (entry == NULL || type == 0) break;
			if (type != RELOC_32BIT_FIELD || type != RELOC_64BIT_FIELD) {
				printf(" Not supported relocations format at %d: %d\n", (int)i, (int)type);
				return false;
			}
			if (reloc_field >= modulesize) {  //大于模块大小了
				printf(" Out of Bound Field: %llx\n", reloc_field);
				return false;
			}

			//获取需要重定位实际内存地址
			size_t* relocAddr = (size_t*)((size_t)(moduleptr)+reloc_field);
			printf("Apply Reloc Field at %p\n", relocAddr);
			//重定位
			(*relocAddr) = ((*relocAddr) - oldBase + newBase);
			entry = (BASE_RELOCATION_ENTRY*)(size_t(entry) + sizeof(BASE_RELOCATION_ENTRY));

		}
	}
	return (parsedSize != 0);
}