typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned long u32;
typedef unsigned long long u64;
typedef signed char s8;
typedef signed short s16;
typedef signed long s32;
typedef signed long long s64;

typedef u32 UInt32;
typedef u64 UInt64;
#include "PluginAPI.h"

#include <Windows.h>
#include <cstring>

struct Patch
{
	const u8 * sigData;
	size_t sigLen;

	size_t patchOffset;
	u8 patchData;
};

// SE/1.5.x signature
// tested matching all released versions before 1.6

const u8 kSESignature[] =
{
	0x41, 0xBA, 0x03, 0x00, 0x00, 0x00,		// 00	mov     r10d, 3
	0xB8, 0x00, 0x00, 0x00, 0x68,			// 06	mov     eax, FILE_FLAG_SEQUENTIAL_SCAN or FILE_FLAG_NO_BUFFERING or FILE_FLAG_OVERLAPPED
											//		patch offset 0x0A from 0x68 -> 0x48
	0x48, 0xC7, 0x44, 0x24, 0x30,
		0x00, 0x00, 0x00, 0x00,				// 0B	mov[rsp + 58h + hTemplateFile], 0; hTemplateFile
	0x45, 0x85, 0xF6,						// 14	test    r14d, r14d
};

const Patch kSEPatch =
{
	kSESignature,
	sizeof(kSESignature),

	0x0A, 0x48
};

// AE/1.6.x signature
// tested matching all currently released versions of 1.6 (317-353)

const u8 kAESignature[] =
{
	0x41, 0x8B, 0xEF,						// 00	mov     ebp, r15d
	0x8B, 0xD7,								// 03	mov     edx, edi        ; dwDesiredAccess
	0xC1, 0xFD, 0x1F,						// 05	sar     ebp, 1Fh
	0x49, 0x8B, 0xCC,						// 08	mov     rcx, r12        ; lpFileName
	0x81, 0xE5, 0x00, 0x00, 0x00, 0x60,		// 0B	and     ebp, FILE_FLAG_NO_BUFFERING or FILE_FLAG_OVERLAPPED
											//		patch offset 0x10 from 0x60 -> 0x40
	0x81, 0xC5, 0x00, 0x00, 0x00, 0x08,		// xx	add     ebp, FILE_FLAG_SEQUENTIAL_SCAN
	0x45, 0x8D, 0x41, 0x01,					// xx	lea     r8d, [r9+1]     ; dwShareMode
};

const Patch kAEPatch =
{
	kAESignature,
	sizeof(kAESignature),

	0x10, 0x40
};

const IMAGE_SECTION_HEADER * getImageSection(const u8 * base, const char * name, u32 * outLength)
{
	const IMAGE_DOS_HEADER * dosHeader = (IMAGE_DOS_HEADER *)base;
	const IMAGE_NT_HEADERS * ntHeader = (IMAGE_NT_HEADERS *)(base + dosHeader->e_lfanew);
	const IMAGE_SECTION_HEADER * sectionHeader = IMAGE_FIRST_SECTION(ntHeader);

	for(u32 i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
	{
		const IMAGE_SECTION_HEADER * section = &sectionHeader[i];

		if(!strcmp((const char *)section->Name, name))
		{
			if(outLength) *outLength = section->SizeOfRawData;

			return section;
		}
	}

	return NULL;
}

bool tryApplyPatch(u8 * textBase, u32 textLen, const Patch * patch)
{
	bool result = false;

	if(textLen <= patch->sigLen) return false;

	for(u32 i = 0; i < textLen - patch->sigLen; i++)
	{
		if(!memcmp(textBase + i, patch->sigData, patch->sigLen))
		{
			u8 * patchByte = textBase + i + patch->patchOffset;

			DWORD oldProtect;
			if(VirtualProtect(patchByte, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				*patchByte = patch->patchData;
				VirtualProtect(patchByte, 1, oldProtect, &oldProtect);

				result = true;

				break;
			}
		}
	}

	return result;
}

bool disableUncachedFileAccess()
{
	bool result = false;

	u8 * exeBase = (u8 *)GetModuleHandle(nullptr);

	u32 textLen;
	auto * section = getImageSection(exeBase, ".text", &textLen);
	if(!section) return false;

	u8 * textBase = exeBase + section->VirtualAddress;

	bool patched = tryApplyPatch(textBase, textLen, &kAEPatch);
	if(!patched)
		tryApplyPatch(textBase, textLen, &kSEPatch);

	return result;
}

extern "C" {
	__declspec(dllexport) SKSEPluginVersionData SKSEPlugin_Version =
	{
		SKSEPluginVersionData::kVersion,

		1,
		"large sector fix patch",

		"ianpatt",
		"ianpatt+largesector@gmail.com",

		SKSEPluginVersionData::kVersionIndependent_Signatures,	// signature scanning
		{ 0 },

		0,
	};
};

extern "C" {
	__declspec(dllexport) bool SKSEPlugin_Query(const SKSEInterface * skse, PluginInfo * info)
	{
		info->infoVersion = PluginInfo::kInfoVersion;
		info->name = "large sector fix patch";
		info->version = 1;

		// runtime-only. signature patch.

		return skse->isEditor == false;
	}

	__declspec(dllexport) bool SKSEPlugin_Load(const SKSEInterface * skse)
	{
		disableUncachedFileAccess();

		return true;
	}
}
