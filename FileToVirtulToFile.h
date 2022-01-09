#pragma once
#ifndef _FILETOVIRTULTOFILE_H_
#define _FILETOVIRTULTOFILE_H_

#endif

//宏定义参考： https://www.cnblogs.com/lanhaicode/p/10546514.html //
#include "StdAfx.h"
#include "PE_s.h"
#include <windows.h>
#include <malloc.h>
#include <iostream>

using namespace std;
class _PE
{
public:
	_PE(){};

	_PE(TCHAR* GPath);

	_PE(TCHAR* GPath,LPSTR lpszFile);

	~_PE();

	VOID ReadPEFile(LPVOID* pFileBuffer);

	VOID CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer);

	VOID CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer,OUT LPVOID* pNewBuffer);	

	VOID MemeryTOFile(IN LPVOID pMemBuffer);

	VOID AddMessageBoxA();	//先弹出MessageBox再出现自己的程序//

	VOID FiToViToFi();	//存盘//


private:

	TCHAR Path[0x256];

	TCHAR lpszPath[0x256];

	DWORD lenFile;				//文件大小

	DWORD pOptHeaderSizeOfImage;	//文件拉伸后的虚拟大小//

	DWORD size_of_new_buffer;		//存盘的文件虚拟大小//

	_PE_S File_PE_s;				

	VOID InjectMessageBoxA(LPVOID* pImageBuffer);	//

	VOID conBuffToAddr(struct _PE_S& _pe_s,const PVOID Addr);////直接把各种Buff结构体与Addr联系到一块//
};


