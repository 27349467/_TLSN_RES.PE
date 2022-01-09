#pragma once
#ifndef _FILETOVIRTULTOFILE_H_
#define _FILETOVIRTULTOFILE_H_

#endif

//�궨��ο��� https://www.cnblogs.com/lanhaicode/p/10546514.html //
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

	VOID AddMessageBoxA();	//�ȵ���MessageBox�ٳ����Լ��ĳ���//

	VOID FiToViToFi();	//����//


private:

	TCHAR Path[0x256];

	TCHAR lpszPath[0x256];

	DWORD lenFile;				//�ļ���С

	DWORD pOptHeaderSizeOfImage;	//�ļ������������С//

	DWORD size_of_new_buffer;		//���̵��ļ������С//

	_PE_S File_PE_s;				

	VOID InjectMessageBoxA(LPVOID* pImageBuffer);	//

	VOID conBuffToAddr(struct _PE_S& _pe_s,const PVOID Addr);////ֱ�ӰѸ���Buff�ṹ����Addr��ϵ��һ��//
};


