#include "Class_PE.h"

_PE::_PE(char* GPath)
{
	memcpy(Path,GPath,0x256);

}

_PE::_PE(TCHAR* GPath,LPSTR lpszFile)	//这个构造函数包含了存盘存的位置//
{
	memcpy(Path,GPath,0x256);
	memcpy(lpszPath,lpszFile,0x256);
	
	lenFile = 0;
	pOptHeaderSizeOfImage = 0;
	size_of_new_buffer = 0;
}

_PE::~_PE()
{
	cout<<"Class_PE析构"<<endl;
}

DWORD _PE::RvaToFileOffset(IN DWORD dwRva)
{
	if(dwRva <= File_PE_s.pOptionHeader->SizeOfHeaders)
        return dwRva;
    for(DWORD i=0;i<File_PE_s.pPEHeader->NumberOfSections;i++)
    {
        if(dwRva >= (File_PE_s.pSectionHeader + i)->VirtualAddress && dwRva < ((File_PE_s.pSectionHeader + i)->VirtualAddress + (File_PE_s.pSectionHeader + i)->Misc.VirtualSize))
        {
            return (File_PE_s.pSectionHeader + i)->PointerToRawData + dwRva - (File_PE_s.pSectionHeader + i)->VirtualAddress;
        }

    }

	return -1;
}


//直接把各种Buff结构体与Addr联系到一块//
VOID _PE::conBuffToAddr(struct _PE_S& _pe_s,const PVOID Addr)
{
	if(!Addr)
	{
		printf("Addr wrong\n");

		return ;
	}
	
	if(*(PWORD)Addr != IMAGE_DOS_SIGNATURE)
	{
		printf("无MZ标记，非exe文件!!!\n");
		free(Addr);

		return ;
	}
	
	_pe_s.pDosHeader = (PIMAGE_DOS_HEADER)Addr;

	_pe_s.pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)Addr + _pe_s.pDosHeader->e_lfanew);

	_pe_s.pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)_pe_s.pNTHeader + sizeof(IMAGE_NT_SIGNATURE)); 

	_pe_s.pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)(_pe_s.pPEHeader)+IMAGE_SIZEOF_FILE_HEADER);

	_pe_s.pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)_pe_s.pOptionHeader+_pe_s.pPEHeader->SizeOfOptionalHeader);

	_pe_s.pDataDirectory = (PIMAGE_DATA_DIRECTORY)((DWORD)_pe_s.pSectionHeader - 16 * sizeof(IMAGE_DATA_DIRECTORY));

	_pe_s.pExportDir = (PIMAGE_EXPORT_DIRECTORY)(((DWORD)Addr + RvaToFileOffset(_pe_s.pDataDirectory[0].VirtualAddress)));
	
	_pe_s.pBaseReloc = (PIMAGE_BASE_RELOCATION)((DWORD)Addr + RvaToFileOffset(_pe_s.pDataDirectory[5].VirtualAddress));

	_pe_s.pImportDescri = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)Addr + RvaToFileOffset(_pe_s.pDataDirectory[1].VirtualAddress));

	_pe_s.pBoundImportDir = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD)Addr + RvaToFileOffset(_pe_s.pDataDirectory[11].VirtualAddress));

	_pe_s.pResDirectory = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)Addr + RvaToFileOffset(_pe_s.pDataDirectory[2].VirtualAddress));
	
	if(*((PDWORD)((DWORD)Addr+_pe_s.pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)//0x00004550  // PE00//
	{
		printf("不是有效的PE标志\n");
		free(Addr);
		getchar();
		exit(0);
		return ;
	}
}




//把文件读到缓冲区//
VOID _PE::ReadPEFile(LPVOID* pFileBuffer)
{
	LPVOID pTempFileBuffer = NULL;
	FILE* fp = fopen(Path,"rb");

	if(!fp)
	{
		printf("fopen Error!!!\n");
		fclose(fp);
		getchar();
		exit(0);
		return ;
	}

	fseek(fp,0,SEEK_END);	//SEEK_END : 使指针指向文件的末尾//
	lenFile = ftell(fp);	//回给定流stream的当前文件位置//
	fseek(fp,0,SEEK_SET);
	
	pTempFileBuffer = malloc(lenFile);
	if(!pTempFileBuffer)
	{
		printf("pTempFileBuffer，malloc失败!!!\n");
		free(pTempFileBuffer);
		fclose(fp);
		return ;
	}

	memset(pTempFileBuffer,0,lenFile);
	fread(pTempFileBuffer,1,lenFile,fp);

	*pFileBuffer = pTempFileBuffer;
	pTempFileBuffer = NULL;
	conBuffToAddr(File_PE_s,*pFileBuffer);

	fclose(fp);
//	cout<<"File的长度为："<<lenFile<<endl;
}

//拉伸//
VOID _PE::CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer)
{
	LPVOID pTempImagebufferr = NULL;

	pTempImagebufferr=malloc(File_PE_s.pOptionHeader->SizeOfImage);

	if(!pTempImagebufferr)
    {
        printf("pTempImagebufferr malloc 2\n");
        free(pFileBuffer);

        return ;
    }

	memset(pTempImagebufferr,0,File_PE_s.pOptionHeader->SizeOfImage);
    memcpy(pTempImagebufferr,File_PE_s.pDosHeader,File_PE_s.pOptionHeader->SizeOfHeaders);

	for(int i = 0;i < File_PE_s.pPEHeader->NumberOfSections;i++,(File_PE_s.pSectionHeader)++ )
	{
		memcpy((LPVOID)((DWORD)pTempImagebufferr + File_PE_s.pSectionHeader->VirtualAddress),(LPVOID)((DWORD)pFileBuffer + File_PE_s.pSectionHeader->PointerToRawData),File_PE_s.pSectionHeader->SizeOfRawData);
	}
	
	for(int j = 0;j < File_PE_s.pPEHeader->NumberOfSections; j++)
	{
		(File_PE_s.pSectionHeader)--;
	}//恢复第0个节表//
	
	*pImageBuffer=pTempImagebufferr;
	pTempImagebufferr = NULL;

	pOptHeaderSizeOfImage = File_PE_s.pOptionHeader->SizeOfImage;
	
//	cout<<"pOptHeaderSizeOfImage : "<<pOptHeaderSizeOfImage<<endl;
	return ;
}

//压缩//
VOID _PE::CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer,OUT LPVOID* pNewBuffer)
{
	LPVOID pTempImagebufferr = NULL;

	size_of_new_buffer = File_PE_s.pOptionHeader->SizeOfHeaders;
	
	for(size_t i = 0;i<File_PE_s.pPEHeader->NumberOfSections;i++)
	{
		size_of_new_buffer += (File_PE_s.pSectionHeader + i)->SizeOfRawData;
	}
	
	pTempImagebufferr = malloc(size_of_new_buffer);

	if(!pTempImagebufferr)
    {
        printf("malloc Error 3\n");
		free(pImageBuffer);
        
		return ;
    }

	memset(pTempImagebufferr,0,File_PE_s.pOptionHeader->SizeOfHeaders);
	memcpy(pTempImagebufferr,pImageBuffer,File_PE_s.pOptionHeader->SizeOfHeaders);

	for(DWORD j = 0;j < File_PE_s.pPEHeader->NumberOfSections ; j++,(File_PE_s.pSectionHeader)++)
    {
        memcpy((void*)((DWORD)pTempImagebufferr+File_PE_s.pSectionHeader->PointerToRawData),(void*)((DWORD)pImageBuffer+File_PE_s.pSectionHeader->VirtualAddress),File_PE_s.pSectionHeader->SizeOfRawData);
    }
	
	for(int k = 0;k < File_PE_s.pPEHeader->NumberOfSections; k++)
	{
		(File_PE_s.pSectionHeader)--;
	}

	*pNewBuffer=pTempImagebufferr;
	pTempImagebufferr=NULL;

//	cout<<"size_of_new_buffer : "<<size_of_new_buffer<<endl;

//	cout<<"pSectionHeader->Misc.VirtualSize : "<<hex<<File_PE_s.pSectionHeader->Misc.VirtualSize<<endl;

}
//存盘//
VOID _PE::MemeryTOFile(IN LPVOID pMemBuffer)
{
	FILE* Fb=fopen(lpszPath,"wb");

	if(!Fb)
    {
        printf("fopen Error 2!!!\n");
        fclose(Fb);
        free(pMemBuffer);

		
    }
	fwrite(pMemBuffer,1,size_of_new_buffer,Fb);
	
	fclose(Fb);
	free(pMemBuffer);

	return ;
}

//存盘//
VOID _PE::FiToViToFi()
{
	PVOID pImageBuffer = NULL;
	PVOID pNewBuffer = NULL;
	PVOID pFileBuffer=NULL;

	ReadPEFile(&pFileBuffer);

	CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);

	CopyImageBufferToNewBuffer(pImageBuffer,&pNewBuffer);
	
	MemeryTOFile(pNewBuffer);

}

//向程序里注入MessageBox//
VOID _PE::AddMessageBoxA()
{
	PVOID pImageBuffer = NULL;
	PVOID pNewBuffer = NULL;
	PVOID pFileBuffer=NULL;

	ReadPEFile(&pFileBuffer);

	CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);

	InjectMessageBoxA(&pImageBuffer);

	CopyImageBufferToNewBuffer(pImageBuffer,&pNewBuffer);

	MemeryTOFile(pNewBuffer);

}

/************************************************/
/*												*/
/*真正要跳转的地址 = E8这条指令的下一行地址 + X	*/		
/*												*/
/*X = 真正要跳转的地址 - E8这条指令的下一行地址	*/
/*												*/		
/************************************************/

BYTE shellcode[]=
{
    0x6A,00,0x6A,00,0x6A,00,0x6A,00,
    0xE8,00,00,00,00,
    0xE9,00,00,00,00

};



VOID _PE::InjectMessageBoxA(LPVOID* pImageBuffer)
{
	
	DWORD Misc_VirtualSize;
	DWORD SectionAlignment;
	DWORD dwMessageBoxA;
	_PE_S  File_PE_s;

	conBuffToAddr(File_PE_s,*pImageBuffer);
	for(size_t i = 0;i < File_PE_s.pPEHeader->NumberOfSections; i++, (File_PE_s.pSectionHeader)++)
	{
		 Misc_VirtualSize = File_PE_s.pSectionHeader->Misc.VirtualSize;
		 SectionAlignment = File_PE_s.pOptionHeader->SectionAlignment;

		if(SectionAlignment - (Misc_VirtualSize % SectionAlignment) >= 0x12)
		break;
	}
	
	if(i == File_PE_s.pPEHeader->NumberOfSections) 
	{
		printf("节表空隙中无可用的空间，使用其他方式试试吧\n");
		free(*pImageBuffer);

		return;
	}

	dwMessageBoxA = (DWORD)MessageBoxA;
	PBYTE codeBegin=(PBYTE)((DWORD)*pImageBuffer + File_PE_s.pSectionHeader->VirtualAddress + Misc_VirtualSize);
	memcpy(codeBegin,shellcode,0x12);

	//修改E8//
    DWORD RelE8Addr=(DWORD)(dwMessageBoxA)- ((DWORD)codeBegin + 0xD - (DWORD)*pImageBuffer + File_PE_s.pOptionHeader->ImageBase);
	*(PDWORD)(codeBegin + 0x09)=RelE8Addr;

	//修改E9//
    DWORD RelE9Addr =  File_PE_s.pOptionHeader->ImageBase + File_PE_s.pOptionHeader->AddressOfEntryPoint -  ((DWORD)codeBegin + 0xD - (DWORD)*pImageBuffer + File_PE_s.pOptionHeader->ImageBase);
    *(PDWORD)(codeBegin + 0x0E) = RelE9Addr;
	
	//修改ope//
    File_PE_s.pOptionHeader->AddressOfEntryPoint=(DWORD)codeBegin - (DWORD)*pImageBuffer;

}
