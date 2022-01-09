#include "Class_PE.h"
#include "Class_PE_USER.h"

_PE_User::_PE_User(TCHAR* GPath,LPSTR lpszFile) :_PE(GPath,lpszFile)		//父类构造函数的显式调用,不然父类会自动执行有参的构造函数//
{
	RelFloors = 0;
}

_PE_User::~_PE_User()
{
	cout<<"_PE_User析构"<<endl;
}

DWORD _PE_User::cmp(DWORD s1,DWORD s2)
{
	return s1 > s2 ? s1 : s2;
}


VOID _PE_User::AddSectionHeared(size_t SelKind,size_t expand )
{
	PVOID pImageBuffer = NULL;
	PVOID pNewBuffer = NULL;
	PVOID pFileBuffer=NULL;

	ReadPEFile(&pFileBuffer);

	if(SelKind)
	{
		CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);
	
		RelAddSectionHeader(&pImageBuffer,expand,SelKind);		
	}



	else
	{
		RelAddSectionHeader(&pFileBuffer,expand,SelKind);
	
		CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);		
	}
	

	CopyImageBufferToNewBuffer(pImageBuffer,&pNewBuffer);
	
	MemeryTOFile(pNewBuffer);
	

}


VOID _PE_User::RelAddSectionHeader(LPVOID* pImageBuffer,size_t expand,size_t SelKind)
{
	LPVOID pTempImageBuffer;
	DWORD space_nt_dos;	//
	PE_S PeTmp_s;	//直接使用 File_PE_s 也行，这里我多虑了//

	if(!SelKind)
	{
		pTempImageBuffer = malloc(lenFile + expand);
		memset(pTempImageBuffer,lenFile + expand,0);
		memcpy(pTempImageBuffer,*pImageBuffer,lenFile);
	}
	else
	{
		pTempImageBuffer = malloc(pOptHeaderSizeOfImage + expand);
		memset(pTempImageBuffer,pOptHeaderSizeOfImage + expand,0);
		memcpy(pTempImageBuffer,*pImageBuffer,pOptHeaderSizeOfImage);		
	}
	conBuffToAddr(PeTmp_s,pTempImageBuffer);

	space_nt_dos = PeTmp_s.pOptionHeader->SizeOfHeaders - sizeof(IMAGE_SECTION_HEADER) * PeTmp_s.pPEHeader->NumberOfSections -sizeof(IMAGE_NT_HEADERS32) - PeTmp_s.pDosHeader->e_lfanew;

	if(space_nt_dos < sizeof(IMAGE_SECTION_HEADER) * 2)
	{
		printf("空间不足！\n");
		printf("回车键退出\n");
		getchar();
		exit(0);
		return ;
		
	}

	//节表//
	memcpy((void*)((DWORD)pTempImageBuffer + PeTmp_s.pOptionHeader->SizeOfHeaders - space_nt_dos),(void*)((DWORD)pTempImageBuffer + PeTmp_s.pOptionHeader->SizeOfHeaders - space_nt_dos - sizeof(IMAGE_SECTION_HEADER)),sizeof(IMAGE_SECTION_HEADER));
	
	//先改名//
    for(DWORD u=0;u<8;u++)
    {
        (PeTmp_s.pSectionHeader+PeTmp_s.pPEHeader->NumberOfSections)->Name[u]=0x74;
    }
	
	PeTmp_s.pPEHeader->NumberOfSections+=1;

	PeTmp_s.pOptionHeader->SizeOfImage += expand;
	(PeTmp_s.pSectionHeader+PeTmp_s.pPEHeader->NumberOfSections - 1)->Misc.VirtualSize = expand;
	(PeTmp_s.pSectionHeader+PeTmp_s.pPEHeader->NumberOfSections - 1)->VirtualAddress = PeTmp_s.pOptionHeader->SizeOfImage-expand;
    (PeTmp_s.pSectionHeader+PeTmp_s.pPEHeader->NumberOfSections - 1)->SizeOfRawData = expand;
    (PeTmp_s.pSectionHeader+PeTmp_s.pPEHeader->NumberOfSections - 1)->PointerToRawData = (PeTmp_s.pSectionHeader + PeTmp_s.pPEHeader->NumberOfSections - 2)->SizeOfRawData + (PeTmp_s.pSectionHeader+PeTmp_s.pPEHeader->NumberOfSections - 2)->PointerToRawData;
    (PeTmp_s.pSectionHeader+PeTmp_s.pPEHeader->NumberOfSections - 1)->Characteristics=(PeTmp_s.pSectionHeader+PeTmp_s.pPEHeader->NumberOfSections - 2)->Characteristics;

	*pImageBuffer = pTempImageBuffer;
	//更新一下 File_PE_s //
	conBuffToAddr(File_PE_s,pTempImageBuffer);
	
	printf("新增节完成\n");
}


VOID _PE_User::AddSectionHearedDosToNt(size_t SelKind,size_t expand)
{
	PVOID pImageBuffer = NULL;
	PVOID pNewBuffer = NULL;
	PVOID pFileBuffer=NULL;

	ReadPEFile(&pFileBuffer);

 
	 if(SelKind)
	 {
			CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);

			RelAddSectionHearedDosToNt(&pImageBuffer,expand,SelKind);
	 }




	else
	{
		RelAddSectionHearedDosToNt(&pFileBuffer,expand,SelKind);
	
		CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);

	}



	
	CopyImageBufferToNewBuffer(pImageBuffer,&pNewBuffer);
	
	MemeryTOFile(pNewBuffer);

	printf("新增节完成\n");
}


VOID _PE_User::RelAddSectionHearedDosToNt(LPVOID *pImageBuffer,size_t expand,size_t SelKind)
{
	LPVOID pTempImageBuffer;
	PE_S PeTmp_s;
	DWORD space_sec_data;
	DWORD RelSizeOfHeader;	//不包含垃圾数据，对齐//

	if(!SelKind)
	{
		pTempImageBuffer = malloc(lenFile + expand);
		memset(pTempImageBuffer,lenFile + expand,0);
		memcpy(pTempImageBuffer,*pImageBuffer,lenFile);	
	}
	else
	{
		pTempImageBuffer = malloc(pOptHeaderSizeOfImage + expand);
		memset(pTempImageBuffer,pOptHeaderSizeOfImage + expand,0);
		memcpy(pTempImageBuffer,*pImageBuffer,pOptHeaderSizeOfImage);
	}


	conBuffToAddr(PeTmp_s,pTempImageBuffer);

	//移动数据，创造节表空间//
	space_sec_data =  PeTmp_s.pOptionHeader->SizeOfHeaders - sizeof(IMAGE_SECTION_HEADER) * PeTmp_s.pPEHeader->NumberOfSections - sizeof(IMAGE_NT_HEADERS32) - PeTmp_s.pDosHeader->e_lfanew;
	RelSizeOfHeader = sizeof(IMAGE_SECTION_HEADER) * PeTmp_s.pPEHeader->NumberOfSections + sizeof(IMAGE_NT_HEADERS32) + sizeof(IMAGE_DOS_HEADER);

	memcpy((void*)((DWORD)pTempImageBuffer + sizeof(IMAGE_DOS_HEADER)),(void*)((DWORD)pTempImageBuffer+PeTmp_s.pDosHeader->e_lfanew), PeTmp_s.pOptionHeader->SizeOfHeaders - space_sec_data - PeTmp_s.pDosHeader->e_lfanew);
	
	PeTmp_s.pDosHeader->e_lfanew = sizeof(IMAGE_DOS_HEADER);
	conBuffToAddr(PeTmp_s,pTempImageBuffer);//前面的数据都偏移了，这里一定要修复一下//
	
	memset((void*)((DWORD)pTempImageBuffer + RelSizeOfHeader ),0,PeTmp_s.pOptionHeader->SizeOfHeaders - RelSizeOfHeader); //我想了一下，这个新增节的方法为了增加这个节，压缩了垃圾缓冲区，但同时也可使用节表与SizeOfHeader直接的距离,所以，这种方法不如说是上一种方法的加强版//
	 
	//判断//
	if(PeTmp_s.pOptionHeader->SizeOfHeaders - RelSizeOfHeader < sizeof(IMAGE_SECTION_HEADER) * 2)
	{
		printf("压缩垃圾数据后，空间还是不够...\n");
		printf("按回车键退出\n");
		getchar();
		exit(0);
		free(pTempImageBuffer);
		free(*pImageBuffer);

		return ;
	}

	//移动数据后，在腾出的空间上复制出新的节表//
    memcpy((void*)((DWORD)pTempImageBuffer + RelSizeOfHeader ),(void*)((DWORD)pTempImageBuffer + RelSizeOfHeader - sizeof(IMAGE_SECTION_HEADER) ),sizeof(IMAGE_SECTION_HEADER));

    //改数据//
    PeTmp_s.pPEHeader->NumberOfSections +=1;

    for(int k=0;k<7;k++)
    {
        (PeTmp_s.pSectionHeader + PeTmp_s.pPEHeader->NumberOfSections - 1)->Name[k]=0x74;
    }

    PeTmp_s.pOptionHeader->SizeOfImage +=expand;
    (PeTmp_s.pSectionHeader + PeTmp_s.pPEHeader->NumberOfSections - 1)->Misc.VirtualSize = expand;
    (PeTmp_s.pSectionHeader + PeTmp_s.pPEHeader->NumberOfSections - 1)->VirtualAddress =  PeTmp_s.pOptionHeader->SizeOfImage - expand;
    (PeTmp_s.pSectionHeader + PeTmp_s.pPEHeader->NumberOfSections - 1)->SizeOfRawData = expand;
    (PeTmp_s.pSectionHeader + PeTmp_s.pPEHeader->NumberOfSections - 1)->PointerToRawData = (PeTmp_s.pSectionHeader + PeTmp_s.pPEHeader->NumberOfSections - 2)->SizeOfRawData + (PeTmp_s.pSectionHeader+PeTmp_s.pPEHeader->NumberOfSections - 2)->PointerToRawData;
    (PeTmp_s.pSectionHeader + PeTmp_s.pPEHeader->NumberOfSections - 1)->Characteristics=(PeTmp_s.pSectionHeader + PeTmp_s.pPEHeader->NumberOfSections - 2)->Characteristics;
	
    
	*pImageBuffer = pTempImageBuffer;
	//更新一下 File_PE_s //
	conBuffToAddr(File_PE_s,pTempImageBuffer);
	

    
}

VOID _PE_User::ExpandSection(size_t expand)
{
	PVOID pImageBuffer = NULL;
	PVOID pNewBuffer = NULL;
	PVOID pFileBuffer=NULL;

	ReadPEFile(&pFileBuffer);

	CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);
		
	RelExpandSection(&pImageBuffer,expand);

	CopyImageBufferToNewBuffer(pImageBuffer,&pNewBuffer);
	
	MemeryTOFile(pNewBuffer);
	
	printf("扩大节结束\n");
}




VOID _PE_User::RelExpandSection(LPVOID* pImageBuffer,size_t expand)
{
	LPVOID pTempImageBuffer;
	PE_S PeTmp_s;

	pTempImageBuffer = malloc(pOptHeaderSizeOfImage + expand);
	memset(pTempImageBuffer,pOptHeaderSizeOfImage + expand,0);
	memcpy(pTempImageBuffer,*pImageBuffer,pOptHeaderSizeOfImage);

	conBuffToAddr(PeTmp_s,pTempImageBuffer);

    (PeTmp_s.pSectionHeader + PeTmp_s.pPEHeader->NumberOfSections - 1)->Misc.VirtualSize += expand;
    (PeTmp_s.pSectionHeader + PeTmp_s.pPEHeader->NumberOfSections - 1)->SizeOfRawData += expand;
	PeTmp_s.pOptionHeader->SizeOfImage += expand;
	
	conBuffToAddr(File_PE_s,pTempImageBuffer);
	*pImageBuffer = pTempImageBuffer;


}

VOID _PE_User::CombineSection()
{
	PVOID pImageBuffer = NULL;
	PVOID pNewBuffer = NULL;
	PVOID pFileBuffer=NULL;

	ReadPEFile(&pFileBuffer);

	CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);
		
	RelCombineSection(&pImageBuffer);

	CopyImageBufferToNewBuffer(pImageBuffer,&pNewBuffer);
	
	MemeryTOFile(pNewBuffer);
	
	printf("合并节结束\n");
}


VOID _PE_User::RelCombineSection(LPVOID *pImageBuffer)
{
	LPVOID pTempImageBuffer;
	PE_S PeTmp_s;
	DWORD AllChara;
	
	AllChara = 0;
	pTempImageBuffer = malloc(pOptHeaderSizeOfImage);
	memset(pTempImageBuffer,pOptHeaderSizeOfImage,0);
	memcpy(pTempImageBuffer,*pImageBuffer,pOptHeaderSizeOfImage);

	conBuffToAddr(PeTmp_s,pTempImageBuffer);
	
	PeTmp_s.pSectionHeader->Misc.VirtualSize = cmp((PeTmp_s.pSectionHeader + PeTmp_s.pPEHeader->NumberOfSections - 1)->VirtualAddress + (PeTmp_s.pSectionHeader + PeTmp_s.pPEHeader->NumberOfSections - 1)->Misc.VirtualSize,(PeTmp_s.pSectionHeader + PeTmp_s.pPEHeader->NumberOfSections - 1)->VirtualAddress + (PeTmp_s.pSectionHeader + PeTmp_s.pPEHeader->NumberOfSections - 1)->SizeOfRawData) - PeTmp_s.pOptionHeader->SizeOfHeaders;
	PeTmp_s.pSectionHeader->SizeOfRawData = PeTmp_s.pSectionHeader->Misc.VirtualSize;

	for(int i = 0;i < PeTmp_s.pPEHeader->NumberOfSections;i++,(PeTmp_s.pSectionHeader)++) AllChara |= PeTmp_s.pSectionHeader->Characteristics;

	for(int j = 0;j < PeTmp_s.pPEHeader->NumberOfSections;j++) (PeTmp_s.pSectionHeader)--;
	
	PeTmp_s.pSectionHeader->Characteristics = AllChara;
	PeTmp_s.pPEHeader->NumberOfSections = 1;

	conBuffToAddr(File_PE_s,pTempImageBuffer);
	*pImageBuffer = pTempImageBuffer;


}


VOID _PE_User::PrintAllDataDirectory()
{
	PVOID pImageBuffer = NULL;
	PVOID pNewBuffer = NULL;
	PVOID pFileBuffer=NULL;

	ReadPEFile(&pFileBuffer);

	CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);
		
	RelPrintAllDataDirectory(pImageBuffer);

	CopyImageBufferToNewBuffer(pImageBuffer,&pNewBuffer);
	
	MemeryTOFile(pNewBuffer);
	
	printf("输出所有目录项\n");
}

VOID _PE_User::RelPrintAllDataDirectory(const LPVOID pImageBuffer)
{

    printf("导出表的映像地址为VirtualAdress0x0x%20x   大小size为0x%20x\n",File_PE_s.pDataDirectory[0].VirtualAddress,File_PE_s.pDataDirectory[0].Size);
    printf("导入表的映像地址为VirtualAdress0x%20x     大小size为0x%20x\n",File_PE_s.pDataDirectory[1].VirtualAddress,File_PE_s.pDataDirectory[1].Size);
    printf("资源表的映像地址为VirtualAdress0x%20x     大小size为0x%20x\n",File_PE_s.pDataDirectory[2].VirtualAddress,File_PE_s.pDataDirectory[2].Size);
    printf("异常信息表的映像地址为VirtualAdress0x%20x 大小size为0x%20x\n",File_PE_s.pDataDirectory[3].VirtualAddress,File_PE_s.pDataDirectory[3].Size);
    printf("安全证书表的映像地址为VirtualAdress0x%20x 大小size为0x%20x\n",File_PE_s.pDataDirectory[4].VirtualAddress,File_PE_s.pDataDirectory[4].Size);
    printf("重定位表的映像地址为VirtualAdress0x%20x   大小size为0x%20x\n",File_PE_s.pDataDirectory[5].VirtualAddress,File_PE_s.pDataDirectory[5].Size);
    printf("调试信息表的映像地址为VirtualAdress0x%20x 大小size为0x%20x\n",File_PE_s.pDataDirectory[6].VirtualAddress,File_PE_s.pDataDirectory[6].Size);
    printf("版权信息表的映像地址为VirtualAdress0x%20x 大小size为0x%20x\n",File_PE_s.pDataDirectory[7].VirtualAddress,File_PE_s.pDataDirectory[7].Size);
    printf("全局指针表的映像地址为VirtualAdress0x%20x 大小size为0x%20x\n",File_PE_s.pDataDirectory[8].VirtualAddress,File_PE_s.pDataDirectory[8].Size);
    printf("TLS表的映像地址为VirtualAdress0x%20x      大小size为0x%20x\n",File_PE_s.pDataDirectory[9].VirtualAddress,File_PE_s.pDataDirectory[9].Size);
    printf("加载配置表的映像地址为VirtualAdress0x%20x 大小size为0x%20x\n",File_PE_s.pDataDirectory[10].VirtualAddress,File_PE_s.pDataDirectory[10].Size);
    printf("绑定导入表的映像地址为VirtualAdress0x%20x 大小size为0x%20x\n",File_PE_s.pDataDirectory[11].VirtualAddress,File_PE_s.pDataDirectory[11].Size);
    printf("IAT表的映像地址为VirtualAdress0x%20x      大小size为0x%20x\n",File_PE_s.pDataDirectory[12].VirtualAddress,File_PE_s.pDataDirectory[12].Size);
    printf("延迟导入表的映像地址为VirtualAdress0x%20x 大小size为0x%20x\n",File_PE_s.pDataDirectory[13].VirtualAddress,File_PE_s.pDataDirectory[13].Size);
    printf("COM信息的映像地址为VirtualAdress0x%20x    大小size为0x%20x\n",File_PE_s.pDataDirectory[14].VirtualAddress,File_PE_s.pDataDirectory[14].Size);
    printf("未被使用表的映像地址为VirtualAdress0x%20x 大小size为0x%20x\n",File_PE_s.pDataDirectory[15].VirtualAddress,File_PE_s.pDataDirectory[15].Size);
}


VOID _PE_User::PrintAllExport()
{

	PVOID pFileBuffer=NULL;

	ReadPEFile(&pFileBuffer);
		
	RelPrintAllExport(pFileBuffer);

	free(pFileBuffer);
	printf("打印所有的导出表信息成功，但不知道为什么，导出函数的地址都是这一个固定的值\n");
}


VOID _PE_User::RelPrintAllExport(const LPVOID pFileBuffer)
{
	if(!File_PE_s.pExportDir->NumberOfFunctions)
	{
		printf("无导出表\n");
		getchar();
		exit(0);
	}

    printf("导出表      Characteristics值为：    %x\n",File_PE_s.pExportDir->Characteristics);
    printf("导出表      TimeDateStamp  值为：    %x\n",File_PE_s.pExportDir->TimeDateStamp);
    printf("导出表      MajorVersion   值为：    %x\n",File_PE_s.pExportDir->MajorVersion);
    printf("导出表      MinorVersion   值为：    %x\n",File_PE_s.pExportDir->MinorVersion);
    printf("导出表      Name           值为：    %x\n",File_PE_s.pExportDir->Name);
    printf("导出表      Base           值为：    %x\n",File_PE_s.pExportDir->Base);
    printf("导出表    NumberOfFunctions值为：    %x\n",File_PE_s.pExportDir->NumberOfFunctions);
    printf("导出表      NumberOfNames  值为：    %x\n",File_PE_s.pExportDir->NumberOfNames);
    printf("导出表   AddressOfFunctions值为：    %x\n",File_PE_s.pExportDir->AddressOfFunctions);
    printf("导出表      AddressOfNames 值为：    %x\n",File_PE_s.pExportDir->AddressOfNames);
    printf("导出表AddressOfNameOrdinals值为：    %x\n",File_PE_s.pExportDir->AddressOfNameOrdinals);
    printf("\n************************************** 导出函数信息 ********************************\n");

    LPDWORD AddressOfFunctions = (PDWORD)((DWORD)pFileBuffer + RvaToFileOffset(File_PE_s.pExportDir->AddressOfFunctions)); 
	LPDWORD AddressOfNames = (PDWORD)((DWORD)pFileBuffer + RvaToFileOffset(File_PE_s.pExportDir->AddressOfNames));
	LPWORD AddressOfNameOrdinals = (PWORD)((DWORD)pFileBuffer + RvaToFileOffset( File_PE_s.pExportDir->AddressOfNameOrdinals));

    for (int ii = 0;ii < File_PE_s.pExportDir->NumberOfNames;ii++)
    {
        DWORD test1 = *(AddressOfNames+ii);
        PBYTE test2  = (PBYTE)((DWORD)pFileBuffer +  RvaToFileOffset(test1));
		DWORD test3 = *(PDWORD)((DWORD)pFileBuffer +  RvaToFileOffset(*(AddressOfFunctions + ii) ) );
	//	DWORD test3 = *(AddressOfFunctions + ii);
		WORD test4 = *(AddressOfNameOrdinals+ii);

        printf("导出序号: %20x             函数名:  %s\n函数地址: %20x             RVA(序号): %x\n\n",test4, test2 ,test3,test1);//导出序号没有加base,寻找函数地址的时候也不用加base//
    }
   
}


VOID _PE_User::POINTER_BASE_RELOCATION()
{
	
	PVOID pFileBuffer=NULL;

	ReadPEFile(&pFileBuffer);
		
	RelPOINTER_BASE_RELOCATION(pFileBuffer);

	free(pFileBuffer);
	printf("打印重定位表信息结束\n");
}



VOID _PE_User::RelPOINTER_BASE_RELOCATION(IN LPVOID pFileBuffer)
{
	PWORD specificItem;
	int ans = 0;
	while(File_PE_s.pBaseReloc->SizeOfBlock && File_PE_s.pBaseReloc->VirtualAddress)
	{
		 cout<<"第"<<" "<<ans<<" "<<"个块"<<endl;
		 cout<<"***********************************************************************************************************"<<endl;
		
		printf("pBaseReloc->VirtualAddress :      %x\n",File_PE_s.pBaseReloc->VirtualAddress);
        printf("pBaseReloc->SizeOfBlock    :      %x\n",File_PE_s.pBaseReloc->SizeOfBlock);
        printf("NumberOfRelocAddress :            %x\n\n",(File_PE_s.pBaseReloc->SizeOfBlock - 8)/2);
		
		printf("the_RVA_of_RELOC(x)          type(3or!3)          FOA(x)         true_address(x)          \n");
		DWORD NumberOfRelocAddress = (File_PE_s.pBaseReloc->SizeOfBlock - 8) / 2;

		specificItem = (PWORD)((DWORD)File_PE_s.pBaseReloc + IMAGE_SIZEOF_BASE_RELOCATION);

		for(int i = NumberOfRelocAddress;i > 0; i-- , specificItem++)
		{
			printf("%-30x",((*specificItem) & 0x0fff) + File_PE_s.pBaseReloc->VirtualAddress);
            printf("%-21x",(*specificItem)>>12);
            printf("%-16x",RvaToFileOffset( ((*specificItem) & 0x0fff) + File_PE_s.pBaseReloc->VirtualAddress));
            printf("%-30x\n",*(PDWORD)((DWORD)pFileBuffer + RvaToFileOffset( ((*specificItem) & 0x0fff) + File_PE_s.pBaseReloc->VirtualAddress) ));// 
			//printf("%-30s\n",(CHAR*)*(PDWORD)((DWORD)pFileBuffer + RvaToFileOffset( ((*specificItem) & 0x0fff) + File_PE_s.pBaseReloc->VirtualAddress) ));
		}
		cout<<endl<<endl;
		ans++;
		File_PE_s.pBaseReloc = (PIMAGE_BASE_RELOCATION)( (DWORD)File_PE_s.pBaseReloc + File_PE_s.pBaseReloc->SizeOfBlock );
	}
}

/************************************************************/
/*															*/
/*	第一步：在DLL中新增一个节，并返回新增后的FOA			*/				
					
/*	第二步：复制AddressOfFunctions 							*/
					
/*		长度：4*NumberOfFunctions							*/
					
/*	第三步：复制AddressOfNameOrdinals						*/
					
/*		长度：NumberOfNames*2								*/
					
/*	第四步：复制AddressOfNames								*/
					
/*		长度：NumberOfNames*4								*/
					
/*	第五步：复制所有的函数名								*/
					
/*		长度不确定，复制时直接修复AddressOfNames			*/
					
/*	第六步：复杂IMAGE_EXPORT_DIRECTORY结构					*/
					
					
/*	第七步：修复IMAGE_EXPORT_DIRECTORY结构中的				*/
					
/*		AddressOfFunctions									*/
					
/*		AddressOfNameOrdinals								*/			
					
/*		AddressOfNames										*/			
					
/*	第八步：修复目录项中的值，指向新的IMAGE_EXPORT_DIRECTORY*/			
/*															*/
/************************************************************/

VOID _PE_User::Move_Export_Directory(size_t expand)
{
	PVOID pImageBuffer = NULL;
	PVOID pNewBuffer = NULL;
	PVOID pFileBuffer=NULL;

	ReadPEFile(&pFileBuffer);	
	
	RelAddSectionHeader(&pFileBuffer,expand,0);

	RelMove_Export_Directory(&pFileBuffer);

	CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);

	CopyImageBufferToNewBuffer(pImageBuffer,&pNewBuffer);
	
	MemeryTOFile(pNewBuffer);
	
	printf("移动导出表完成\n");
}

VOID _PE_User::RelMove_Export_Directory(LPVOID *pFileBuffer)
{
	LPVOID pTempFileBuffer = NULL;
	PE_S PeTmp_s;

	pTempFileBuffer = malloc(lenFile);
	memset(pTempFileBuffer,lenFile,0);
	memcpy(pTempFileBuffer,*pFileBuffer,lenFile);

	conBuffToAddr(PeTmp_s,pTempFileBuffer);
	if(!File_PE_s.pExportDir->NumberOfFunctions)
	{
		printf("无导出表\n");
		getchar();
		exit(0);
	}

    memcpy((void*)((DWORD)pTempFileBuffer + (PeTmp_s.pSectionHeader + PeTmp_s.pPEHeader->NumberOfSections - 1)->PointerToRawData),(void*)((DWORD)pTempFileBuffer + RvaToFileOffset(PeTmp_s.pExportDir->AddressOfFunctions)),4 * (PeTmp_s.pExportDir->NumberOfFunctions));

    memcpy((void*)((DWORD)pTempFileBuffer + (PeTmp_s.pSectionHeader + PeTmp_s.pPEHeader->NumberOfSections - 1)->PointerToRawData + 4*(PeTmp_s.pExportDir->NumberOfFunctions)),(void*)((DWORD)pTempFileBuffer + RvaToFileOffset(PeTmp_s.pExportDir->AddressOfNameOrdinals)),2 * (PeTmp_s.pExportDir->NumberOfNames));

    memcpy((void*)((DWORD)pTempFileBuffer + (PeTmp_s.pSectionHeader + PeTmp_s.pPEHeader->NumberOfSections - 1)->PointerToRawData + 4*(PeTmp_s.pExportDir->NumberOfFunctions) + 2 * (PeTmp_s.pExportDir->NumberOfNames)),(void*)((DWORD)pTempFileBuffer + RvaToFileOffset(PeTmp_s.pExportDir->AddressOfNames)),4 * (PeTmp_s.pExportDir->NumberOfNames));

	
    DWORD size_of_name[0x1000] = {0};

    LPDWORD AddressOfNames = (PDWORD)((DWORD)pTempFileBuffer + RvaToFileOffset(PeTmp_s.pExportDir->AddressOfNames));
	DWORD AddrExport = 4 * (PeTmp_s.pExportDir->NumberOfNames) + 2 * (PeTmp_s.pExportDir->NumberOfNames) + 4 * (PeTmp_s.pExportDir->NumberOfFunctions);
	
    for(int i =0;i<PeTmp_s.pExportDir->NumberOfNames;i++)
    {
        size_of_name[i] = strlen((char*)((DWORD)pTempFileBuffer + RvaToFileOffset(*(AddressOfNames+i)))) + 1;//加一是为了补 '\0'结束符 //

        memcpy((void*)((DWORD)pTempFileBuffer + (PeTmp_s.pSectionHeader + PeTmp_s.pPEHeader->NumberOfSections - 1)->PointerToRawData + 4*(PeTmp_s.pExportDir->NumberOfFunctions) + 2 * (PeTmp_s.pExportDir->NumberOfNames) + 4 * (PeTmp_s.pExportDir->NumberOfNames) + size_of_name[i]),(void*)((char*)((DWORD)pTempFileBuffer + *(AddressOfNames+i))),size_of_name[i]);
        *(PDWORD)((DWORD)pTempFileBuffer + PeTmp_s.pExportDir->AddressOfNames + i*4) =  (PeTmp_s.pSectionHeader + PeTmp_s.pPEHeader->NumberOfSections - 1)->PointerToRawData + 4*(PeTmp_s.pExportDir->NumberOfFunctions) + 2 * (PeTmp_s.pExportDir->NumberOfNames) + 4 * (PeTmp_s.pExportDir->NumberOfNames) + size_of_name[i];
		
		AddrExport = AddrExport + size_of_name[i];
    }

	PeTmp_s.pExportDir->AddressOfFunctions = (PeTmp_s.pSectionHeader + PeTmp_s.pPEHeader->NumberOfSections - 1)->VirtualAddress;

    PeTmp_s.pExportDir->AddressOfNameOrdinals = (PeTmp_s.pSectionHeader + PeTmp_s.pPEHeader->NumberOfSections - 1)->VirtualAddress + 4*(PeTmp_s.pExportDir->NumberOfFunctions);

    PeTmp_s.pExportDir->AddressOfNames = (PeTmp_s.pSectionHeader + PeTmp_s.pPEHeader->NumberOfSections - 1)->VirtualAddress + 4*(PeTmp_s.pExportDir->NumberOfFunctions) + 2 * (PeTmp_s.pExportDir->NumberOfNames);

	*pFileBuffer = pTempFileBuffer;
	conBuffToAddr(File_PE_s,pTempFileBuffer);
}


//这里没有过多采用类的形式,因为这个函数很重要，我想以后能更方便的引用这个函数//
VOID _PE_User::Correct_Base_Reloc(LPVOID pImageBuffer,size_t Size_of_Bechanged_Image)
{
	
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    DWORD Size_Of_Base_Reloc = 0;
	if(!pImageBuffer)
    {
        free(pImageBuffer);
        return ;
    }
	if(*(PWORD)(pImageBuffer)!=IMAGE_DOS_SIGNATURE)
	{
	    free(pImageBuffer);
        return ;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer+pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader+4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader+pPEHeader->SizeOfOptionalHeader);
	if(*((PDWORD)((DWORD)pImageBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志\n");
		free(pImageBuffer);
		return ;
	}
	PIMAGE_DATA_DIRECTORY pDataDirectory =NULL;
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)((DWORD)pSectionHeader-16*sizeof(IMAGE_DATA_DIRECTORY));
	PIMAGE_BASE_RELOCATION pBaseReloc =NULL;
	pBaseReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pImageBuffer + pDataDirectory[5].VirtualAddress);
	//修改ImageBase//
	pOptionHeader->ImageBase = pOptionHeader->ImageBase + Size_of_Bechanged_Image;

	PWORD guodu = NULL;
	DWORD RVA_MEMBER = 0;int ans = 0;
	DWORD FOA_MEMBER = 0;
	DWORD bns = 0;
	DWORD cns = 0;
	while(pBaseReloc->SizeOfBlock!=0 &&pBaseReloc->VirtualAddress!=0)
    {
		
        guodu = (PWORD)((DWORD)pBaseReloc + IMAGE_SIZEOF_BASE_RELOCATION);
		if(pBaseReloc->SizeOfBlock<8)
		{
			pBaseReloc = (PIMAGE_BASE_RELOCATION)( (DWORD)pBaseReloc + pBaseReloc->SizeOfBlock );
		continue;
		}
         DWORD NumberOfRelocAddress = (pBaseReloc->SizeOfBlock - 8)/2;
        for(DWORD i = NumberOfRelocAddress;i>0;i--,guodu++)
        {

            DWORD qwq = *guodu>>12;
             if(qwq !=0)
             {
                RVA_MEMBER =(DWORD)(*guodu & 0xFFF) + (DWORD)pBaseReloc->VirtualAddress;//出错原因，偏移出错，原因还是数据类型出错，以后自己要是拿不准，建议全加括号//
                FOA_MEMBER = RVA_MEMBER;
				DWORD test = *(PDWORD)((DWORD)pImageBuffer+(DWORD)FOA_MEMBER);
                *(PDWORD)((DWORD)pImageBuffer+(DWORD)FOA_MEMBER) = *(PDWORD)((DWORD)pImageBuffer+(DWORD)FOA_MEMBER) + Size_of_Bechanged_Image;
             }

        }
        pBaseReloc = (PIMAGE_BASE_RELOCATION)( (DWORD)pBaseReloc + pBaseReloc->SizeOfBlock );

    }
	return ;

}


VOID _PE_User::PointAllImportData()
{
	PVOID pFileBuffer=NULL;

	ReadPEFile(&pFileBuffer);
		
	RelPointAllImportData(pFileBuffer);

	free(pFileBuffer);
	printf("打印导出表信息结束\n");
}

VOID _PE_User::RelPointAllImportData(LPVOID pFileBuffer)
{
	PIMAGE_IMPORT_BY_NAME pImExortByName = NULL;
    PIMAGE_IMPORT_BY_NAME pImExortByNameOri = NULL;

	int i = 0;
	DWORD ExportXuHao = 0;
	while(*(PDWORD)File_PE_s.pImportDescri)
    {
        printf("\n\n%s\n\n",(PDWORD)((DWORD)pFileBuffer + RvaToFileOffset(File_PE_s.pImportDescri->Name)));
       // printf("%s\n\n",RvaToFileOffset(pFileBuffer,pImportDescri->Name) + )
        cout<<"时间戳：\t"<<File_PE_s.pImportDescri->TimeDateStamp<<endl;
        cout<<"dall名字的文件偏移: \t"<<File_PE_s.pImportDescri->Name<<endl;
        while((*(PDWORD)((DWORD)pFileBuffer + 4*i +RvaToFileOffset(File_PE_s.pImportDescri->OriginalFirstThunk)))!=0)//第一张表的值//
        {
            cout<<"***********************************"<<"INT表"<<"************************************"<<endl<<endl<<endl;
            //判断最高位//
            DWORD qaz = (*(PDWORD)((DWORD)pFileBuffer + 4*i + RvaToFileOffset(File_PE_s.pImportDescri->OriginalFirstThunk)))&(0x80000000);
            if(qaz!=0)
            {
               ExportXuHao = (*(PDWORD)((DWORD)pFileBuffer + 4*i + RvaToFileOffset(File_PE_s.pImportDescri->OriginalFirstThunk)))&(0x7FFFFFFF);
               cout<<"最高位为 1 "<<endl;
               cout<<"OriginalOriginalFirstThunk的第"<<i<<"个值为 : "<<hex<<"\t"<<*(PDWORD)((DWORD)pFileBuffer + 4*i + RvaToFileOffset(File_PE_s.pImportDescri->OriginalFirstThunk))<<"\t\t"<<"函数序号为：\t"<<ExportXuHao<<endl;
               i++;
            }

            if(qaz==0)
            {
                    cout<<"最高位为 0 "<<endl;
                    pImExortByNameOri = (PIMAGE_IMPORT_BY_NAME)((DWORD)pFileBuffer + RvaToFileOffset(*(PDWORD)((DWORD)pFileBuffer + 4*i + RvaToFileOffset(File_PE_s.pImportDescri->OriginalFirstThunk))));
                    cout<<"OriginalFirstThunk的第"<<i<<"个值为 : "<<"\t"<<hex<<*(PDWORD)((DWORD)pFileBuffer + 4*i + RvaToFileOffset(File_PE_s.pImportDescri->OriginalFirstThunk))<<"\t\t"<<"下表与名字：\t"<<pImExortByNameOri->Hint<<"-"; 
					printf("%s\n",pImExortByNameOri->Name);
                    i++;
            }
        }

        i=0;

        while((*(PDWORD)((DWORD)pFileBuffer + 4*i + RvaToFileOffset(File_PE_s.pImportDescri->FirstThunk)))!=0)//第一张表的值//
        {
            cout<<"***********************************"<<"IAT表"<<"************************************"<<endl<<endl<<endl;
            //判断最高位//
            DWORD qwe = (*(PDWORD)((DWORD)pFileBuffer + 4*i + RvaToFileOffset(File_PE_s.pImportDescri->FirstThunk)))&0x80000000;
            if(qwe!=0)
            {
				//最高位为1，去掉最高位，就是导出序号//
               ExportXuHao = (*(PDWORD)((DWORD)pFileBuffer + 4*i + RvaToFileOffset(File_PE_s.pImportDescri->FirstThunk)))&0x7FFFFFFF;
               cout<<"FirstThunk的第"<<i<<"个值为 : "<<hex<<"\t"<<*(PDWORD)((DWORD)pFileBuffer + 4*i + RvaToFileOffset(File_PE_s.pImportDescri->FirstThunk))<<"\t\t"<<"函数序号为：\t"<<ExportXuHao<<endl;
               i++;
            }
            else
			if(qwe==0)
            {
                    pImExortByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)pFileBuffer + RvaToFileOffset(*(PDWORD)((DWORD)pFileBuffer + 4*i + RvaToFileOffset(File_PE_s.pImportDescri->FirstThunk))));
                    cout<<"FirstThunk的第"<<i<<"个值为 : "<<"\t"<<hex<<*(PDWORD)((DWORD)pFileBuffer + 4*i + RvaToFileOffset(File_PE_s.pImportDescri->FirstThunk))<<"\t\t"<<"下表与名字：\t"<<pImExortByName->Hint<<"-"; 
					printf("%s\n",pImExortByName->Name);
                    i++;
            }

        }
        i = 0;
        File_PE_s.pImportDescri = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)File_PE_s.pImportDescri + sizeof(IMAGE_IMPORT_DESCRIPTOR));
    }
}


VOID _PE_User::Point_Bound_Import_Dir()
{
	PVOID pFileBuffer=NULL;

	ReadPEFile(&pFileBuffer);
		
	RelPoint_Bound_Import_Dir(pFileBuffer);

	free(pFileBuffer);
	printf("打印导出表信息结束\n");
}


VOID _PE_User::RelPoint_Bound_Import_Dir(LPVOID pFileBuffer)
{
	PIMAGE_BOUND_FORWARDER_REF pBoundForRef = NULL;
    
	
	int ans =0;
	if(!File_PE_s.pDataDirectory[11].VirtualAddress)
	{
		printf("无绑定导入表\n");
		
		return ;
	}
	else
	{
		 while(File_PE_s.pBoundImportDir)
		 {
				pBoundForRef =(PIMAGE_BOUND_FORWARDER_REF)((DWORD)File_PE_s.pBoundImportDir + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR));
			    cout<<"第\t\t"<<ans<<"\t\t组dall的绑定导入表数据*\n"<<endl;
                WORD num = File_PE_s.pBoundImportDir->NumberOfModuleForwarderRefs;
				
				
                cout<<"*"<<"TimeDateStamp ："<<File_PE_s.pBoundImportDir->TimeDateStamp<<"\t"<<" "<<endl;
                cout<<"NumberOfModuleForwarderRefs-> "<<num<<endl;
                printf("Dall名称为：\t\t%s\t\t",(char*)((DWORD)pFileBuffer + RvaToFileOffset(File_PE_s.pBoundImportDir->OffsetModuleName + File_PE_s.pDataDirectory[11].VirtualAddress)));
                cout<<"\nIMAGE_BOUND_FORWARDER_REF\n"<<endl;
                for(int i=0;i<num;i++,pBoundForRef++)
                {
                    cout<<"*"<<"TimeDateStamp ："<<pBoundForRef->TimeDateStamp<<"\t"<<" "<<endl;
                    cout<<"Reserved : "<<pBoundForRef->Reserved<<endl;
                    printf("*Dall名：/t/t%s/t/t",(char*)((DWORD)pFileBuffer + RvaToFileOffset(pBoundForRef->OffsetModuleName + File_PE_s.pDataDirectory[11].VirtualAddress)));
                }

                File_PE_s.pBoundImportDir = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD)File_PE_s.pBoundImportDir + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR) + num * sizeof(IMAGE_BOUND_FORWARDER_REF));
   
				ans++;
		 }	
	
	}

}

/************************************************************************/
/*																		*/
/*第一步：																*/			
			
/*根据目录项(第二个就是导入表)得到导入表信息：							*/			


/*第二步：																*/


/*新增一个导入表需要的空间：											*/					
					
/*A:20字节																*/					
					
/*B:16字节																*/					
					
/*C:取决于DLL名串的长度+1												*/					
					
/*D:取决于函数名的长度+1+2												*/					
					
					
/*判断哪一个节的空白区 > Size(原导入表的大小) + 20 + A + B + C + D		*/					
					
/*如果空间不够：可以将C/D 存储在其他的空白区							*/					
					
/*也就是，只要空白区 > Size + 0x20就可以了								*/					
					
/*如果仍然不够，就需要扩大最后一个节，或者新增节来解决.					*/					
					
					
/*第三步：																*/					
					
/*将原导入表全部Copy到空白区											*/					
					
/*第四步：																*/					
					
/*在新的导入表后面，追加一个导入表.										*/					
					
/*第五步：																*/					
					
/*追加8个字节的INT表  8个字节的IAT表									*/					
					
/*第六步：																*/					
					
/*追加一个IMAGE_IMPORT_BY_NAME 结构，前2个字节是0 后面是函数名称字符串	*/					
					
/*第七步：																*/					
					
/*将IMAGE_IMPORT_BY_NAME结构的RVA赋值给INT和IAT表中的第一项				*/				
					
/*第八步：																*/					
					
/*分配空间存储DLL名称字符串 并将该字符串的RVA赋值给Name属性				*/					
					
/*第九步：																*/					
					
/*修正IMAGE_DATA_DIRECTORY结构的VirtualAddress和Size					*/					
/*																		*/
/************************************************************************/
VOID _PE_User::InjectImportTable()
{
	PVOID pImageBuffer = NULL;
	PVOID pNewBuffer = NULL;
	PVOID pFileBuffer=NULL;

	ReadPEFile(&pFileBuffer);

	RelInjectImportTable(&pFileBuffer);

	CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);

	CopyImageBufferToNewBuffer(pImageBuffer,&pNewBuffer);
	
	MemeryTOFile(pNewBuffer);
	
	printf("注入导入表完成\n");
}

VOID _PE_User::RelInjectImportTable(LPVOID* pFileBuffer,size_t expand)
{
		DWORD UseAddr;
		DWORD SizeOfImport;
		PIMAGE_IMPORT_DESCRIPTOR pImportDescr;	//添加表的位置//
		PIMAGE_IMPORT_BY_NAME pImportByName;
	
		RelAddSectionHeader(pFileBuffer, expand);	//这里我直接使用的新增节//
		
		SizeOfImport = File_PE_s.pDataDirectory[1].Size - sizeof(IMAGE_IMPORT_DESCRIPTOR);
			
		memcpy( (void*)((DWORD)*pFileBuffer + (File_PE_s.pSectionHeader +  File_PE_s.pPEHeader->NumberOfSections - 1)->PointerToRawData), (void *)((DWORD)*pFileBuffer + RvaToFileOffset(File_PE_s.pDataDirectory[1].VirtualAddress)) , SizeOfImport);//1
		memcpy( (void*)((DWORD)*pFileBuffer + SizeOfImport + (File_PE_s.pSectionHeader +  File_PE_s.pPEHeader->NumberOfSections - 1)->PointerToRawData), (void *)((DWORD)*pFileBuffer + RvaToFileOffset(File_PE_s.pDataDirectory[1].VirtualAddress)) ,sizeof(IMAGE_IMPORT_DESCRIPTOR) );
		memset( (void*)((DWORD)*pFileBuffer + SizeOfImport + sizeof(IMAGE_IMPORT_DESCRIPTOR) + (File_PE_s.pSectionHeader +  File_PE_s.pPEHeader->NumberOfSections - 1)->PointerToRawData)  , 0 , sizeof(IMAGE_IMPORT_DESCRIPTOR));

		pImportDescr = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)*pFileBuffer + SizeOfImport + (File_PE_s.pSectionHeader +  File_PE_s.pPEHeader->NumberOfSections - 1)->PointerToRawData);
		pImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)pImportDescr + 2 * sizeof(IMAGE_IMPORT_DESCRIPTOR) + 4 * sizeof(IMAGE_THUNK_DATA32));
		
		*(PDWORD)((DWORD)pImportDescr + 2*sizeof(IMAGE_IMPORT_DESCRIPTOR)) = SizeOfImport + (File_PE_s.pSectionHeader +  File_PE_s.pPEHeader->NumberOfSections - 1)->VirtualAddress + 2 * sizeof(IMAGE_IMPORT_DESCRIPTOR) + 4 * sizeof(IMAGE_THUNK_DATA32);	//INT// 保存的地址是RVA//
		*(PDWORD)((DWORD)pImportDescr + 2*sizeof(IMAGE_IMPORT_DESCRIPTOR) + sizeof(IMAGE_THUNK_DATA32)) = 0x0;
		*(PDWORD)((DWORD)pImportDescr + 2*sizeof(IMAGE_IMPORT_DESCRIPTOR) + sizeof(IMAGE_THUNK_DATA32) + sizeof(IMAGE_THUNK_DATA32)) = SizeOfImport + (File_PE_s.pSectionHeader +  File_PE_s.pPEHeader->NumberOfSections - 1)->VirtualAddress +2 * sizeof(IMAGE_IMPORT_DESCRIPTOR) + 4 * sizeof(IMAGE_THUNK_DATA32);  //IAT//
		*(PDWORD)((DWORD)pImportDescr + 2*sizeof(IMAGE_IMPORT_DESCRIPTOR) + sizeof(IMAGE_THUNK_DATA32) + sizeof(IMAGE_THUNK_DATA32) + sizeof(IMAGE_THUNK_DATA32)) = 0x0;
		
		pImportByName->Hint = 0x666;
		strcpy((char *)&pImportByName->Name[0] ,"_TLSN_Load_PE");
		pImportByName->Name[strlen("_TLSN_Load_PE")] = '\0';

		strcpy((char *)((DWORD)pImportByName + strlen("_TLSN_Load_PE") + 0x2 + 0x1),"_TLSN.dll");  //0x1是'\0'//
		pImportDescr->Name = SizeOfImport +  2*sizeof(IMAGE_IMPORT_DESCRIPTOR) + 4 * sizeof(IMAGE_THUNK_DATA32) + (File_PE_s.pSectionHeader +  File_PE_s.pPEHeader->NumberOfSections - 1)->VirtualAddress + strlen("_TLSN_Load_PE") + 0x2 + 0x1;
		pImportDescr->OriginalFirstThunk = (File_PE_s.pSectionHeader +  File_PE_s.pPEHeader->NumberOfSections - 1)->VirtualAddress + SizeOfImport +  2*sizeof(IMAGE_IMPORT_DESCRIPTOR);
		pImportDescr->FirstThunk = (File_PE_s.pSectionHeader +  File_PE_s.pPEHeader->NumberOfSections - 1)->VirtualAddress + SizeOfImport +  2*sizeof(IMAGE_IMPORT_DESCRIPTOR) + 2 * sizeof(IMAGE_THUNK_DATA32);
		

		File_PE_s.pDataDirectory[1].VirtualAddress = (File_PE_s.pSectionHeader +  File_PE_s.pPEHeader->NumberOfSections - 1)->VirtualAddress;
		File_PE_s.pDataDirectory[1].Size = SizeOfImport + 2*sizeof(IMAGE_IMPORT_DESCRIPTOR);
		
		conBuffToAddr(File_PE_s,*pFileBuffer);
		UseAddr = 0;
		UseAddr =  SizeOfImport + 2*sizeof(IMAGE_IMPORT_DESCRIPTOR) + sizeof(IMAGE_THUNK_DATA32) * 4 + strlen("_TLSN_Load_PE") + 0x2 + 0x1 + strlen("_TLSN.dll") + 0x1;
		printf("一共需要 %x 个字节\n",UseAddr);
}



VOID _PE_User::ThreadProcCorrectTable(LPVOID lpParam) {   //修复导入表是内存写入的时候用到的，跟修复重定位表一样很重要,这里直接把我内存写入时的代码拿下来了...//
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pIMPORT_DESCRIPTOR = NULL;
	PIMAGE_IMPORT_BY_NAME pImage_IMPORT_BY_NAME = NULL;
	
	PDWORD OriginalFirstThunk = NULL;
	PDWORD FirstThunk = NULL;

	PIMAGE_THUNK_DATA pImageThunkData = NULL;
	
	DWORD Original = 0;
	
	pDosHeader = (PIMAGE_DOS_HEADER)lpParam;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)lpParam + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);

	//每个导入表的相关信息占20个字节
	pIMPORT_DESCRIPTOR = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)lpParam + pOptionHeader->DataDirectory[1].VirtualAddress);

	DWORD dwFuncAddr = 0;
	HMODULE hModule;

	while (pIMPORT_DESCRIPTOR->FirstThunk && pIMPORT_DESCRIPTOR->OriginalFirstThunk) {
		hModule = LoadLibrary((PCHAR)((DWORD)lpParam + (DWORD)pIMPORT_DESCRIPTOR->Name));
		// FirstThunk 指向 IMAGE_THUNK_DATA 结构数组
		OriginalFirstThunk = (PDWORD)((DWORD)lpParam + (DWORD)pIMPORT_DESCRIPTOR->OriginalFirstThunk);
		FirstThunk = (PDWORD)((DWORD)lpParam + (DWORD)pIMPORT_DESCRIPTOR->FirstThunk);
		
		while (*OriginalFirstThunk) {
			if (*OriginalFirstThunk & 0x80000000) {
				//高位为1 则 除去最高位的值就是函数的导出序号
				Original = *OriginalFirstThunk & 0xFFF;	//去除最高标志位。
				dwFuncAddr = (DWORD)GetProcAddress(hModule, (PCHAR)Original);
			}
			else
			{		// MessageBox(0,0,0,0);
				//高位不为1 则指向IMAGE_IMPORT_BY_NAME;
				pImage_IMPORT_BY_NAME = (PIMAGE_IMPORT_BY_NAME)((DWORD)lpParam + *OriginalFirstThunk);
				dwFuncAddr = (DWORD)GetProcAddress(hModule, (PCHAR)pImage_IMPORT_BY_NAME->Name);
			}
			*FirstThunk = dwFuncAddr;
			OriginalFirstThunk++;
		}
		
		pIMPORT_DESCRIPTOR++;
	}
	return ;
}




VOID _PE_User::TestPrintResourceICO()
{
	PVOID pFileBuffer=NULL;

	ReadPEFile(&pFileBuffer);
		
	RelTestPrintResourceICO(pFileBuffer);

	free(pFileBuffer);
	printf("打印导出表信息结束\n");
}

VOID _PE_User::RelTestPrintResourceICO(LPVOID pFileBuffer)
{
	Circulation_Of_Resource(File_PE_s.pResDirectory,0);
}

	
VOID _PE_User::Circulation_Of_Resource(PIMAGE_RESOURCE_DIRECTORY pResDirectorys,size_t floors)
{	
	PIMAGE_DATA_DIRECTORY pImageDataDiry;	
	PIMAGE_RESOURCE_DIR_STRING_U pResDirUniString;
	DWORD NumOfFirEntry = pResDirectorys->NumberOfNamedEntries + pResDirectorys->NumberOfIdEntries;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pResDirectorys + sizeof(IMAGE_RESOURCE_DIRECTORY));
	floors++;
	for(size_t i = 0;i<NumOfFirEntry;i++)
	{
		if(floors == 1)
		{
			printf("\n***************************************%x***************************************\n\n",RelFloors++);
		}
		if(floors == 2)
		printf("\t");
		if(floors == 3)
			printf("\t\t");
		printf("第 %x 层\n",floors);
	
		if( (pResDirEntry + i)->NameIsString == 0)
		{
			
			if(floors == 1)
			printf("序号：%x\n",(pResDirEntry + i)->Id);
			
			if(floors == 2)
			printf("\t资源编号：%x\n",(pResDirEntry + i)->Id);
		
			if(floors == 3)
			printf("\t\t代码页：%x\n",(pResDirEntry + i)->Id);
		}
		else
		if( (pResDirEntry + i)->NameIsString == 1)
		{
			printf("名称：");
			pResDirUniString = (PIMAGE_RESOURCE_DIR_STRING_U)( (DWORD)File_PE_s.pResDirectory + (pResDirEntry + i)->NameOffset);
			for(int j = 0;j<pResDirUniString->Length;j++)
			{
				printf("%wc",pResDirUniString->NameString[j]);
			}
			printf("\n");
		}
		
		if( (pResDirEntry + i)->DataIsDirectory == 1 )
		{
			pResDirectorys = (PIMAGE_RESOURCE_DIRECTORY)((pResDirEntry + i)->OffsetToDirectory + (DWORD)File_PE_s.pResDirectory);
			Circulation_Of_Resource(pResDirectorys,floors);
		}
		else
		{
			pImageDataDiry = (PIMAGE_DATA_DIRECTORY)((pResDirEntry + i)->OffsetToDirectory + (DWORD)File_PE_s.pResDirectory);
			printf("\t\t\t数据项：\n");
			printf("\t\t\tVirtualAddress: %x   Size:%x\n",pImageDataDiry->VirtualAddress,pImageDataDiry->Size);

		}

	}
}




VOID _PE_User::PointYouWant(OUT struct _PE_S& _pe_s)
{
	PVOID pFileBuffer=NULL;
	ReadPEFile(&pFileBuffer);

	conBuffToAddr(_pe_s,pFileBuffer);
}


