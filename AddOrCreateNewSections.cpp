#include "Class_PE.h"
#include "Class_PE_USER.h"

_PE_User::_PE_User(TCHAR* GPath,LPSTR lpszFile) :_PE(GPath,lpszFile)		//���๹�캯������ʽ����,��Ȼ������Զ�ִ���вεĹ��캯��//
{
	RelFloors = 0;
}

_PE_User::~_PE_User()
{
	cout<<"_PE_User����"<<endl;
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
	PE_S PeTmp_s;	//ֱ��ʹ�� File_PE_s Ҳ�У������Ҷ�����//

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
		printf("�ռ䲻�㣡\n");
		printf("�س����˳�\n");
		getchar();
		exit(0);
		return ;
		
	}

	//�ڱ�//
	memcpy((void*)((DWORD)pTempImageBuffer + PeTmp_s.pOptionHeader->SizeOfHeaders - space_nt_dos),(void*)((DWORD)pTempImageBuffer + PeTmp_s.pOptionHeader->SizeOfHeaders - space_nt_dos - sizeof(IMAGE_SECTION_HEADER)),sizeof(IMAGE_SECTION_HEADER));
	
	//�ȸ���//
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
	//����һ�� File_PE_s //
	conBuffToAddr(File_PE_s,pTempImageBuffer);
	
	printf("���������\n");
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

	printf("���������\n");
}


VOID _PE_User::RelAddSectionHearedDosToNt(LPVOID *pImageBuffer,size_t expand,size_t SelKind)
{
	LPVOID pTempImageBuffer;
	PE_S PeTmp_s;
	DWORD space_sec_data;
	DWORD RelSizeOfHeader;	//�������������ݣ�����//

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

	//�ƶ����ݣ�����ڱ�ռ�//
	space_sec_data =  PeTmp_s.pOptionHeader->SizeOfHeaders - sizeof(IMAGE_SECTION_HEADER) * PeTmp_s.pPEHeader->NumberOfSections - sizeof(IMAGE_NT_HEADERS32) - PeTmp_s.pDosHeader->e_lfanew;
	RelSizeOfHeader = sizeof(IMAGE_SECTION_HEADER) * PeTmp_s.pPEHeader->NumberOfSections + sizeof(IMAGE_NT_HEADERS32) + sizeof(IMAGE_DOS_HEADER);

	memcpy((void*)((DWORD)pTempImageBuffer + sizeof(IMAGE_DOS_HEADER)),(void*)((DWORD)pTempImageBuffer+PeTmp_s.pDosHeader->e_lfanew), PeTmp_s.pOptionHeader->SizeOfHeaders - space_sec_data - PeTmp_s.pDosHeader->e_lfanew);
	
	PeTmp_s.pDosHeader->e_lfanew = sizeof(IMAGE_DOS_HEADER);
	conBuffToAddr(PeTmp_s,pTempImageBuffer);//ǰ������ݶ�ƫ���ˣ�����һ��Ҫ�޸�һ��//
	
	memset((void*)((DWORD)pTempImageBuffer + RelSizeOfHeader ),0,PeTmp_s.pOptionHeader->SizeOfHeaders - RelSizeOfHeader); //������һ�£���������ڵķ���Ϊ����������ڣ�ѹ������������������ͬʱҲ��ʹ�ýڱ���SizeOfHeaderֱ�ӵľ���,���ԣ����ַ�������˵����һ�ַ����ļ�ǿ��//
	 
	//�ж�//
	if(PeTmp_s.pOptionHeader->SizeOfHeaders - RelSizeOfHeader < sizeof(IMAGE_SECTION_HEADER) * 2)
	{
		printf("ѹ���������ݺ󣬿ռ仹�ǲ���...\n");
		printf("���س����˳�\n");
		getchar();
		exit(0);
		free(pTempImageBuffer);
		free(*pImageBuffer);

		return ;
	}

	//�ƶ����ݺ����ڳ��Ŀռ��ϸ��Ƴ��µĽڱ�//
    memcpy((void*)((DWORD)pTempImageBuffer + RelSizeOfHeader ),(void*)((DWORD)pTempImageBuffer + RelSizeOfHeader - sizeof(IMAGE_SECTION_HEADER) ),sizeof(IMAGE_SECTION_HEADER));

    //������//
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
	//����һ�� File_PE_s //
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
	
	printf("����ڽ���\n");
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
	
	printf("�ϲ��ڽ���\n");
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
	
	printf("�������Ŀ¼��\n");
}

VOID _PE_User::RelPrintAllDataDirectory(const LPVOID pImageBuffer)
{

    printf("�������ӳ���ַΪVirtualAdress0x0x%20x   ��СsizeΪ0x%20x\n",File_PE_s.pDataDirectory[0].VirtualAddress,File_PE_s.pDataDirectory[0].Size);
    printf("������ӳ���ַΪVirtualAdress0x%20x     ��СsizeΪ0x%20x\n",File_PE_s.pDataDirectory[1].VirtualAddress,File_PE_s.pDataDirectory[1].Size);
    printf("��Դ���ӳ���ַΪVirtualAdress0x%20x     ��СsizeΪ0x%20x\n",File_PE_s.pDataDirectory[2].VirtualAddress,File_PE_s.pDataDirectory[2].Size);
    printf("�쳣��Ϣ���ӳ���ַΪVirtualAdress0x%20x ��СsizeΪ0x%20x\n",File_PE_s.pDataDirectory[3].VirtualAddress,File_PE_s.pDataDirectory[3].Size);
    printf("��ȫ֤����ӳ���ַΪVirtualAdress0x%20x ��СsizeΪ0x%20x\n",File_PE_s.pDataDirectory[4].VirtualAddress,File_PE_s.pDataDirectory[4].Size);
    printf("�ض�λ���ӳ���ַΪVirtualAdress0x%20x   ��СsizeΪ0x%20x\n",File_PE_s.pDataDirectory[5].VirtualAddress,File_PE_s.pDataDirectory[5].Size);
    printf("������Ϣ���ӳ���ַΪVirtualAdress0x%20x ��СsizeΪ0x%20x\n",File_PE_s.pDataDirectory[6].VirtualAddress,File_PE_s.pDataDirectory[6].Size);
    printf("��Ȩ��Ϣ���ӳ���ַΪVirtualAdress0x%20x ��СsizeΪ0x%20x\n",File_PE_s.pDataDirectory[7].VirtualAddress,File_PE_s.pDataDirectory[7].Size);
    printf("ȫ��ָ����ӳ���ַΪVirtualAdress0x%20x ��СsizeΪ0x%20x\n",File_PE_s.pDataDirectory[8].VirtualAddress,File_PE_s.pDataDirectory[8].Size);
    printf("TLS���ӳ���ַΪVirtualAdress0x%20x      ��СsizeΪ0x%20x\n",File_PE_s.pDataDirectory[9].VirtualAddress,File_PE_s.pDataDirectory[9].Size);
    printf("�������ñ��ӳ���ַΪVirtualAdress0x%20x ��СsizeΪ0x%20x\n",File_PE_s.pDataDirectory[10].VirtualAddress,File_PE_s.pDataDirectory[10].Size);
    printf("�󶨵�����ӳ���ַΪVirtualAdress0x%20x ��СsizeΪ0x%20x\n",File_PE_s.pDataDirectory[11].VirtualAddress,File_PE_s.pDataDirectory[11].Size);
    printf("IAT���ӳ���ַΪVirtualAdress0x%20x      ��СsizeΪ0x%20x\n",File_PE_s.pDataDirectory[12].VirtualAddress,File_PE_s.pDataDirectory[12].Size);
    printf("�ӳٵ�����ӳ���ַΪVirtualAdress0x%20x ��СsizeΪ0x%20x\n",File_PE_s.pDataDirectory[13].VirtualAddress,File_PE_s.pDataDirectory[13].Size);
    printf("COM��Ϣ��ӳ���ַΪVirtualAdress0x%20x    ��СsizeΪ0x%20x\n",File_PE_s.pDataDirectory[14].VirtualAddress,File_PE_s.pDataDirectory[14].Size);
    printf("δ��ʹ�ñ��ӳ���ַΪVirtualAdress0x%20x ��СsizeΪ0x%20x\n",File_PE_s.pDataDirectory[15].VirtualAddress,File_PE_s.pDataDirectory[15].Size);
}


VOID _PE_User::PrintAllExport()
{

	PVOID pFileBuffer=NULL;

	ReadPEFile(&pFileBuffer);
		
	RelPrintAllExport(pFileBuffer);

	free(pFileBuffer);
	printf("��ӡ���еĵ�������Ϣ�ɹ�������֪��Ϊʲô�����������ĵ�ַ������һ���̶���ֵ\n");
}


VOID _PE_User::RelPrintAllExport(const LPVOID pFileBuffer)
{
	if(!File_PE_s.pExportDir->NumberOfFunctions)
	{
		printf("�޵�����\n");
		getchar();
		exit(0);
	}

    printf("������      CharacteristicsֵΪ��    %x\n",File_PE_s.pExportDir->Characteristics);
    printf("������      TimeDateStamp  ֵΪ��    %x\n",File_PE_s.pExportDir->TimeDateStamp);
    printf("������      MajorVersion   ֵΪ��    %x\n",File_PE_s.pExportDir->MajorVersion);
    printf("������      MinorVersion   ֵΪ��    %x\n",File_PE_s.pExportDir->MinorVersion);
    printf("������      Name           ֵΪ��    %x\n",File_PE_s.pExportDir->Name);
    printf("������      Base           ֵΪ��    %x\n",File_PE_s.pExportDir->Base);
    printf("������    NumberOfFunctionsֵΪ��    %x\n",File_PE_s.pExportDir->NumberOfFunctions);
    printf("������      NumberOfNames  ֵΪ��    %x\n",File_PE_s.pExportDir->NumberOfNames);
    printf("������   AddressOfFunctionsֵΪ��    %x\n",File_PE_s.pExportDir->AddressOfFunctions);
    printf("������      AddressOfNames ֵΪ��    %x\n",File_PE_s.pExportDir->AddressOfNames);
    printf("������AddressOfNameOrdinalsֵΪ��    %x\n",File_PE_s.pExportDir->AddressOfNameOrdinals);
    printf("\n************************************** ����������Ϣ ********************************\n");

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

        printf("�������: %20x             ������:  %s\n������ַ: %20x             RVA(���): %x\n\n",test4, test2 ,test3,test1);//�������û�м�base,Ѱ�Һ�����ַ��ʱ��Ҳ���ü�base//
    }
   
}


VOID _PE_User::POINTER_BASE_RELOCATION()
{
	
	PVOID pFileBuffer=NULL;

	ReadPEFile(&pFileBuffer);
		
	RelPOINTER_BASE_RELOCATION(pFileBuffer);

	free(pFileBuffer);
	printf("��ӡ�ض�λ����Ϣ����\n");
}



VOID _PE_User::RelPOINTER_BASE_RELOCATION(IN LPVOID pFileBuffer)
{
	PWORD specificItem;
	int ans = 0;
	while(File_PE_s.pBaseReloc->SizeOfBlock && File_PE_s.pBaseReloc->VirtualAddress)
	{
		 cout<<"��"<<" "<<ans<<" "<<"����"<<endl;
		 cout<<"***********************************************************************************************************"<<endl;
		
		printf("pBaseReloc->VirtualAddress :      %x\n",File_PE_s.pBaseReloc->VirtualAddress);
        printf("pBaseReloc->SizeOfBlock    :      %x\n",File_PE_s.pBaseReloc->SizeOfBlock);
        printf("NumberOfRelocAddress :            %x\n\n",(File_PE_s.pBaseReloc->SizeOfBlock - 8)/2);
		if((File_PE_s.pBaseReloc->SizeOfBlock - 8) > 0x7fffffff || File_PE_s.pBaseReloc->SizeOfBlock >= 0x400) 
		{
			File_PE_s.pBaseReloc = (PIMAGE_BASE_RELOCATION)( (DWORD)File_PE_s.pBaseReloc + File_PE_s.pBaseReloc->SizeOfBlock );
			ans++;
			printf("�ض�λ������\n");
			continue;
		}
		
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
/*	��һ������DLL������һ���ڣ��������������FOA			*/				
					
/*	�ڶ���������AddressOfFunctions 							*/
					
/*		���ȣ�4*NumberOfFunctions							*/
					
/*	������������AddressOfNameOrdinals						*/
					
/*		���ȣ�NumberOfNames*2								*/
					
/*	���Ĳ�������AddressOfNames								*/
					
/*		���ȣ�NumberOfNames*4								*/
					
/*	���岽���������еĺ�����								*/
					
/*		���Ȳ�ȷ��������ʱֱ���޸�AddressOfNames			*/
					
/*	������������IMAGE_EXPORT_DIRECTORY�ṹ					*/
					
					
/*	���߲����޸�IMAGE_EXPORT_DIRECTORY�ṹ�е�				*/
					
/*		AddressOfFunctions									*/
					
/*		AddressOfNameOrdinals								*/			
					
/*		AddressOfNames										*/			
					
/*	�ڰ˲����޸�Ŀ¼���е�ֵ��ָ���µ�IMAGE_EXPORT_DIRECTORY*/			
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
	
	printf("�ƶ����������\n");
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
		printf("�޵�����\n");
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
        size_of_name[i] = strlen((char*)((DWORD)pTempFileBuffer + RvaToFileOffset(*(AddressOfNames+i)))) + 1;//��һ��Ϊ�˲� '\0'������ //

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


//����û�й�����������ʽ,��Ϊ�����������Ҫ�������Ժ��ܸ�����������������//
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
		printf("������Ч��PE��־\n");
		free(pImageBuffer);
		return ;
	}
	PIMAGE_DATA_DIRECTORY pDataDirectory =NULL;
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)((DWORD)pSectionHeader-16*sizeof(IMAGE_DATA_DIRECTORY));
	PIMAGE_BASE_RELOCATION pBaseReloc =NULL;
	pBaseReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pImageBuffer + pDataDirectory[5].VirtualAddress);
	//�޸�ImageBase//
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
                RVA_MEMBER =(DWORD)(*guodu & 0xFFF) + (DWORD)pBaseReloc->VirtualAddress;//����ԭ��ƫ�Ƴ���ԭ�����������ͳ����Ժ��Լ�Ҫ���ò�׼������ȫ������//
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
	printf("��ӡ��������Ϣ����\n");
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
        cout<<"ʱ�����\t"<<File_PE_s.pImportDescri->TimeDateStamp<<endl;
        cout<<"dall���ֵ��ļ�ƫ��: \t"<<File_PE_s.pImportDescri->Name<<endl;
        while((*(PDWORD)((DWORD)pFileBuffer + 4*i +RvaToFileOffset(File_PE_s.pImportDescri->OriginalFirstThunk)))!=0)//��һ�ű��ֵ//
        {
            cout<<"***********************************"<<"INT��"<<"************************************"<<endl<<endl<<endl;
            //�ж����λ//
            DWORD qaz = (*(PDWORD)((DWORD)pFileBuffer + 4*i + RvaToFileOffset(File_PE_s.pImportDescri->OriginalFirstThunk)))&(0x80000000);
            if(qaz!=0)
            {
               ExportXuHao = (*(PDWORD)((DWORD)pFileBuffer + 4*i + RvaToFileOffset(File_PE_s.pImportDescri->OriginalFirstThunk)))&(0x7FFFFFFF);
               cout<<"���λΪ 1 "<<endl;
               cout<<"OriginalOriginalFirstThunk�ĵ�"<<i<<"��ֵΪ : "<<hex<<"\t"<<*(PDWORD)((DWORD)pFileBuffer + 4*i + RvaToFileOffset(File_PE_s.pImportDescri->OriginalFirstThunk))<<"\t\t"<<"�������Ϊ��\t"<<ExportXuHao<<endl;
               i++;
            }

            if(qaz==0)
            {
                    cout<<"���λΪ 0 "<<endl;
                    pImExortByNameOri = (PIMAGE_IMPORT_BY_NAME)((DWORD)pFileBuffer + RvaToFileOffset(*(PDWORD)((DWORD)pFileBuffer + 4*i + RvaToFileOffset(File_PE_s.pImportDescri->OriginalFirstThunk))));
                    cout<<"OriginalFirstThunk�ĵ�"<<i<<"��ֵΪ : "<<"\t"<<hex<<*(PDWORD)((DWORD)pFileBuffer + 4*i + RvaToFileOffset(File_PE_s.pImportDescri->OriginalFirstThunk))<<"\t\t"<<"�±������֣�\t"<<pImExortByNameOri->Hint<<"-"; 
					printf("%s\n",pImExortByNameOri->Name);
                    i++;
            }
        }

        i=0;

        while((*(PDWORD)((DWORD)pFileBuffer + 4*i + RvaToFileOffset(File_PE_s.pImportDescri->FirstThunk)))!=0)//��һ�ű��ֵ//
        {
            cout<<"***********************************"<<"IAT��"<<"************************************"<<endl<<endl<<endl;
            //�ж����λ//
            DWORD qwe = (*(PDWORD)((DWORD)pFileBuffer + 4*i + RvaToFileOffset(File_PE_s.pImportDescri->FirstThunk)))&0x80000000;
            if(qwe!=0)
            {
				//���λΪ1��ȥ�����λ�����ǵ������//
               ExportXuHao = (*(PDWORD)((DWORD)pFileBuffer + 4*i + RvaToFileOffset(File_PE_s.pImportDescri->FirstThunk)))&0x7FFFFFFF;
               cout<<"FirstThunk�ĵ�"<<i<<"��ֵΪ : "<<hex<<"\t"<<*(PDWORD)((DWORD)pFileBuffer + 4*i + RvaToFileOffset(File_PE_s.pImportDescri->FirstThunk))<<"\t\t"<<"�������Ϊ��\t"<<ExportXuHao<<endl;
               i++;
            }
            else
			if(qwe==0)
            {
                    pImExortByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)pFileBuffer + RvaToFileOffset(*(PDWORD)((DWORD)pFileBuffer + 4*i + RvaToFileOffset(File_PE_s.pImportDescri->FirstThunk))));
                    cout<<"FirstThunk�ĵ�"<<i<<"��ֵΪ : "<<"\t"<<hex<<*(PDWORD)((DWORD)pFileBuffer + 4*i + RvaToFileOffset(File_PE_s.pImportDescri->FirstThunk))<<"\t\t"<<"�±������֣�\t"<<pImExortByName->Hint<<"-"; 
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
	printf("��ӡ��������Ϣ����\n");
}


VOID _PE_User::RelPoint_Bound_Import_Dir(LPVOID pFileBuffer)//��һ����뻹û�е��ԣ���Ϊ�һ�û�ҵ����а󶨵������ļ�
{
	PIMAGE_BOUND_FORWARDER_REF pBoundForRef = NULL;
   
	
	int ans =0;
	if(!File_PE_s.pDataDirectory[11].VirtualAddress)
	{
		printf("�ް󶨵����\n");
		
		return ;
	}
	else
	{
		 while(File_PE_s.pBoundImportDir)
		 {
				pBoundForRef =(PIMAGE_BOUND_FORWARDER_REF)((DWORD)File_PE_s.pBoundImportDir + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR));
			    cout<<"��\t\t"<<ans<<"\t\t��dall�İ󶨵��������*\n"<<endl;
                WORD num = File_PE_s.pBoundImportDir->NumberOfModuleForwarderRefs;
				
				
                cout<<"*"<<"TimeDateStamp ��"<<File_PE_s.pBoundImportDir->TimeDateStamp<<"\t"<<" "<<endl;
                cout<<"NumberOfModuleForwarderRefs-> "<<num<<endl;
                printf("Dall����Ϊ��\t\t%s\t\t",(char*)((DWORD)pFileBuffer + RvaToFileOffset(File_PE_s.pBoundImportDir->OffsetModuleName + File_PE_s.pDataDirectory[11].VirtualAddress)));
                cout<<"\nIMAGE_BOUND_FORWARDER_REF\n"<<endl;
                for(int i=0;i<num;i++,pBoundForRef++)
                {
                    cout<<"*"<<"TimeDateStamp ��"<<pBoundForRef->TimeDateStamp<<"\t"<<" "<<endl;
                    cout<<"Reserved : "<<pBoundForRef->Reserved<<endl;
                    printf("*Dall����/t/t%s/t/t",(char*)((DWORD)pFileBuffer + RvaToFileOffset(pBoundForRef->OffsetModuleName + File_PE_s.pDataDirectory[11].VirtualAddress)));
                }

                File_PE_s.pBoundImportDir = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD)File_PE_s.pBoundImportDir + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR) + num * sizeof(IMAGE_BOUND_FORWARDER_REF));
   
				ans++;
		 }	
	
	}
	cout<<"��һ����뻹û�е��ԣ���Ϊ�һ�û�ҵ����а󶨵������ļ�"<<endl;

}

/************************************************************************/
/*																		*/
/*��һ����																*/			
			
/*����Ŀ¼��(�ڶ������ǵ����)�õ��������Ϣ��							*/			


/*�ڶ�����																*/


/*����һ���������Ҫ�Ŀռ䣺											*/					
					
/*A:20�ֽ�																*/					
					
/*B:16�ֽ�																*/					
					
/*C:ȡ����DLL�����ĳ���+1												*/					
					
/*D:ȡ���ں������ĳ���+1+2												*/					
					
					
/*�ж���һ���ڵĿհ��� > Size(ԭ�����Ĵ�С) + 20 + A + B + C + D		*/					
					
/*����ռ䲻�������Խ�C/D �洢�������Ŀհ���							*/					
					
/*Ҳ���ǣ�ֻҪ�հ��� > Size + 0x20�Ϳ�����								*/					
					
/*�����Ȼ����������Ҫ�������һ���ڣ����������������.					*/					
					
					
/*��������																*/					
					
/*��ԭ�����ȫ��Copy���հ���											*/					
					
/*���Ĳ���																*/					
					
/*���µĵ������棬׷��һ�������.										*/					
					
/*���岽��																*/					
					
/*׷��8���ֽڵ�INT��  8���ֽڵ�IAT��									*/					
					
/*��������																*/					
					
/*׷��һ��IMAGE_IMPORT_BY_NAME �ṹ��ǰ2���ֽ���0 �����Ǻ��������ַ���	*/					
					
/*���߲���																*/					
					
/*��IMAGE_IMPORT_BY_NAME�ṹ��RVA��ֵ��INT��IAT���еĵ�һ��				*/				
					
/*�ڰ˲���																*/					
					
/*����ռ�洢DLL�����ַ��� �������ַ�����RVA��ֵ��Name����				*/					
					
/*�ھŲ���																*/					
					
/*����IMAGE_DATA_DIRECTORY�ṹ��VirtualAddress��Size					*/					
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
	
	printf("ע�뵼������\n");
}

VOID _PE_User::RelInjectImportTable(LPVOID* pFileBuffer,size_t expand)
{
		DWORD UseAddr;
		DWORD SizeOfImport;
		PIMAGE_IMPORT_DESCRIPTOR pImportDescr;	//��ӱ��λ��//
		PIMAGE_IMPORT_BY_NAME pImportByName;
	
		RelAddSectionHeader(pFileBuffer, expand);	//������ֱ��ʹ�õ�������//
		
		SizeOfImport = File_PE_s.pDataDirectory[1].Size - sizeof(IMAGE_IMPORT_DESCRIPTOR);
			
		memcpy( (void*)((DWORD)*pFileBuffer + (File_PE_s.pSectionHeader +  File_PE_s.pPEHeader->NumberOfSections - 1)->PointerToRawData), (void *)((DWORD)*pFileBuffer + RvaToFileOffset(File_PE_s.pDataDirectory[1].VirtualAddress)) , SizeOfImport);//1
		memcpy( (void*)((DWORD)*pFileBuffer + SizeOfImport + (File_PE_s.pSectionHeader +  File_PE_s.pPEHeader->NumberOfSections - 1)->PointerToRawData), (void *)((DWORD)*pFileBuffer + RvaToFileOffset(File_PE_s.pDataDirectory[1].VirtualAddress)) ,sizeof(IMAGE_IMPORT_DESCRIPTOR) );
		memset( (void*)((DWORD)*pFileBuffer + SizeOfImport + sizeof(IMAGE_IMPORT_DESCRIPTOR) + (File_PE_s.pSectionHeader +  File_PE_s.pPEHeader->NumberOfSections - 1)->PointerToRawData)  , 0 , sizeof(IMAGE_IMPORT_DESCRIPTOR));

		pImportDescr = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)*pFileBuffer + SizeOfImport + (File_PE_s.pSectionHeader +  File_PE_s.pPEHeader->NumberOfSections - 1)->PointerToRawData);
		pImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)pImportDescr + 2 * sizeof(IMAGE_IMPORT_DESCRIPTOR) + 4 * sizeof(IMAGE_THUNK_DATA32));
		
		*(PDWORD)((DWORD)pImportDescr + 2*sizeof(IMAGE_IMPORT_DESCRIPTOR)) = SizeOfImport + (File_PE_s.pSectionHeader +  File_PE_s.pPEHeader->NumberOfSections - 1)->VirtualAddress + 2 * sizeof(IMAGE_IMPORT_DESCRIPTOR) + 4 * sizeof(IMAGE_THUNK_DATA32);	//INT// ����ĵ�ַ��RVA//
		*(PDWORD)((DWORD)pImportDescr + 2*sizeof(IMAGE_IMPORT_DESCRIPTOR) + sizeof(IMAGE_THUNK_DATA32)) = 0x0;
		*(PDWORD)((DWORD)pImportDescr + 2*sizeof(IMAGE_IMPORT_DESCRIPTOR) + sizeof(IMAGE_THUNK_DATA32) + sizeof(IMAGE_THUNK_DATA32)) = SizeOfImport + (File_PE_s.pSectionHeader +  File_PE_s.pPEHeader->NumberOfSections - 1)->VirtualAddress +2 * sizeof(IMAGE_IMPORT_DESCRIPTOR) + 4 * sizeof(IMAGE_THUNK_DATA32);  //IAT//
		*(PDWORD)((DWORD)pImportDescr + 2*sizeof(IMAGE_IMPORT_DESCRIPTOR) + sizeof(IMAGE_THUNK_DATA32) + sizeof(IMAGE_THUNK_DATA32) + sizeof(IMAGE_THUNK_DATA32)) = 0x0;
		
		pImportByName->Hint = 0x666;
		strcpy((char *)&pImportByName->Name[0] ,"_TLSN_Load_PE");
		pImportByName->Name[strlen("_TLSN_Load_PE")] = '\0';

		strcpy((char *)((DWORD)pImportByName + strlen("_TLSN_Load_PE") + 0x2 + 0x1),"_TLSN.dll");  //0x1��'\0'//
		pImportDescr->Name = SizeOfImport +  2*sizeof(IMAGE_IMPORT_DESCRIPTOR) + 4 * sizeof(IMAGE_THUNK_DATA32) + (File_PE_s.pSectionHeader +  File_PE_s.pPEHeader->NumberOfSections - 1)->VirtualAddress + strlen("_TLSN_Load_PE") + 0x2 + 0x1;
		pImportDescr->OriginalFirstThunk = (File_PE_s.pSectionHeader +  File_PE_s.pPEHeader->NumberOfSections - 1)->VirtualAddress + SizeOfImport +  2*sizeof(IMAGE_IMPORT_DESCRIPTOR);
		pImportDescr->FirstThunk = (File_PE_s.pSectionHeader +  File_PE_s.pPEHeader->NumberOfSections - 1)->VirtualAddress + SizeOfImport +  2*sizeof(IMAGE_IMPORT_DESCRIPTOR) + 2 * sizeof(IMAGE_THUNK_DATA32);
		

		File_PE_s.pDataDirectory[1].VirtualAddress = (File_PE_s.pSectionHeader +  File_PE_s.pPEHeader->NumberOfSections - 1)->VirtualAddress;
		File_PE_s.pDataDirectory[1].Size = SizeOfImport + 2*sizeof(IMAGE_IMPORT_DESCRIPTOR);
		
		conBuffToAddr(File_PE_s,*pFileBuffer);
		UseAddr = 0;
		UseAddr =  SizeOfImport + 2*sizeof(IMAGE_IMPORT_DESCRIPTOR) + sizeof(IMAGE_THUNK_DATA32) * 4 + strlen("_TLSN_Load_PE") + 0x2 + 0x1 + strlen("_TLSN.dll") + 0x1;
		printf("һ����Ҫ %x ���ֽ�\n",UseAddr);
}



VOID _PE_User::ThreadProcCorrectTable(LPVOID lpParam) {   //�޸���������ڴ�д���ʱ���õ��ģ����޸��ض�λ��һ������Ҫ,����ֱ�Ӱ����ڴ�д��ʱ�Ĵ�����������...//
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

	//ÿ�������������Ϣռ20���ֽ�
	pIMPORT_DESCRIPTOR = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)lpParam + pOptionHeader->DataDirectory[1].VirtualAddress);

	DWORD dwFuncAddr = 0;
	HMODULE hModule;

	while (pIMPORT_DESCRIPTOR->FirstThunk && pIMPORT_DESCRIPTOR->OriginalFirstThunk) {
		hModule = LoadLibrary((PCHAR)((DWORD)lpParam + (DWORD)pIMPORT_DESCRIPTOR->Name));
		// FirstThunk ָ�� IMAGE_THUNK_DATA �ṹ����
		OriginalFirstThunk = (PDWORD)((DWORD)lpParam + (DWORD)pIMPORT_DESCRIPTOR->OriginalFirstThunk);
		FirstThunk = (PDWORD)((DWORD)lpParam + (DWORD)pIMPORT_DESCRIPTOR->FirstThunk);
		
		while (*OriginalFirstThunk) {
			if (*OriginalFirstThunk & 0x80000000) {
				//��λΪ1 �� ��ȥ���λ��ֵ���Ǻ����ĵ������
				Original = *OriginalFirstThunk & 0xFFF;	//ȥ����߱�־λ��
				dwFuncAddr = (DWORD)GetProcAddress(hModule, (PCHAR)Original);
			}
			else
			{		// MessageBox(0,0,0,0);
				//��λ��Ϊ1 ��ָ��IMAGE_IMPORT_BY_NAME;
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
		
	RelTestPrintResourceICO(File_PE_s.pResDirectory,0);
	
	free(pFileBuffer);
	printf("��ӡ��������Ϣ����\n");
}

	
VOID _PE_User::RelTestPrintResourceICO(PIMAGE_RESOURCE_DIRECTORY pResDirectorys,size_t floors)
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
		printf("�� %x ��\n",floors);
	
		if( (pResDirEntry + i)->NameIsString == 0)
		{
			
			if(floors == 1)
			printf("��ţ�%x\n",(pResDirEntry + i)->Id);
			
			if(floors == 2)
			printf("\t��Դ��ţ�%x\n",(pResDirEntry + i)->Id);
		
			if(floors == 3)
			printf("\t\t����ҳ��%x\n",(pResDirEntry + i)->Id);
		}
		else
		if( (pResDirEntry + i)->NameIsString == 1)
		{
			printf("���ƣ�");
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
			RelTestPrintResourceICO(pResDirectorys,floors);
		}
		else
		{
			pImageDataDiry = (PIMAGE_DATA_DIRECTORY)((pResDirEntry + i)->OffsetToDirectory + (DWORD)File_PE_s.pResDirectory);
			printf("\t\t\t�����\n");
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


