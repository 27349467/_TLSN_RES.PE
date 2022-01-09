#pragma once
#ifndef _CLASS_PE_USER_H_
#define _CLASS_PE_USER_H_

#endif

#include "Class_PE.h"


class _PE_User: public _PE
{
public:
	_PE_User(TCHAR* GPath,LPSTR lpszFile);

	~_PE_User();


	VOID AddSectionHeared(size_t SelKind = 0,size_t expand = 0x1000);	//�����ӽ�//�������ڽ���ڱ��м�Ŀ�϶//  SelKind����չλ����Ϊ�˼���pFileBuffer��pImaeBuffer�����ڵ�,Ĭ��0����pFileBuffer//

	VOID AddSectionHearedDosToNt(size_t SelKind = 0,size_t expand = 0x1000);	//�����ӽ�//���ӽ���Dosͷ��Ntͷ֮���������������//

	VOID ExpandSection(size_t expand = 0x1000);		//�����//

	VOID CombineSection();	//�ϲ���//

	VOID PrintAllDataDirectory();	//����������е�Ŀ¼��//

	VOID PrintAllExport();			//��ӡ���������������Ϣ//

	VOID POINTER_BASE_RELOCATION();	//����ض�λ�����Ϣ//

	VOID Move_Export_Directory(size_t expand = 0x5000);	//�ƶ�������//

	VOID Correct_Base_Reloc(LPVOID pImageBuffer,size_t Size_of_Bechanged_Image);		//�޸��ض�λ�� PS:�ƶ��ض�λ��ûд����//

	VOID ThreadProcCorrectTable(LPVOID lpParam);		//�޸������//

	VOID PointAllImportData();	//��ӡ��������Ϣ//

	VOID Point_Bound_Import_Dir();	//��ӡ�󶨵����//

	VOID InjectImportTable();		//ע�뵼���//

	VOID PointYouWant(OUT struct _PE_S& _pe_s);			//�ṩһ��ƽ̨����ӡ����֪������Ϣ//

	VOID TestPrintResourceICO();	//��ӡ��Դ��//

	
protected:
	
	DWORD cmp(DWORD s1,DWORD s2);

	VOID RelAddSectionHeader(LPVOID* pImageBuffer,size_t expand,size_t SelKind = 0);

	VOID RelAddSectionHearedDosToNt(LPVOID* pImageBuffer,size_t expand,size_t SelKind = 0);

	VOID RelExpandSection(LPVOID* pImageBuffer,size_t expand);

	VOID RelCombineSection(LPVOID* pImageBuffer);

	VOID RelPrintAllDataDirectory(const LPVOID pImageBuffer);

	VOID RelPrintAllExport(const LPVOID pFileBuffer);
	
	VOID RelPOINTER_BASE_RELOCATION(IN LPVOID pFileBuffer);
	
	VOID RelMove_Export_Directory(LPVOID *pFileBuffer);

	VOID RelPointAllImportData(LPVOID pFileBuffer);
	
	VOID RelPoint_Bound_Import_Dir(LPVOID pFileBuffer);

	VOID RelInjectImportTable(LPVOID* pFileBuffer,size_t expand = 0x1000);

	VOID RelTestPrintResourceICO(LPVOID pFileBuffer);

	VOID Circulation_Of_Resource(PIMAGE_RESOURCE_DIRECTORY pResDirectorys,size_t floors);	//�ݹ��ӡ//

	DWORD RelFloors;	//��Դ��Ĳ���//
};
