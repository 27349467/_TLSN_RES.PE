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


	VOID AddSectionHeared(size_t SelKind = 0,size_t expand = 0x1000);	//新增加节//首先是在节与节表中间的空隙//  SelKind是扩展位，是为了兼容pFileBuffer与pImaeBuffer而存在的,默认0代表pFileBuffer//

	VOID AddSectionHearedDosToNt(size_t SelKind = 0,size_t expand = 0x1000);	//新增加节//增加节在Dos头与Nt头之间的垃圾缓冲区里//

	VOID ExpandSection(size_t expand = 0x1000);		//扩大节//

	VOID CombineSection();	//合并节//

	VOID PrintAllDataDirectory();	//编译输出所有的目录项//

	VOID PrintAllExport();			//打印输出导出表所有信息//

	VOID POINTER_BASE_RELOCATION();	//输出重定位表的信息//

	VOID Move_Export_Directory(size_t expand = 0x5000);	//移动导出表//

	VOID Correct_Base_Reloc(LPVOID pImageBuffer,size_t Size_of_Bechanged_Image);		//修复重定位表 PS:移动重定位表没写，懒//

	VOID ThreadProcCorrectTable(LPVOID lpParam);		//修复导入表//

	VOID PointAllImportData();	//打印导出表信息//

	VOID Point_Bound_Import_Dir();	//打印绑定导入表//

	VOID InjectImportTable();		//注入导入表//

	VOID PointYouWant(OUT struct _PE_S& _pe_s);			//提供一个平台，打印你想知道的信息//

	VOID TestPrintResourceICO();	//打印资源表//

	
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

	VOID Circulation_Of_Resource(PIMAGE_RESOURCE_DIRECTORY pResDirectorys,size_t floors);	//递归打印//

	DWORD RelFloors;	//资源表的层数//
};
