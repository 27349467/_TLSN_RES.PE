// _PE.cpp : Defines the entry point for the console application.
//


/********************/
/*					*/
/*��������vc++		*/
/*����ߣ�_TLSN		*/
/*���ʱ�䣺2022/1/9*/
/*					*/
/********************/

/********************************************/
/*											*/
/*������c++�����ʽ���е�PE����				*/
/*��Щ����һ����_PE_User�� �������������	*/
/*�����Ĺ�����ͷ�ļ��ﶼ�ж���				*/
/*											*/
/********************************************/



#include "stdafx.h"
#include "Class_PE.h"
#include "Class_PE_USER.h"


#define PATH TEXT("C:\\WINDOWS\\system32\\notepad.exe")
#define lpszPATH TEXT("D:\\PE����.exe")
 //C:\\WINDOWS\\system32\\nshwfp.dll		C:\\WINDOWS\\system32\\nsi.dll		D:\\��ˮ����\\tools\\IPMsgCHS206\\IPMSG2007.exe				D:\\PE����.exe	




int main(int argc, char* argv[])
{
	printf("%s:\n",PATH);
	_PE_User PEU(PATH,lpszPATH);
	//PEU.FiToViToFi();
	//PEU.AddMessageBoxA();
	//PEU.AddSectionHeared();
	//PEU.AddSectionHearedDosToNt(1);
	PEU.ExpandSection();
	//PEU.CombineSection();
	//PEU.PrintAllExport();
	//PEU.POINTER_BASE_RELOCATION();
	//PEU.Move_Export_Directory();
	//PEU.PointAllImportData();
	//PEU.Point_Bound_Import_Dir();
	//PEU.InjectImportTable();
	PEU.TestPrintResourceICO();

	//PE_S PeTmp_s;
	//PEU.PointYouWant(PeTmp_s);
	//cout<<"Size:  "<<hex<<PeTmp_s.pDataDirectory[1].Size<<endl;
	return 0;
}


//����//

