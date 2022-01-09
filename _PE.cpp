// _PE.cpp : Defines the entry point for the console application.
//


/********************/
/*					*/
/*编译器：vc++		*/
/*完成者：_TLSN		*/
/*完成时间：2022/1/9*/
/*					*/
/********************/

/********************************************/
/*											*/
/*这是以c++类的形式进行的PE解析				*/
/*这些函数一般用_PE_User类 定义出对象都能用	*/
/*函数的功能在头文件里都有定义				*/
/*											*/
/********************************************/



#include "stdafx.h"
#include "Class_PE.h"
#include "Class_PE_USER.h"


#define PATH TEXT("C:\\WINDOWS\\system32\\notepad.exe")
#define lpszPATH TEXT("D:\\PE解析.exe")
 //C:\\WINDOWS\\system32\\nshwfp.dll		C:\\WINDOWS\\system32\\nsi.dll		D:\\滴水逆向\\tools\\IPMsgCHS206\\IPMSG2007.exe				D:\\PE解析.exe	




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


//结束//

