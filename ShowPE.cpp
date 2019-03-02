//读取所有的PE头信息
#include "ShowPE.h"

//打印DosHeader
VOID PrintDosHeaders(LPVOID pFileBuffer){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader=getDosHeader(pFileBuffer);

	//打印DOC头	
	printf("********************DOC头********************\n");	
	printf("e_magic(MZ标志):%x\n",pDosHeader->e_magic);	
	printf("e_lfanew(PE偏移):%x\n",pDosHeader->e_lfanew);
}

//打印NTHeader
VOID PrintNTHeaders(LPVOID pFileBuffer){
	PIMAGE_NT_HEADERS pNTHeader = NULL;	
	pNTHeader=getNTHeader(pFileBuffer);
	printf("********************NT头********************\n");	
	printf("Signature(PE标志):%x\n",pNTHeader->Signature);
}

//打印PEheader
VOID PrintPEHeaders(LPVOID pFileBuffer){
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	pPEHeader=getPEHeader(pFileBuffer);
	printf("********************PE头********************\n");	
	printf("Machine(运行的平台):%x\n",pPEHeader->Machine);	
	printf("NumberOfSections(节的数量了):%x\n",pPEHeader->NumberOfSections);	
	printf("SizeOfOptionalHeader(可选PE头的大小了):%x\n",pPEHeader->SizeOfOptionalHeader);
}

//打印可选的PE头
VOID PrintOptionHeaders(LPVOID pFileBuffer){
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader=getOptionHeader(pFileBuffer);
	printf("********************OPTIOIN_PE头********************\n");
	printf("OPTION_PE:%x\n",pOptionHeader->Magic);	
	printf("SizeOfCode:%x\n",pOptionHeader->SizeOfCode);	
	printf("SizeOfInitializedData:%x\n",pOptionHeader->SizeOfInitializedData);	
	printf("SizeOfUninitializedData:%x\n",pOptionHeader->SizeOfUninitializedData);	
	printf("AddressOfEntryPoint:%x\n",pOptionHeader->AddressOfEntryPoint);	
	printf("BaseOfCode:%x\n",pOptionHeader->BaseOfCode);	
	printf("BaseOfData:%x\n",pOptionHeader->BaseOfData);	
	printf("ImageBase:%x\n",pOptionHeader->ImageBase);	
	printf("SectionAlignment:%x\n",pOptionHeader->SectionAlignment);	
	printf("SizeOfImage:%x\n",pOptionHeader->SizeOfImage);	
	printf("CheckSum:%x\n",pOptionHeader->CheckSum);	
}

//打印节表信息
VOID PrintSectionHeaders(LPVOID pFileBuffer){
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	

	
	pSectionHeader=getSectionHeader(pFileBuffer);
	
	WORD sectionNum=getSectionNum(pFileBuffer);


	printf("********************SECTION头********************\n");
	WORD i=0;
	for(i=0;i<sectionNum;i++){
		BYTE names[9]={0};
		BYTE* p_name=names;
		p_name=pSectionHeader->Name;
		printf("-----SectionNum:%d-----\n",i+1);
		printf("SectionName:%s\n",p_name);
		printf("Misc:%X\n",pSectionHeader->Misc);
		printf("SizeOfRawData:%X\n",pSectionHeader->SizeOfRawData);
		printf("PointerToRawData:%X\n",pSectionHeader->PointerToRawData);
		printf("PointerToRelocations:%X\n",pSectionHeader->PointerToRelocations);
		printf("PointerToLinenumbers:%X\n",pSectionHeader->PointerToLinenumbers);
		printf("NumberOfRelocations:%X\n",pSectionHeader->NumberOfRelocations);
		printf("NumberOfLinenumbers:%X\n",pSectionHeader->NumberOfLinenumbers);
		printf("Characteristics:%X\n",pSectionHeader->Characteristics);
		pSectionHeader=(PIMAGE_SECTION_HEADER)((char*)pSectionHeader+40);

	}


}

//打印目录表
VOID PrintDataDirectory(LPVOID pFileBuffer){
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader=getOptionHeader(pFileBuffer);
	DWORD i=0;
	PIMAGE_DATA_DIRECTORY pImageDataDirectory=pOptionHeader->DataDirectory;

	//导出表、导入表、资源表、异常信息表、安全证书表、重定位表、调试信息表、版权所有表、全局指针表
    //TLS表、加载配置表、绑定导入表、IAT表、延迟导入表、COM信息表 最后一个保留未使用。
	char* pTableNames[16]={"导出表","导入表","资源表","异常信息表","安全证书表","重定位表","调试信息表","版权所有表","全局指针表","TLS表","加载配置表","绑定导入表","IAT表","延迟导入表","COM信息表","保留表"};

	printf("===============PrintDataDirectory=============\n");
	PIMAGE_DATA_DIRECTORY pDataDirectory=NULL;
	for(i=0;i<16;i++){
		pDataDirectory=pImageDataDirectory+i;
		printf("===============%s=============\n",pTableNames[i]);
		printf("地址:%X\n",pDataDirectory->VirtualAddress);
		printf("表大小:%X\n",pDataDirectory->Size);

	}
}	


