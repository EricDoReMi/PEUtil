//读取所有的PE头信息
#include "ShowPE.h"

//打印DosHeader
VOID PrintDosHeaders(){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader=getDosHeader();

	//打印DOC头	
	printf("********************DOC头********************\n");	
	printf("e_magic(MZ标志):%x\n",pDosHeader->e_magic);	
	printf("e_lfanew(PE偏移):%x\n",pDosHeader->e_lfanew);
}

//打印NTHeader
VOID PrintNTHeaders(){
	PIMAGE_NT_HEADERS pNTHeader = NULL;	
	pNTHeader=getNTHeader();
	printf("********************NT头********************\n");	
	printf("Signature(PE标志):%x\n",pNTHeader->Signature);
}

//打印PEheader
VOID PrintPEHeaders(){
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	pPEHeader=getPEHeader();
	printf("********************PE头********************\n");	
	printf("Machine(运行的平台):%x\n",pPEHeader->Machine);	
	printf("NumberOfSections(节的数量了):%x\n",pPEHeader->NumberOfSections);	
	printf("SizeOfOptionalHeader(可选PE头的大小了):%x\n",pPEHeader->SizeOfOptionalHeader);
}

//打印可选的PE头
VOID PrintOptionHeaders(){
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader=getOptionHeader();
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
	printf("CheckSum%:x\n",pOptionHeader->CheckSum);	
}

//打印节表信息
VOID PrintSectionHeaders(){
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	
	pOptionHeader=getOptionHeader();
	DWORD sizeOfImage=pOptionHeader->SizeOfImage;
	
	pSectionHeader=getSectionHeader();
	
	

}	


