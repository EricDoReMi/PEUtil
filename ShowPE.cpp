//��ȡ���е�PEͷ��Ϣ
#include "ShowPE.h"

//��ӡDosHeader
VOID PrintDosHeaders(){
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader=getDosHeader();

	//��ӡDOCͷ	
	printf("********************DOCͷ********************\n");	
	printf("e_magic(MZ��־):%x\n",pDosHeader->e_magic);	
	printf("e_lfanew(PEƫ��):%x\n",pDosHeader->e_lfanew);
}

//��ӡNTHeader
VOID PrintNTHeaders(){
	PIMAGE_NT_HEADERS pNTHeader = NULL;	
	pNTHeader=getNTHeader();
	printf("********************NTͷ********************\n");	
	printf("Signature(PE��־):%x\n",pNTHeader->Signature);
}

//��ӡPEheader
VOID PrintPEHeaders(){
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	pPEHeader=getPEHeader();
	printf("********************PEͷ********************\n");	
	printf("Machine(���е�ƽ̨):%x\n",pPEHeader->Machine);	
	printf("NumberOfSections(�ڵ�������):%x\n",pPEHeader->NumberOfSections);	
	printf("SizeOfOptionalHeader(��ѡPEͷ�Ĵ�С��):%x\n",pPEHeader->SizeOfOptionalHeader);
}

//��ӡ��ѡ��PEͷ
VOID PrintOptionHeaders(){
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader=getOptionHeader();
	printf("********************OPTIOIN_PEͷ********************\n");
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

//��ӡ�ڱ���Ϣ
VOID PrintSectionHeaders(){
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	
	pOptionHeader=getOptionHeader();
	DWORD sizeOfImage=pOptionHeader->SizeOfImage;
	
	pSectionHeader=getSectionHeader();
	
	

}	


