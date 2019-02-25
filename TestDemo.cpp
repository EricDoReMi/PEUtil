#include "ShowPE.h"


void testPrinter(){
		//初始化
	char* pathName="Hello.exe";

	LPVOID pFileBuffer=NULL;
	LPVOID pImageBuffer=NULL;
	LPVOID pNewFileBuffer=NULL;

	if(ReadPEFile(pathName,&pFileBuffer) && checkIsPEFile(pFileBuffer)){
		
		//打印DosHeader
		PrintDosHeaders(pFileBuffer);

		//打印NTHeader
		PrintNTHeaders(pFileBuffer);

		//打印PEheader
		PrintPEHeaders(pFileBuffer);

		//打印可选的PE头
		PrintOptionHeaders(pFileBuffer);
		
		//打印节表信息
		PrintSectionHeaders(pFileBuffer);

		
		
		
	}



}

void testCopyFile(){
		//初始化
	char* pathName="Hello.exe";
	char* pathNameDes="Hello2.exe";
	LPVOID pFileBuffer=NULL;
	LPVOID pImageBuffer=NULL;
	LPVOID pNewFileBuffer=NULL;

	if(ReadPEFile(pathName,&pFileBuffer) && checkIsPEFile(pFileBuffer)){


		DWORD copySize=0;
		copySize= CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);
		if(copySize){
			freePBuffer(pFileBuffer);
			copySize=CopyImageBufferToNewBuffer(pImageBuffer,&pNewFileBuffer);
			if(copySize){
				freePBuffer(pImageBuffer);
				copySize=MemeryTOFile(pNewFileBuffer,copySize,pathNameDes);

				if(copySize){
					freePBuffer(pNewFileBuffer);	
				}else{
					printf("MemeryTOFile Failed!");
				}
			}else{
				printf("CopyImageBufferToNewBuffer Failed!");
			}
		}else{
			printf("CopyFileBufferToImageBuffer Failed!");
		}
		
		
		
	}


	
	}
	

void testRvaToFileOffset(){
	//初始化
	char* pathName="Hello.exe";

	LPVOID pFileBuffer=NULL;

	if(ReadPEFile(pathName,&pFileBuffer) && checkIsPEFile(pFileBuffer)){
		
	
		DWORD fileOffset=RvaToFileOffset(pFileBuffer,0x401480);

		printf("%X\n",fileOffset);
	
	}

	
}

void testFileOffsetToRva(){
	//初始化
	char* pathName="TestWin32.exe";

	LPVOID pFileBuffer=NULL;

	if(ReadPEFile(pathName,&pFileBuffer) && checkIsPEFile(pFileBuffer)){
		
	
		DWORD RVA=FileOffsetToRva(pFileBuffer,0x21f92);

		printf("%X\n",RVA);
	
	}

	
}

int main(int argc, char* argv[]){

	testPrinter();
	testCopyFile();
	testRvaToFileOffset();
	testFileOffsetToRva();
	return 0;
}

