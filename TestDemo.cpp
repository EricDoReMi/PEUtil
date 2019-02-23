#include "ShowPE.h"

int main(int argc, char* argv[]){
	
	//初始化
	char* pathName="PETool.exe";
	char* pathNameDes="Hello2.exe";
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
	
	return 0;
}