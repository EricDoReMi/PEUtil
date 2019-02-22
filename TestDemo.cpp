#include "ShowPE.h"

int main(int argc, char* argv[]){
	
	//初始化
	char* pathName="Hello.exe";
	LPVOID pFileBuffer;
	

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
		freePBuffer(pFileBuffer);
	}
	
	return 0;
}