#include "ShowPE.h"

int main(int argc, char* argv[]){
	
	//初始化
	if(InitFileBuffer("Hello.exe") && checkIsPEFile()){
		
		//打印DosHeader
		PrintDosHeaders();

		//打印NTHeader
		PrintNTHeaders();

		//打印PEheader
		PrintPEHeaders();

		//打印可选的PE头
		PrintOptionHeaders();
		
		//打印节表信息
		PrintSectionHeaders();
		freePFileBuffer();
	}
	
	return 0;
}