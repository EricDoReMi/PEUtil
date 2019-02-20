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
		
		
		freePFileBuffer();
	}
	
	return 0;
}