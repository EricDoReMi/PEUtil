#ifndef __SHOWPE_H__
#define __SHOWPE_H__
#include "PEUtil.h"
#include "ShowPE.h"

//��ӡDosHeader
VOID PrintDosHeaders(LPVOID pFileBuffer);

//��ӡNTHeader
VOID PrintNTHeaders(LPVOID pFileBuffer);

//��ӡPEheader
VOID PrintPEHeaders(LPVOID pFileBuffer);

//��ӡ��ѡ��PEͷ
VOID PrintOptionHeaders(LPVOID pFileBuffer);

//��ӡ�ڱ���Ϣ
VOID PrintSectionHeaders(LPVOID pFileBuffer);

//��ӡĿ¼��
VOID PrintDataDirectory(LPVOID pFileBuffer);

//��ӡ������
VOID PrintExportTable(LPVOID pFileBuffer);


#endif