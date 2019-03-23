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

//��ӡ�ض�λ��
VOID PrintRelocationTable(LPVOID pFileBuffer);

//��ӡ�����
VOID PrintImportTable(LPVOID pFileBuffer);

//��ӡ�󶨵����
VOID PrintBoundImportTable(LPVOID pFileBuffer);

//��ӡ��Դ��
VOID PrintResourceTable(LPVOID pFileBuffer);

//�ݹ��ӡ��Դ��ĺ���
//TableAddr:��Դ���ͷ��λ��
//pResourceDir
//index:����
VOID printResource(LPVOID pFileBuffer,DWORD TableAddr,PIMAGE_RESOURCE_DIRECTORY pResourceDir,int index);

//��ӡnames
//index ����
//names
VOID printIndexTitle(int index,WCHAR* names);

//��ӡnames
//index ����
//names
VOID printIndexTitle(int index,CHAR* names);

//��ӡID
//index ����
//id
VOID printIndexID(int index,DWORD id);

#endif