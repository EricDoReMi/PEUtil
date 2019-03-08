#ifndef __PEUTIL_H__
#define __PEUTIL_H__
#include "Common.h"
#include "PEUtil.h"


//ȫ�ֱ�������
extern BYTE shellcode[];

//��ȡ�ļ���С
int getFileSize(FILE *P_file);

//��ȡ��FileBuffer
//return 0 ʧ�� 1 �ɹ�
//��������							
//**************************************************************************							
//ReadPEFile:���ļ���ȡ��������							
//����˵����							
//lpszFile �ļ�·��							
//pFileBuffer ������ָ��							
//����ֵ˵����							
//��ȡʧ�ܷ���0  ���򷵻�ʵ�ʶ�ȡ�Ĵ�С							
//**************************************************************************							
DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer);

//**************************************************************************							
//CopyFileBufferToImageBuffer:���ļ���FileBuffer���Ƶ�ImageBuffer							
//����˵����							
//pFileBuffer  FileBufferָ��							
//pImageBuffer ImageBufferָ��							
//����ֵ˵����							
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С							
//**************************************************************************
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer);
							
//**************************************************************************							
//CopyImageBufferToNewBuffer:��ImageBuffer�е����ݸ��Ƶ��µĻ���������ImageBuffer��ԭΪ�ļ���PE��ʽ							
//����˵����							
//pImageBuffer ImageBufferָ��							
//pNewBuffer NewBufferָ��							
//����ֵ˵����							
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С							
//**************************************************************************							
DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer,OUT LPVOID* pNewBuffer);
						
//**************************************************************************							
//MemeryTOFile:���ڴ��е����ݸ��Ƶ��ļ�							
//����˵����							
//pMemBuffer �ڴ������ݵ�ָ��							
//size Ҫ���ƵĴ�С							
//lpszFile Ҫ�洢���ļ�·��							
//����ֵ˵����							
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С							
//**************************************************************************							
DWORD MemeryTOFile(IN LPVOID pMemBuffer,IN size_t size,OUT LPSTR lpszFile);
						
//**************************************************************************							
//RvaToFileOffset:���ڴ�ƫ��ת��Ϊ�ļ�ƫ��							
//����˵����							
//pFileBuffer FileBufferָ��							
//dwRva RVA��ֵ							
//����ֵ˵����							
//����ת�����FOA��ֵ  ���ʧ�ܷ���0							
//**************************************************************************							
DWORD RvaToFileOffset(IN LPVOID pFileBuffer,IN DWORD dwRva);

//**************************************************************************							
//RvaToSectionIndex:ͨ���ڴ�ƫ��Ѱ��sectionIndex						
//����˵����							
//pFileBuffer FileBufferָ��							
//dwRva RVA��ֵ							
//����ֵ˵����							
//�����ҵ���SectionNum�� ���ʧ�ܷ���0							
//**************************************************************************							
DWORD RvaToSectionIndex(IN LPVOID pFileBuffer,IN DWORD dwRva);

//**************************************************************************							
//FileOffsetToRva:���ļ�ƫ��ת��Ϊ�ڴ�ƫ��							
//����˵����							
//pFileBuffer FileBufferָ��							
//dwFileOffSet RVA��ֵ							
//����ֵ˵����							
//����ת�����RVA��ֵ  ���ʧ�ܷ���0							
//**************************************************************************							
DWORD FileOffsetToRva(IN LPVOID pFileBuffer,IN DWORD dwFileOffSet);


//**************************************************************************							
//RvaToFileBufferAddress:���ڴ�ƫ��ת��ΪFileBuffer�еĵ�ַ��							
//����˵����							
//pFileBuffer FileBufferָ��							
//dwRva RVA��ֵ							
//����ֵ˵����							
//����ת�����FileAddress��ֵ  ���ʧ�ܷ���0							
//**************************************************************************							
DWORD RvaToFileBufferAddress(IN LPVOID pFileBuffer,IN DWORD dwRva);

//**************************************************************************							
//FileBufferAddressToRva:��FileBuffer�еĵ�ַת��Ϊ�ڴ�ƫ��							
//����˵����							
//pFileBuffer FileBufferָ��							
//dwFileAddress fileBuffer�е�ַ						
//����ֵ˵����							
//����ת�����RVA��ֵ  ���ʧ�ܷ���0							
//**************************************************************************							
DWORD FileBufferAddressToRva(IN LPVOID pFileBuffer,IN DWORD dwFileAddress);
	

//�ͷ�Buffer
void freePBuffer(LPVOID pBuffer);

//����ǲ���PE�ļ�
//return 0 ʧ�� 1 �ɹ�
int checkIsPEFile(LPVOID pBuffer);

//��ȡDos�ļ�ͷ
PIMAGE_DOS_HEADER getDosHeader(LPVOID pBuffer);

//���NT�ļ�ͷ
PIMAGE_NT_HEADERS getNTHeader(LPVOID pBuffer);


//���PE�ļ�ͷ
PIMAGE_FILE_HEADER getPEHeader(LPVOID pBuffer);


//��ÿ�ѡ��PEͷ
PIMAGE_OPTIONAL_HEADER32 getOptionHeader(LPVOID pBuffer);

//��ýڱ�ͷ
PIMAGE_SECTION_HEADER getSectionHeader(LPVOID pBuffer);

//��ȡ�ڱ���
//index �ڼ����ڱ�
//����ֵ���ɹ����ظýڱ�ͷ��ʧ���򷵻�NULL
PIMAGE_SECTION_HEADER getSection(LPVOID pBuffer,WORD index);

//��ýڵ�����
WORD getSectionNum(LPVOID pBuffer);



//��ShellCode��ӵ�ĳ��Section��
//pathName:Դ�ļ�·��
//pathNameDes:Ŀ���ļ�·��
//pshellCode:shellCode��ַ
//shellCodeLength:shellCode�ĳ���
//sectionNum:�ڵĵ�ַ��
//����ֵ:�ɹ�����1,ʧ�ܷ���0
DWORD addShellCodeIntoSection(char* pathName,char* pathNameDes,PBYTE pshellCode,DWORD shellCodeLength,WORD sectionNum);

//�ж�Section�Ƿ��㹻�洢shellCode�Ĵ���
//pSectionHeader:Ҫ��������section��Header
//shellCodeLength:����������
//����ֵ:�ɹ��򷵻�1��ʧ���򷵻�0
DWORD checkSectionHeaderCouldWriteCode(IN PIMAGE_SECTION_HEADER pSectionHeader,DWORD shellCodeLength);

//��ImageBuffer�л���ܹ�ע������λ��
//����ע��Ĵ�����ImageBuffer�е�λ����
PBYTE getCodeBeginFromImageBuffer(IN LPVOID pImageBuffer,IN PIMAGE_SECTION_HEADER pSectionHeader);

//��ImageBuffer�еĵ�ַת��Ϊ����ʱ�ĵ�ַ
//pImageBuffer
//imageBufferRunAddr��ImageBuffer�еĵ�ַ��
//��������ʱ�ĵ�ַ
DWORD changeImageBufferAddressToRunTimeAddress(IN LPVOID pImageBuffer,DWORD imageBufferRunAddr);

//��ImageBuffer�еĵ�ַת��ΪE8��E9ָ�������ת�ĵ�ַ��Ӳ����
//pImageBuffer
//imageBufferRunAddr��ImageBuffer�еĵ�ַ��
//E8E9RunTimeAddress:E8��E9ָ������ʱ�ĵ�ַ
DWORD changeE8E9AddressFromImageBuffer(IN LPVOID pImageBuffer,DWORD imageBufferRunAddr,DWORD E8E9RunTimeAddress);

//��RunTImeBuffer�еĵ�ַת��ΪE8��E9ָ�������ת�ĵ�ַ��Ӳ����
//E8E9RunTimeAddress:E8��E9ָ������ʱ�ĵ�ַ
//rumTimeAddress:Ҫת��������ʱ��ַ
//���أ�ת�����Ӳ�����ַ
DWORD changeE8E9AddressFromRunTimeBuffer(DWORD E8E9RunTimeAddress,DWORD rumTimeAddress);

//��ó�������ʱ��ڵĵ�ַ
//pBuffer
//������ڵ�ַ
PBYTE getEntryRunTimeAddress(LPVOID pBuffer);

//�޸ĳ�������ʱ��ڵ�ַ
//pImageBuffer
//imageBufferRunAddress��ImageBuffer�еĵ�ַ��
void changeEntryPosByImageBufferAddress(LPVOID pImageBuffer,DWORD imageBufferRunAddress);

//�޸�section��Ȩ��
//pBuffer
//sectionNum Section�ĵ�ַ
//characteristics�������Ȩ�ޣ���0x60000020
//�ɹ�������1��ʧ�ܣ�����0
DWORD changeSectionCharacteristics(LPVOID pBuffer,WORD sectionNum,DWORD characteristics);

//��pBuffer�н�PE��NTͷ��Section��ͷ������Dosͷ��
//pBuffer
//����ֵ:Dosͷ�µļ�϶�Ĵ�С��0:Dosͷ��û�м�϶
DWORD topPENTAndSectionHeader(IN LPVOID pBuffer);

//��ýڱ�����һ���ֽڵ���һ���ֽڵĵ�ַ
//pBuffer
//����ֵ:LPVOID,����һ���ڱ�ָ�룬���������ڱ�
LPVOID getSectionEnderNext(IN LPVOID pBuffer);

//�ж��Ƿ�������һ���ڱ�,�����һ���ڱ���80���ֽ�ȫΪ0,��������
//pBuffer
//����ֵ:1�ɹ�,0ʧ��
DWORD checkCanAddSection(IN LPVOID pBuffer);

//����һ���ڱ�,Ȩ��Ϊ
//pBuffer
//sizeOfNewSection,�����Ľڱ�ռ����
//pNewBuffer���سɹ���newBuffer��ַ
//characteristics�������Ȩ�ޣ���0x60000020
//����ֵ 1�ɹ� 0ʧ��
DWORD addNewSection(IN LPVOID pImageBuffer,DWORD sizeOfNewSection,DWORD characteristics,OUT LPVOID* pNewImageBuffer);

//���FileBuffer�Ĵ�С
DWORD getFileBufferSize(IN LPVOID pFileBuffer);


//ֱ����FileBuffer������һ����
//pFileBuffer
//sizeOfNewSection,�������ֽ���
//pNewFileBuffer���سɹ���newFileBuffer��ַ
//characteristics�������Ȩ�ޣ���0x60000020
//����ֵ �����������׵�ַ��RVA 0ʧ��
DWORD addNewSectionByFileBuffer(IN LPVOID pFileBuffer,DWORD sizeOfNewSection,DWORD characteristics,OUT LPVOID* pNewFileBuffer);


//��չ���һ���ڱ�
//pBuffer
//addSize,���ӵ��ֽ���
//pNewBuffer���سɹ���newBuffer��ַ
//characteristics�������Ȩ�ޣ���0x60000020
//����ֵ 1�ɹ� 0ʧ��
DWORD extendTheLastSection(IN LPVOID pImageBuffer,DWORD addSizeNew,DWORD characteristics,OUT LPVOID* pNewImageBuffer);

//��fileBuffer��չ���һ���ڱ�
//pBuffer
//addSize,���ӵ��ֽ���
//pNewBuffer���سɹ���newBuffer��ַ
//characteristics�������Ȩ�ޣ���0x60000020
//����ֵ 1�ɹ� 0ʧ��
DWORD extendTheLastSectionByFileBuffer(IN LPVOID pFileBuffer,DWORD addSizeNew,DWORD characteristics,OUT LPVOID* pNewFileBuffer);

//�ϲ����н�
//pBuffer
//characteristics �ϲ���ֻ��һ���ڣ�Ҫ���У�������Ȩ��Ϊ0xE0000020������Ҫ���������ڣ�����������Ȩ�ޣ����޷�����
//pNewBuffer���سɹ���newBuffer��ַ
//����ֵ 1�ɹ� 0ʧ��
DWORD mergeAllSections(IN LPVOID pImageBuffer,DWORD characteristics,OUT LPVOID* pNewImageBuffer);

//��changeNumber��ΪbaseNumber��������
DWORD changeNumberByBase(DWORD baseNumber,DWORD changeNumber);


//===================PIMAGE_DATA_DIRECTORY=======================
//��index��ȡDataDirectoryTable��Ϣ
//pFileBuffer
//index ���,�� 1 ������
//���� PIMAGE_DATA_DIRECTORY
PIMAGE_DATA_DIRECTORY getDataDirectory(LPVOID pFileBuffer,DWORD index);


//********************������********************************
//ͨ��������������ú�����ַRVA
//pFileBuffer
//pFunName �������ַ���ָ��
//����ֵ:�ɹ� �ú���RVA
DWORD GetFunctionRVAByName(LPVOID pFileBuffer,char* pFunName);

//ͨ������������Ż�ú�����ַRVA,���������.def�ļ��еĶ���
//pFileBuffer
//index ���
//����ֵ:�ɹ� �ú���RVA
DWORD GetFunctionRVAByOrdinals(LPVOID pFileBuffer,DWORD index);

//��ȡ������Ĵ�С,�����������еĺ�����ַ���������Ʊ�ͺ�����ű�Ĵ�С���Լ��������Ʊ���ָ����ַ����Ĵ�С
//pFileBuffer
//����ֵ �������С
DWORD getExportDirectorySize(LPVOID pFileBuffer);

//�ƶ�������
//pFileBuffer
//fileRVA �������ƶ�����RVA
void removeExportDirectory(LPVOID pFileBuffer,DWORD fileRVA);

//��ȡ�ض�λ��Ĵ�С
//pFileBuffer
//����ֵ �ض�λ��Ĵ�С
DWORD getRelocationDirectorySize(LPVOID pFileBuffer);

//�ƶ��ض�λ��
//pFileBuffer
//fileRVA �������ƶ�����RVA
void removeRelocationDirectory(LPVOID pFileBuffer,DWORD fileRVA);

//******************************ImportTableDirectory******************************
//��ȡ��������нṹ��Ĵ�С
//pFileBuffer
//����ֵ �����Ĵ�С
DWORD getImageImportDescriptorsSize(LPVOID pFileBuffer);

//���Dll�ļ�����Ϣ
//pFileInputPath �ļ���·��
//pFunName ���������
//pDllNames,���Dll�ļ�������
//���� ��ӵ�PE������е���Ҫ����Ĵ�С
DWORD getDllExportInfor(IN char* pFileInputPath,char* pFunName,char** pDllName);

//�ƶ������
//pFileBuffer
//fileRVA 
//imageImportDescriptorsSize,Ҫ�ƶ��ĵ����Ĵ�С
//���� �ƶ����µ����ĩβ����һ���ֽڵ�ַ
DWORD removeImportDirectory(LPVOID pFileBuffer,DWORD fileRVA,DWORD imageImportDescriptorsSize);

#endif
