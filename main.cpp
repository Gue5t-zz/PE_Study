#include <main.h>
int main() {
	FILE * pFile = NULL;
	char * buffer;
	int nFileLength = 0;
	pFile = fopen("C:\\huanjing\\phpstudy.exe", "rb");
	fseek(pFile, 0, SEEK_END);
	nFileLength = ftell(pFile);
	rewind(pFile);
	int imageLength = nFileLength * sizeof(char) + 1;
	buffer = (char *)malloc(imageLength);
	memset(buffer, 0, nFileLength * sizeof(char) + 1);
	fread(buffer, 1, imageLength, pFile);

	PIMAGE_DOS_HEADER ReadDosHeader;
	ReadDosHeader = (PIMAGE_DOS_HEADER)buffer;
	printf("ms-dos info: \n");
	printf("MZ��־λ info: %x\n", ReadDosHeader->e_magic);
	printf("PEͷƫ�� info: %x\n", ReadDosHeader->e_lfanew);

	PIMAGE_NT_HEADERS ntheader;
	ntheader = (PIMAGE_NT_HEADERS)(buffer + ReadDosHeader->e_lfanew);
	printf("PE info: \n");
	printf("PE��־λ: %x\n", ntheader->Signature);
	printf("PE����ƽ̨: %x\n", ntheader->FileHeader.Machine);
	printf("PE imagebase: %x\n", ntheader->OptionalHeader.ImageBase);

	PIMAGE_SECTION_HEADER ReadSectionHeader = IMAGE_FIRST_SECTION(ntheader);
	PIMAGE_FILE_HEADER pFileHeader = &ntheader->FileHeader;

	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		printf("Name(��������)��%s\n", ReadSectionHeader[i].Name);
		printf("Voffset(������ʼ��Ե�ַ)��%08X\n", ReadSectionHeader[i].VirtualAddress);
		printf("Vsize(���δ�С)��%08X\n", ReadSectionHeader[i].Misc.VirtualSize);
		printf("Roffset(�ļ�ƫ��)��%08X\n", ReadSectionHeader[i].SizeOfRawData);
		printf("Rsize(�ļ������д�С)��%08X\n", ReadSectionHeader[i].PointerToRawData);
		printf("Flags(��������)��%08X\n", ReadSectionHeader[i].Characteristics);
		printf("\n--------------------------------------------------------------------\n");
	}

	DelayImportTable(buffer);
	free(buffer);
	system("pause");

	return 0;
}

DWORD RvaToOffset(DWORD dwRva, char * buffer)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + buffer);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

	if (dwRva < pSection[0].VirtualAddress)
	{
		return dwRva;
	}

	for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		if (dwRva >= pSection[i].VirtualAddress && dwRva <pSection[i].VirtualAddress + pSection[i].Misc.VirtualSize)
		{
			return dwRva - pSection[i].VirtualAddress + pSection[i].PointerToRawData;
		}
	}
}

void ImportTable(char * buffer)
{
	printf("================================================================\n");
	//Dos
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	//PE
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + buffer);
	//��λ�����
	PIMAGE_DATA_DIRECTORY pImportDir = (PIMAGE_DATA_DIRECTORY)(pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_IMPORT);
	//���ṹ
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(RvaToOffset(pImportDir->VirtualAddress,buffer) + buffer);
	while (pImport->Name !=NULL)
	{
		char * DllName = (char *)(RvaToOffset(pImport->Name,buffer) + buffer);

		printf("DLL���ƣ�%s\n", DllName);
		printf("ʱ���־��%08x\n", pImport->TimeDateStamp);
		printf("����ƫ�ƣ�%08x\n", pImport->Name);
		printf("ForwarderChain��%08x\n", pImport->ForwarderChain);
		printf("FirstThunk��%08x\n", pImport->FirstThunk);
		printf("OriginalFirstThunk��%08x\n\n", pImport->OriginalFirstThunk);

		//ָ�����ַ��(IAT)��RVA
		PIMAGE_THUNK_DATA pIat = (PIMAGE_THUNK_DATA)(RvaToOffset(pImport->OriginalFirstThunk,buffer) + buffer);
		DWORD index = 0;
		DWORD ImportOffset = 0;
		while (pIat->u1.Ordinal !=0)
		{
			printf("ThunkRva��%08x\n",pImport->OriginalFirstThunk + index);
			ImportOffset = RvaToOffset(pImport->OriginalFirstThunk, buffer);
			printf("ThunkOffset��%08x\n",ImportOffset + index);
			index +=4;
			if ((pIat->u1.Ordinal & 0x80000000) != 1)
			{
				PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(RvaToOffset(pIat->u1.AddressOfData, buffer) + buffer);
				printf("ApiName��%s\n",pName->Name);
				printf("Hint��%04x\n",pName->Hint);
			}
			pIat++;
		}

		pImport++;
	}
}

void ExportTable(char * buffer)
{
	printf("================================================================\n");
	//DOS
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	//PE
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + buffer);
	//��λ����Ŀ¼���еĵ�����
	PIMAGE_DATA_DIRECTORY pExportDir = (PIMAGE_DATA_DIRECTORY)pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(RvaToOffset(pExportDir->VirtualAddress, buffer) + buffer);
	char * szName = (char *)(RvaToOffset(pExport->Name,buffer) + buffer);
	if (pExport->AddressOfFunctions == 0)
	{
		printf("û�е�����!\n");
		return;
	}
	printf("������OFFSET��%08x\n",RvaToOffset(pExportDir->VirtualAddress,buffer));
	printf("����ֵ��%08x\n",pExport->Characteristics);
	printf("����%08x\n",pExport->Base);
	printf("����OFFSET��%08x\n",pExport->Name);
	printf("���ƣ�%s\n",szName);
	printf("����������%08x\n",pExport->NumberOfFunctions);
	printf("������������%08x\n",pExport->NumberOfNames);
	printf("������ַ��%08x\n",pExport->AddressOfFunctions);
	printf("�������Ƶ�ַ��%08x\n", pExport->AddressOfNames);
	printf("����������ŵ�ַ��%08x\n", pExport->AddressOfNameOrdinals);

	//��������
	DWORD dwNumOfFun = pExport->NumberOfFunctions;
	//����������
	DWORD dwNumOfNames = pExport->NumberOfNames;
	//��
	DWORD dwBase = pExport->Base;
	//������ַ��
	PWORD pEat32 = (PWORD)(RvaToOffset(pExport->AddressOfFunctions,buffer) + buffer);
	//�������Ʊ�
	PWORD pEnt32 = (PWORD)(RvaToOffset(pExport->AddressOfNames,buffer) + buffer);
	//������ű�
	PWORD pId = (PWORD)(RvaToOffset(pExport->AddressOfNameOrdinals,buffer) + buffer);

	for (DWORD i = 0; i < dwNumOfFun; i++)
	{
		if (pEat32[i] == 0)
		{
			continue;
		
		}
		DWORD Id = 0;
		for (; Id < dwNumOfNames; Id++)
		{
			if (pId[Id] == i)
			{
				break;
			}
		}
		if (Id == dwNumOfNames)
		{
			printf("Id:%x Address:0x%08x Name[NULL]\n",i + dwBase,pEat32[i] );
		}
		else
		{
			char * szFunName = (char *)(RvaToOffset(pEat32[i],buffer) + buffer);
			printf("Id:%x Address:0x%08x Name[%s]\n",i+dwBase,pEat32[i],szFunName);
		}
	}


}

void RelocTable(char * buffer)
{
	typedef struct _TYPE {
		WORD Offset : 12;
		WORD Type : 4;
	}TYPE,*PTYPE;
	//Dos
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	//PE
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + buffer);
	//��λ�ض�λ��
	PIMAGE_DATA_DIRECTORY pRelocDir = (pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_BASERELOC);
	//����ض�λ��ṹ
	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(RvaToOffset(pRelocDir->VirtualAddress,buffer) + buffer);
	//��λ����
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	while (pReloc->SizeOfBlock != 0)
	{
		//�ҵ���0x1000�ֽڵ���ʼλ��
		DWORD dwCount = (pReloc->SizeOfBlock - 8) / 2;
		DWORD dwRva = pReloc->VirtualAddress;
		PTYPE pRelocArr = (PTYPE)(pReloc+1);
		printf("���Σ�%s\n",pSection->Name);
		printf("RVA��%08x\n", dwRva);
		printf("Items��%x H/ %d D��",pReloc->SizeOfBlock,pReloc->SizeOfBlock);
		//�ҵ���һ��0x1000�ֽڵĽṹ��
		pReloc = (PIMAGE_BASE_RELOCATION)((char *)pReloc + pReloc->SizeOfBlock);

		for (int i = 0; i < dwCount; i++)
		{
			PWORD pData = (PWORD)(RvaToOffset(pRelocArr[i].Offset +dwRva,buffer) + buffer);
			DWORD pDataOffset = RvaToOffset(pRelocArr[i].Offset + dwRva, buffer);
			printf("Rva: %08x\n", pRelocArr[i].Offset + dwRva);
			printf("����: %08x\n", *pData);
			printf("OFFSET: %08x\n", pDataOffset);
		}
	}
}

void TlsTable(char * buffer)
{
	//Dos
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	//PE
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + buffer);
	//��λ����Ŀ¼���е�TLS��
	PIMAGE_DATA_DIRECTORY pTLSDir = (pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_TLS);
	//�ṹ���
	PIMAGE_TLS_DIRECTORY pTLS = (PIMAGE_TLS_DIRECTORY)(RvaToOffset(pTLSDir->VirtualAddress, buffer) + buffer);
	printf("���ݿ鿪ʼ��VA:%08x\n",pTLS->StartAddressOfRawData);
	printf("���ݿ������VA:%08x\n",pTLS->EndAddressOfRawData);
	printf("����������VA:%08x\n",pTLS->AddressOfIndex);
	printf("�ص����VA:%08x\n",pTLS->AddressOfCallBacks);
	printf("�����С��VA:%08x\n",pTLS->SizeOfZeroFill);
	printf("����ֵ:%08x\n",pTLS->Characteristics);
}

void DelayImportTable(char * buffer)
{
	//Dos
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	//PE
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + buffer);
	//��λ����Ŀ¼���е��ӳٵ����
	PIMAGE_DATA_DIRECTORY pDelayLoadDir = (pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
	//�ṹ���
	PIMAGE_DELAYLOAD_DESCRIPTOR pDelayLoad = (PIMAGE_DELAYLOAD_DESCRIPTOR)(RvaToOffset(pDelayLoadDir->VirtualAddress, buffer) + buffer);
	while (pDelayLoad->DllNameRVA !=NULL)
	{
		char * szName = (char *)(RvaToOffset(pDelayLoad->DllNameRVA, buffer) + buffer);
		printf("DllName:%s\n", szName);
		printf("Attributes:%08x\n", pDelayLoad->Attributes);
		printf("��IAT��RVA:%08x\n", pDelayLoad->BoundImportAddressTableRVA);
		printf("IAT��RVA:%08x\n", pDelayLoad->ImportAddressTableRVA);
		printf("INT��RVA:%08x\n",pDelayLoad->ImportNameTableRVA);
		printf("ģ������RVA:%08x\n",pDelayLoad->ModuleHandleRVA);
		printf("UnloadInformationTableRVA:%08x\n", pDelayLoad->UnloadInformationTableRVA);
		printf("TimeDateStamp:%08x\n\n", pDelayLoad->TimeDateStamp);
		pDelayLoad++;

	}

}



