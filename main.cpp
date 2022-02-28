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
	printf("MZ标志位 info: %x\n", ReadDosHeader->e_magic);
	printf("PE头偏移 info: %x\n", ReadDosHeader->e_lfanew);

	PIMAGE_NT_HEADERS ntheader;
	ntheader = (PIMAGE_NT_HEADERS)(buffer + ReadDosHeader->e_lfanew);
	printf("PE info: \n");
	printf("PE标志位: %x\n", ntheader->Signature);
	printf("PE运行平台: %x\n", ntheader->FileHeader.Machine);
	printf("PE imagebase: %x\n", ntheader->OptionalHeader.ImageBase);

	PIMAGE_SECTION_HEADER ReadSectionHeader = IMAGE_FIRST_SECTION(ntheader);
	PIMAGE_FILE_HEADER pFileHeader = &ntheader->FileHeader;

	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		printf("Name(区段名称)：%s\n", ReadSectionHeader[i].Name);
		printf("Voffset(区段起始相对地址)：%08X\n", ReadSectionHeader[i].VirtualAddress);
		printf("Vsize(区段大小)：%08X\n", ReadSectionHeader[i].Misc.VirtualSize);
		printf("Roffset(文件偏移)：%08X\n", ReadSectionHeader[i].SizeOfRawData);
		printf("Rsize(文件区段中大小)：%08X\n", ReadSectionHeader[i].PointerToRawData);
		printf("Flags(区段属性)：%08X\n", ReadSectionHeader[i].Characteristics);
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
	//定位导入表
	PIMAGE_DATA_DIRECTORY pImportDir = (PIMAGE_DATA_DIRECTORY)(pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_IMPORT);
	//填充结构
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(RvaToOffset(pImportDir->VirtualAddress,buffer) + buffer);
	while (pImport->Name !=NULL)
	{
		char * DllName = (char *)(RvaToOffset(pImport->Name,buffer) + buffer);

		printf("DLL名称：%s\n", DllName);
		printf("时间标志：%08x\n", pImport->TimeDateStamp);
		printf("名称偏移：%08x\n", pImport->Name);
		printf("ForwarderChain：%08x\n", pImport->ForwarderChain);
		printf("FirstThunk：%08x\n", pImport->FirstThunk);
		printf("OriginalFirstThunk：%08x\n\n", pImport->OriginalFirstThunk);

		//指向导入地址表(IAT)的RVA
		PIMAGE_THUNK_DATA pIat = (PIMAGE_THUNK_DATA)(RvaToOffset(pImport->OriginalFirstThunk,buffer) + buffer);
		DWORD index = 0;
		DWORD ImportOffset = 0;
		while (pIat->u1.Ordinal !=0)
		{
			printf("ThunkRva：%08x\n",pImport->OriginalFirstThunk + index);
			ImportOffset = RvaToOffset(pImport->OriginalFirstThunk, buffer);
			printf("ThunkOffset：%08x\n",ImportOffset + index);
			index +=4;
			if ((pIat->u1.Ordinal & 0x80000000) != 1)
			{
				PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(RvaToOffset(pIat->u1.AddressOfData, buffer) + buffer);
				printf("ApiName：%s\n",pName->Name);
				printf("Hint：%04x\n",pName->Hint);
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
	//定位数据目录表中的导出表
	PIMAGE_DATA_DIRECTORY pExportDir = (PIMAGE_DATA_DIRECTORY)pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(RvaToOffset(pExportDir->VirtualAddress, buffer) + buffer);
	char * szName = (char *)(RvaToOffset(pExport->Name,buffer) + buffer);
	if (pExport->AddressOfFunctions == 0)
	{
		printf("没有导出表!\n");
		return;
	}
	printf("导出表OFFSET：%08x\n",RvaToOffset(pExportDir->VirtualAddress,buffer));
	printf("特征值：%08x\n",pExport->Characteristics);
	printf("基：%08x\n",pExport->Base);
	printf("名称OFFSET：%08x\n",pExport->Name);
	printf("名称：%s\n",szName);
	printf("函数个数：%08x\n",pExport->NumberOfFunctions);
	printf("函数名数量：%08x\n",pExport->NumberOfNames);
	printf("函数地址：%08x\n",pExport->AddressOfFunctions);
	printf("函数名称地址：%08x\n", pExport->AddressOfNames);
	printf("函数名称序号地址：%08x\n", pExport->AddressOfNameOrdinals);

	//函数数量
	DWORD dwNumOfFun = pExport->NumberOfFunctions;
	//函数名数量
	DWORD dwNumOfNames = pExport->NumberOfNames;
	//基
	DWORD dwBase = pExport->Base;
	//导出地址表
	PWORD pEat32 = (PWORD)(RvaToOffset(pExport->AddressOfFunctions,buffer) + buffer);
	//导出名称表
	PWORD pEnt32 = (PWORD)(RvaToOffset(pExport->AddressOfNames,buffer) + buffer);
	//导出序号表
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
	//定位重定位表
	PIMAGE_DATA_DIRECTORY pRelocDir = (pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_BASERELOC);
	//填充重定位表结构
	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(RvaToOffset(pRelocDir->VirtualAddress,buffer) + buffer);
	//定位区段
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	while (pReloc->SizeOfBlock != 0)
	{
		//找到本0x1000字节的起始位置
		DWORD dwCount = (pReloc->SizeOfBlock - 8) / 2;
		DWORD dwRva = pReloc->VirtualAddress;
		PTYPE pRelocArr = (PTYPE)(pReloc+1);
		printf("区段：%s\n",pSection->Name);
		printf("RVA：%08x\n", dwRva);
		printf("Items：%x H/ %d D：",pReloc->SizeOfBlock,pReloc->SizeOfBlock);
		//找到下一个0x1000字节的结构体
		pReloc = (PIMAGE_BASE_RELOCATION)((char *)pReloc + pReloc->SizeOfBlock);

		for (int i = 0; i < dwCount; i++)
		{
			PWORD pData = (PWORD)(RvaToOffset(pRelocArr[i].Offset +dwRva,buffer) + buffer);
			DWORD pDataOffset = RvaToOffset(pRelocArr[i].Offset + dwRva, buffer);
			printf("Rva: %08x\n", pRelocArr[i].Offset + dwRva);
			printf("区段: %08x\n", *pData);
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
	//定位数据目录表中的TLS表
	PIMAGE_DATA_DIRECTORY pTLSDir = (pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_TLS);
	//结构填充
	PIMAGE_TLS_DIRECTORY pTLS = (PIMAGE_TLS_DIRECTORY)(RvaToOffset(pTLSDir->VirtualAddress, buffer) + buffer);
	printf("数据块开始的VA:%08x\n",pTLS->StartAddressOfRawData);
	printf("数据快结束的VA:%08x\n",pTLS->EndAddressOfRawData);
	printf("索引变量的VA:%08x\n",pTLS->AddressOfIndex);
	printf("回调表的VA:%08x\n",pTLS->AddressOfCallBacks);
	printf("填零大小的VA:%08x\n",pTLS->SizeOfZeroFill);
	printf("特征值:%08x\n",pTLS->Characteristics);
}

void DelayImportTable(char * buffer)
{
	//Dos
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	//PE
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + buffer);
	//定位数据目录表中的延迟导入表
	PIMAGE_DATA_DIRECTORY pDelayLoadDir = (pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
	//结构填充
	PIMAGE_DELAYLOAD_DESCRIPTOR pDelayLoad = (PIMAGE_DELAYLOAD_DESCRIPTOR)(RvaToOffset(pDelayLoadDir->VirtualAddress, buffer) + buffer);
	while (pDelayLoad->DllNameRVA !=NULL)
	{
		char * szName = (char *)(RvaToOffset(pDelayLoad->DllNameRVA, buffer) + buffer);
		printf("DllName:%s\n", szName);
		printf("Attributes:%08x\n", pDelayLoad->Attributes);
		printf("绑定IAT的RVA:%08x\n", pDelayLoad->BoundImportAddressTableRVA);
		printf("IAT的RVA:%08x\n", pDelayLoad->ImportAddressTableRVA);
		printf("INT的RVA:%08x\n",pDelayLoad->ImportNameTableRVA);
		printf("模块句柄的RVA:%08x\n",pDelayLoad->ModuleHandleRVA);
		printf("UnloadInformationTableRVA:%08x\n", pDelayLoad->UnloadInformationTableRVA);
		printf("TimeDateStamp:%08x\n\n", pDelayLoad->TimeDateStamp);
		pDelayLoad++;

	}

}



