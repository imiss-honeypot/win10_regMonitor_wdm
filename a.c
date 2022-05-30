#include <ntifs.h>
#include <windef.h>
#include <ntstrsafe.h>

#define REGISTRY_POOL_TAG 'lxw'

// ��־�ļ�·�����������ǰ��ģ���
PCWSTR LOGFILEPATH = L"\\??\\C:\\1.log";

//ע���ص�ʹ�õ�Cookie
LARGE_INTEGER	cookie;

//���ݶ����ȡ����
NTKERNELAPI NTSTATUS ObQueryNameString
(
	IN  PVOID Object,
	OUT POBJECT_NAME_INFORMATION ObjectNameInfo,
	IN  ULONG Length,
	OUT PULONG ReturnLength
);

//����EPROCESS��ȡ��������
PUCHAR PsGetProcessImageFileName(PEPROCESS pEProcess);

//��ȡע��������·��
//BOOLEAN GetRegisterPath(PUNICODE_STRING pRegPath, PVOID pRegObj);

//Ҫ������ע���ֵ
const PWCHAR ProtectedRegKey = L"test1";
void closeLogFile();

NTSTATUS	Unload(PDRIVER_OBJECT driver)
{
	NTSTATUS status = STATUS_SUCCESS;
	DbgPrint("unload driver");
	closeLogFile();
	if (cookie.QuadPart > 0)
	{
		status = CmUnRegisterCallback(cookie);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("ɾ���ص�����ʧ��0x%X\r\n", status);
		}
		else
		{
			DbgPrint("ɾ���ص������ɹ�\r\n");
		}
	}
	DbgPrint("����ж�����\r\n");
	// CmUnRegisterCallback(cookie);
	return status;
}

BOOLEAN GetRegistryObjectCompleteName(PUNICODE_STRING pRegistryPath, PUNICODE_STRING pPartialRegistryPath, PVOID pRegistryObject)
{
	BOOLEAN foundCompleteName = FALSE;
	BOOLEAN partial = FALSE;
	if ((!MmIsAddressValid(pRegistryObject)) || (pRegistryObject == NULL))
		return FALSE;
	/* Check to see if the partial name is really the complete name */
	if (pPartialRegistryPath != NULL)
	{
		if ((((pPartialRegistryPath->Buffer[0] == '\\') || (pPartialRegistryPath->Buffer[0] == '%')) ||
			((pPartialRegistryPath->Buffer[0] == 'T') && (pPartialRegistryPath->Buffer[1] == 'R') &&
				(pPartialRegistryPath->Buffer[2] == 'Y') && (pPartialRegistryPath->Buffer[3] == '\\'))))
		{
			RtlCopyUnicodeString(pRegistryPath, pPartialRegistryPath);
			partial = TRUE;
			foundCompleteName = TRUE;
		}
	}
	if (!foundCompleteName)
	{
		/* Query the object manager in the kernel for the complete name */
		NTSTATUS status;
		ULONG returnedLength;
		PUNICODE_STRING pObjectName = NULL;
		status = ObQueryNameString(pRegistryObject, (POBJECT_NAME_INFORMATION)pObjectName, 0, &returnedLength);
		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			pObjectName = ExAllocatePoolWithTag(NonPagedPool, returnedLength, REGISTRY_POOL_TAG);
			status = ObQueryNameString(pRegistryObject, (POBJECT_NAME_INFORMATION)pObjectName, returnedLength, &returnedLength);
			if (NT_SUCCESS(status))
			{
				RtlCopyUnicodeString(pRegistryPath, pObjectName);
				foundCompleteName = TRUE;
			}
			ExFreePoolWithTag(pObjectName, REGISTRY_POOL_TAG);
		}
	}
	return foundCompleteName;
}

// ��ȡ��ǰϵͳʱ�䣬�������㷵��unixʱ�䣬����windows�²���ת������������ַ�����
PTCHAR getCurrentTime() {
	LARGE_INTEGER SystemTime;
	LARGE_INTEGER LocalTime;
	TIME_FIELDS TimeFiled;
	TCHAR* time_str = ExAllocatePoolWithTag(PagedPool, 32, 0);
	KeQuerySystemTime(&SystemTime);
	ExSystemTimeToLocalTime(&SystemTime, &LocalTime);
	RtlTimeToTimeFields(&LocalTime, &TimeFiled);
#ifdef UNICODE
#define RtlStringCchPrintf RtlStringCchPrintfW
#else
#define RtlStringCchPrintf RtlStringCchPrintfA
#endif // UNICODE
	RtlStringCchPrintf(
		time_str,
		32,
		TEXT("%4d-%02d-%02d %02d:%02d:%02d:%03d"),
		TimeFiled.Year,
		TimeFiled.Month,
		TimeFiled.Day,              //������ʱ����
		TimeFiled.Hour,
		TimeFiled.Minute,
		TimeFiled.Second,
		TimeFiled.Milliseconds);
	return time_str;
	/*struct _timeb t;
	_ftime(&t);
	return t.time * 1000 + t.millitm;*/
}

//char* getRegValue(char* regPath, char* pValue) {
//	char szSubKey[200];
//	strcpy(szSubKey, regPath);
//	strcpy(szSubKey, pValue);
//	HKEY hRoot = HKEY_CURRENT_USER;
//	//char* szSubKey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
//	HKEY hKey;
//	// ��ָ���Ӽ�
//	DWORD dwDisposition = REG_OPENED_EXISTING_KEY;	// ��������ڲ�����
//	LONG lRet = RegCreateKeyEx(hRoot, szSubKey, 0, NULL,
//		REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition);
//	if (lRet != ERROR_SUCCESS)
//		return NULL;
//	char szModule[MAX_PATH];
//	DWORD len;
//	memset(szModule, '\0', sizeof(szModule));
//	RegQueryValueEx(hKey, "SelfRun", 0, NULL, (BYTE*)szModule, &len);
//	RegCloseKey(hKey);
//	//printf("Ҫ��ѯ�ļ�ֵ����Ϊ��%s\n", szModule);
//	return szModule;
//}

VOID RegReadTest(UNICODE_STRING RegPath, PUNICODE_STRING valueName, PCHAR res)
{
	HANDLE hKey = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES oa;
	ULONG Length = 0;
	//UNICODE_STRING RegPath = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\MyKey");
	//UNICODE_STRING valueName;
	PKEY_VALUE_PARTIAL_INFORMATION pvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool(PagedPool, 1024);

	InitializeObjectAttributes(&oa, &RegPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &oa);
	if (NT_SUCCESS(status))
	{
		//DbgPrint("��ע�����%wZ�ɹ�\n", &RegPath);

		//RtlInitUnicodeString(&valueName, L"�ַ���");
		ZwQueryValueKey(hKey, valueName, KeyValuePartialInformation, pvpi, 1024, &Length);
		//DbgPrint("[length:%d][resLen:%d]\n", pvpi->DataLength, Length);
		switch (pvpi->Type)
		{
		case REG_SZ:
			DbgPrint("[REG_SZ][%S]\n", (PWCHAR)pvpi->Data);//todo
			sprintf(res, "[REG_SZ][%S]\n", (PWCHAR)pvpi->Data);
			break;
		case REG_DWORD:
			DbgPrint("[REG_DWORD][%d]\n", *(PULONG)pvpi->Data);
			sprintf(res, "[REG_DWORD][%d]\n", *(PULONG)pvpi->Data);
			break;
		case REG_BINARY:
			DbgPrint("[REG_BINARY][");
			if (pvpi->DataLength > 0) {
				PCHAR tmp = (PCHAR)ExAllocatePool(NonPagedPool, 1024);
				for (unsigned long i = 0; i < pvpi->DataLength && i < 16; i++) {
					DbgPrint("%02x", pvpi->Data[i]);
					sprintf(&(tmp[3 * i]), "%02x", pvpi->Data[i]);
					if (i < pvpi->DataLength - 1 && i < 15) {
						DbgPrint(" ");
						tmp[3 * i+2] = ' ';
					}
					else {
						tmp[3 * i + 2] = '\0';
					}
				}
				sprintf(res, "[REG_BINARY][%s]\n", tmp);
				ExFreePool(tmp);
			}
			else {
				sprintf(res, "[REG_BINARY][]\n");
			}
			
			DbgPrint("]\n");
			
			
			//DbgPrint("[REG_BINARY][%x]\n", (PBYTE)pvpi->Data);
			break;
		default:
			DbgPrint("[OTHER][]\n");
			sprintf(res, "[OTHER][]\n");
			break;
		}
		//DbgPrint("[type:%d][lenth:%d][valueName:%wZ]\n", pvpi->Type, pvpi->DataLength, valueName);

		ExFreePool((PVOID)pvpi);

		ZwClose(hKey);
	} else {
		DbgPrint("[��ע�����%wZʧ��][]\n", &RegPath);
		sprintf(res, "[��ע�����ʧ��][]\n");
	}
	if (strlen(res) > 1024) {
		res[1020] = '\0';
	}
	else if (strlen(res) == 0) {
		res[0] = '\0';
	}
}

LARGE_INTEGER offset;
HANDLE hfile;
IO_STATUS_BLOCK iostatus;

void initLogFile() {
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING logFileUnicodeString;
	RtlInitUnicodeString(&logFileUnicodeString, LOGFILEPATH);
	//���߸�д��  "\\Device\\HarddiskVolume1\\1.log"
	//��ʼ��objectAttributes
	InitializeObjectAttributes(&objectAttributes,
		&logFileUnicodeString,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);
	//�����ļ�
	NTSTATUS ntStatus = ZwCreateFile(&hfile, //���ļ��ľ��
		GENERIC_WRITE, //����д
		&objectAttributes, //OBJECT_ATTRIBUTES�ṹ�ĵ�ַ �����ļ���
		&iostatus,  //����ZwCreateFile�����Ľ��״̬
		NULL, //��ʼ����ʱ�Ĵ�С
		FILE_ATTRIBUTE_NORMAL, //�´����ļ�������
		FILE_SHARE_READ, //����ʽ
		FILE_OPEN_IF, //��ָ���ļ����ڻ򲻴���ʱӦ��δ���
		FILE_SYNCHRONOUS_IO_NONALERT, //ָ�����ƴ򿪲����;��ʹ�õĸ��ӱ�־λ
		NULL, //ָ���ѡ����չ������
		0); //��չ�������ĳ���
	if (!NT_SUCCESS(ntStatus)) {
		DbgPrint("Create file [%wZ] unsuccessfully!\n", logFileUnicodeString);
	}

	//�ļ�����
	// ��ȡ�ļ�ĩβָ���ƫ����
	FILE_STANDARD_INFORMATION fsi;
	ntStatus = ZwQueryInformationFile(hfile,
		&iostatus,
		&fsi,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);

	if (NT_SUCCESS(ntStatus))
	{
		DbgPrint("FILE length:%lld\n", fsi.EndOfFile.QuadPart);
		offset = fsi.EndOfFile;
	}
	else {
		offset.QuadPart = 0i64;
	}
}

ULONG_PTR writeToLogFile(PCHAR log) {
	//д�ļ�
	NTSTATUS ntStatus = ZwWriteFile(hfile,
		NULL,
		NULL,
		NULL,
		&iostatus,
		log,
		min(strlen(log) * sizeof(CHAR), 4090),
		&offset,
		NULL);

	if (!NT_SUCCESS(ntStatus)) {
		DbgPrint("Write file unsuccessfully!\n");
	}
	else {
		DbgPrint("Write file %lld byte, len(log)=%lld\n", iostatus.Information, min(strlen(log) * sizeof(CHAR), 4090));
		offset.QuadPart += iostatus.Information;
	}
	return iostatus.Information;
}

void closeLogFile() {
	//�ر��ļ����
	ZwClose(hfile);
}

NTSTATUS RegistryCallback(
	IN PVOID CallbackContext,
	IN PVOID Argument1,//�������ͣ�
	IN PVOID Argument2//�����Ľṹ��ָ��
)
{
	NTSTATUS	CallbackStatus = STATUS_SUCCESS;
	//����ע�������·��
	UNICODE_STRING	RegPath;
	// ��������������
	REG_NOTIFY_CLASS uOpCode = (REG_NOTIFY_CLASS)Argument1;
	//// ���浱ǰ����ע���Ľ���EPROCESS
	PEPROCESS pEProcess = NULL;
	PUCHAR pProcName = NULL;
	PWCHAR pValue = NULL;
	PCHAR kvstring = NULL;
	// ��ȡ��ǰ������
	pEProcess = PsGetCurrentProcess();
	if (pEProcess != NULL) {
		pProcName = PsGetProcessImageFileName(pEProcess);
	}

	// �����ڴ���������ע���·��
	RegPath.Length = 0;
	RegPath.MaximumLength = 2048 * sizeof(WCHAR);
	RegPath.Buffer = ExAllocatePoolWithTag(NonPagedPool, RegPath.MaximumLength, REGISTRY_POOL_TAG);
	if (RegPath.Buffer == NULL) {
		DbgPrint("ExAllocatePool Error");
		goto exit;
		//return STATUS_SUCCESS;
	}
	PCHAR log = NULL;
	// �������¼� 
	switch (uOpCode)
	{
	// ����ע����֮ǰ
	case RegNtPreCreateKey:
		if (!GetRegistryObjectCompleteName(&RegPath, NULL, ((PREG_CREATE_KEY_INFORMATION)Argument2)->RootObject)) {
			DbgPrint("[RegNtPreCreateKey]��ȡע���·��ʧ��\r\n");
			break;
		}
		// ��ʾ
		DbgPrint("[%s][RegNtPreCreateKey][%wZ][%wZ]\n", pProcName, &RegPath, ((PREG_CREATE_KEY_INFORMATION)Argument2)->CompleteName);
		break;
	// ��ע����֮ǰ
	//case RegNtPreQueryKey:
	//	if (!GetRegistryObjectCompleteName(&RegPath, NULL, ((PREG_QUERY_KEY_INFORMATION)Argument2)->Object)) {
	//		DbgPrint("[RegNtPreQueryKey]��ȡע���·��ʧ��\r\n");
	//		break;
	//	}
	//	// ��ʾ
	//	DbgPrint("[%s][RegNtPreQueryKey][%wZ]\n", pProcName, &RegPath);
	//	break;
	// �޸ļ�ֵ֮ǰ
	case RegNtPreSetValueKey:
		if (!GetRegistryObjectCompleteName(&RegPath, NULL, ((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->Object)) {
			DbgPrint("[RegNtPreSetValueKey]��ȡע���·��ʧ��\r\n");
			break;
		}
		pValue = ((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->ValueName->Buffer;
		//�ж��Ƿ���Ҫ����
		//if (wcsstr(pValue, ProtectedRegKey)) {
		//	DbgPrint("[RegNtPreSetValueKey][%wZ][%ws]\r\n", &RegPath, pValue);
		//	if (pProcName) {
		//		DbgPrint("����[%s]��ͼ�޸�ע���,���سɹ�\r\n", pProcName);
		//	}
		//	CallbackStatus = STATUS_ACCESS_DENIED;    //�Բ�����������
		//} else {
		DbgPrint("[%s][%s][RegNtPreSetValueKey][%wZ][%wZ]", getCurrentTime(), pProcName, &RegPath, ((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->ValueName);
		//RtlAppendUnicodeStringToString(&RegPath, &pValue);
		kvstring = (PCHAR)ExAllocatePool(NonPagedPool, 1024);
		RegReadTest(RegPath, ((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->ValueName, kvstring);
		//DbgPrint("[%s][%s][RegNtPreSetValueKey][%wZ][%wZ]%s\0", getCurrentTime(), pProcName, &RegPath, ((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->ValueName, kvstring);
		log = (PCHAR)ExAllocatePool(NonPagedPool, 4096);
		sprintf(log, "[%s][%s][RegNtPreSetValueKey][%wZ][%wZ]%s\0", getCurrentTime(), pProcName, &RegPath, ((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->ValueName, kvstring);
		//}
		break;
		// �޸ļ�ֵ֮��
	case RegNtPostSetValueKey:
		if (!GetRegistryObjectCompleteName(&RegPath, NULL, ((PREG_POST_OPERATION_INFORMATION)Argument2)->Object)) {
			DbgPrint("[RegNtPostSetValueKey]��ȡע���·��ʧ��\r\n");
			break;
		}
		DbgPrint("[%s][%s][RegNtPostSetValueKey][%wZ][%wZ]", getCurrentTime(), pProcName, &RegPath,((PREG_QUERY_VALUE_KEY_INFORMATION)((PREG_POST_OPERATION_INFORMATION)Argument2)->PreInformation)->ValueName);
		kvstring = (PCHAR)ExAllocatePool(NonPagedPool, 1024);
		RegReadTest(RegPath, ((PREG_QUERY_VALUE_KEY_INFORMATION)((PREG_POST_OPERATION_INFORMATION)Argument2)->PreInformation)->ValueName, kvstring);
		kvstring[1020] = '\0';
		log = (PCHAR)ExAllocatePool(NonPagedPool, 4096);
		sprintf(log, "[%s][%s][RegNtPostSetValueKey][%wZ][%wZ]%s\0", getCurrentTime(), pProcName, &RegPath, ((PREG_QUERY_VALUE_KEY_INFORMATION)((PREG_POST_OPERATION_INFORMATION)Argument2)->PreInformation)->ValueName, kvstring);
		//DbgPrint("[lenth:%d][%s]\n", strlen(log), log);
		// PreInformation�ľ�����Ϣ�ڣ�https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_reg_post_operation_information
		break;
	// ɾ��ע����֮ǰ
	case RegNtPreDeleteKey:
		if (!GetRegistryObjectCompleteName(&RegPath, NULL, ((PREG_DELETE_KEY_INFORMATION)Argument2)->Object)) {
			DbgPrint("[RegNtPreDeleteKey]��ȡע���·��ʧ��\r\n");
			break;
		}
		DbgPrint("[%s][%s][RegNtPreDeleteKey][%wZ]\r\n", getCurrentTime(), pProcName, &RegPath);
		
		log = (PCHAR)ExAllocatePool(NonPagedPool, 4096);
		sprintf(log, "[%s][%s][RegNtPreDeleteKey][%wZ]\n\0", getCurrentTime(), pProcName, &RegPath);

		//DbgPrint("DeleteKey:%wZ", RegPath);
		break;
	// ɾ��ע����֮ǰ
	/*case RegNtPreRenameKey:
		if (!GetRegistryObjectCompleteName(&RegPath, NULL, ((PREG_RENAME_KEY_INFORMATION)Argument2)->Object)) {
			DbgPrint("[RegNtPreRenameKey]��ȡע���·��ʧ��\r\n");
		}
		DbgPrint("[RegNtPreRenameKey][%wZ][%s]\n", &RegPath, ((PREG_RENAME_KEY_INFORMATION)Argument2)->NewName);
		break;*/
	// ɾ��ע���ֵ֮ǰ
	case RegNtPreDeleteValueKey:
		if (!GetRegistryObjectCompleteName(&RegPath, NULL, ((PREG_DELETE_KEY_INFORMATION)Argument2)->Object)) {
			DbgPrint("[RegNtPreSetValueKey]��ȡע���·��ʧ��\r\n");
			break;
		}
		//pValue = ((PREG_DELETE_VALUE_KEY_INFORMATION)Argument2)->ValueName->Buffer;
		////�ж��Ƿ���Ҫ����
		//if (wcsstr(pValue, ProtectedRegKey) || wcsstr(pValue, ProtectedRegKey))
		//{
		//	DbgPrint("[RegNtPreSetValueKey][%wZ][%ws]\r\n", &RegPath, pValue);
		//	if (pProcName) {
		//		DbgPrint("����[%s]��ͼ�޸�ע���,���سɹ�\r\n", pProcName);
		//	}
		//	CallbackStatus = STATUS_ACCESS_DENIED;    //�Բ�����������
		//}
		DbgPrint("[%s][%s][RegNtPreDeleteValueKey][%wZ][%wZ]", getCurrentTime(), pProcName, &RegPath, ((PREG_DELETE_VALUE_KEY_INFORMATION)Argument2)->ValueName);
		kvstring = (PCHAR)ExAllocatePool(NonPagedPool, 1024);
		RegReadTest(RegPath, ((PREG_DELETE_VALUE_KEY_INFORMATION)Argument2)->ValueName, kvstring);
		kvstring[1020] = '\0';
		
		log = (PCHAR)ExAllocatePool(NonPagedPool, 4096);
		sprintf(log, "[%s][%s][RegNtPreDeleteValueKey][%wZ][%wZ]%s\0", getCurrentTime(), pProcName, &RegPath, ((PREG_DELETE_VALUE_KEY_INFORMATION)Argument2)->ValueName, kvstring);
		break;
	default:
		break;
	}
	if (log != NULL) {
		writeToLogFile(log);
		ExFreePool(log);
	}
	if (kvstring != NULL) {
		ExFreePool(kvstring);
	}
	if (RegPath.Buffer != NULL) {
		ExFreePoolWithTag(RegPath.Buffer, REGISTRY_POOL_TAG);
	}
	
exit:
	/*if (RegPath.Buffer) {
		ExFreePool(RegPath.Buffer);
		RegPath.Buffer = NULL;
	}*/
	return CallbackStatus;
}

NTSTATUS	DriverEntry(PDRIVER_OBJECT	driver, PUNICODE_STRING	RegPath) {
	DbgPrint("Driver Entry");
	NTSTATUS status = STATUS_SUCCESS;

	status = CmRegisterCallback(RegistryCallback, NULL, &cookie);
	if (!NT_SUCCESS(status)) {
		DbgPrint("�ص���������ʧ�� 0x%X\r\n", status);
	} else {
		DbgPrint("�ص��������óɹ�\r\n");
		initLogFile();
	}
//exit:
	driver->DriverUnload = Unload;
	return STATUS_SUCCESS;
}

