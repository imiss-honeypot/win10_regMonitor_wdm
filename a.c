#include <ntifs.h>
#include <windef.h>
#include <ntstrsafe.h>

#define REGISTRY_POOL_TAG 'lxw'

// 日志文件路径，必须加上前面的？？
PCWSTR LOGFILEPATH = L"\\??\\C:\\1.log";

//注册表回调使用的Cookie
LARGE_INTEGER	cookie;

//根据对象获取名称
NTKERNELAPI NTSTATUS ObQueryNameString
(
	IN  PVOID Object,
	OUT POBJECT_NAME_INFORMATION ObjectNameInfo,
	IN  ULONG Length,
	OUT PULONG ReturnLength
);

//根据EPROCESS获取进程名称
PUCHAR PsGetProcessImageFileName(PEPROCESS pEProcess);

//获取注册表的完整路径
//BOOLEAN GetRegisterPath(PUNICODE_STRING pRegPath, PVOID pRegObj);

//要保护的注册表值
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
			DbgPrint("删除回调函数失败0x%X\r\n", status);
		}
		else
		{
			DbgPrint("删除回调函数成功\r\n");
		}
	}
	DbgPrint("驱动卸载完成\r\n");
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

// 获取当前系统时间，本来打算返回unix时间，但是windows下不好转换，就输出了字符串。
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
		TimeFiled.Day,              //年月日时分秒
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
//	// 打开指定子键
//	DWORD dwDisposition = REG_OPENED_EXISTING_KEY;	// 如果不存在不创建
//	LONG lRet = RegCreateKeyEx(hRoot, szSubKey, 0, NULL,
//		REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition);
//	if (lRet != ERROR_SUCCESS)
//		return NULL;
//	char szModule[MAX_PATH];
//	DWORD len;
//	memset(szModule, '\0', sizeof(szModule));
//	RegQueryValueEx(hKey, "SelfRun", 0, NULL, (BYTE*)szModule, &len);
//	RegCloseKey(hKey);
//	//printf("要查询的键值数据为：%s\n", szModule);
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
		//DbgPrint("打开注册表项%wZ成功\n", &RegPath);

		//RtlInitUnicodeString(&valueName, L"字符串");
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
		DbgPrint("[打开注册表项%wZ失败][]\n", &RegPath);
		sprintf(res, "[打开注册表项失败][]\n");
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
	//或者改写成  "\\Device\\HarddiskVolume1\\1.log"
	//初始化objectAttributes
	InitializeObjectAttributes(&objectAttributes,
		&logFileUnicodeString,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);
	//创建文件
	NTSTATUS ntStatus = ZwCreateFile(&hfile, //打开文件的句柄
		GENERIC_WRITE, //读，写
		&objectAttributes, //OBJECT_ATTRIBUTES结构的地址 包含文件名
		&iostatus,  //接收ZwCreateFile操作的结果状态
		NULL, //初始分配时的大小
		FILE_ATTRIBUTE_NORMAL, //新创建文件的属性
		FILE_SHARE_READ, //共享方式
		FILE_OPEN_IF, //当指定文件存在或不存在时应如何处理
		FILE_SYNCHRONOUS_IO_NONALERT, //指定控制打开操作和句柄使用的附加标志位
		NULL, //指向可选的扩展属性区
		0); //扩展属性区的长度
	if (!NT_SUCCESS(ntStatus)) {
		DbgPrint("Create file [%wZ] unsuccessfully!\n", logFileUnicodeString);
	}

	//文件操作
	// 获取文件末尾指针和偏移量
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
	//写文件
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
	//关闭文件句柄
	ZwClose(hfile);
}

NTSTATUS RegistryCallback(
	IN PVOID CallbackContext,
	IN PVOID Argument1,//操作类型，
	IN PVOID Argument2//操作的结构体指针
)
{
	NTSTATUS	CallbackStatus = STATUS_SUCCESS;
	//保存注册表完整路径
	UNICODE_STRING	RegPath;
	// 保存操作码的类型
	REG_NOTIFY_CLASS uOpCode = (REG_NOTIFY_CLASS)Argument1;
	//// 保存当前操作注册表的进程EPROCESS
	PEPROCESS pEProcess = NULL;
	PUCHAR pProcName = NULL;
	PWCHAR pValue = NULL;
	PCHAR kvstring = NULL;
	// 获取当前进程名
	pEProcess = PsGetCurrentProcess();
	if (pEProcess != NULL) {
		pProcName = PsGetProcessImageFileName(pEProcess);
	}

	// 申请内存用来保存注册表路径
	RegPath.Length = 0;
	RegPath.MaximumLength = 2048 * sizeof(WCHAR);
	RegPath.Buffer = ExAllocatePoolWithTag(NonPagedPool, RegPath.MaximumLength, REGISTRY_POOL_TAG);
	if (RegPath.Buffer == NULL) {
		DbgPrint("ExAllocatePool Error");
		goto exit;
		//return STATUS_SUCCESS;
	}
	PCHAR log = NULL;
	// 处理监控事件 
	switch (uOpCode)
	{
	// 创建注册表键之前
	case RegNtPreCreateKey:
		if (!GetRegistryObjectCompleteName(&RegPath, NULL, ((PREG_CREATE_KEY_INFORMATION)Argument2)->RootObject)) {
			DbgPrint("[RegNtPreCreateKey]获取注册表路径失败\r\n");
			break;
		}
		// 显示
		DbgPrint("[%s][RegNtPreCreateKey][%wZ][%wZ]\n", pProcName, &RegPath, ((PREG_CREATE_KEY_INFORMATION)Argument2)->CompleteName);
		break;
	// 打开注册表键之前
	//case RegNtPreQueryKey:
	//	if (!GetRegistryObjectCompleteName(&RegPath, NULL, ((PREG_QUERY_KEY_INFORMATION)Argument2)->Object)) {
	//		DbgPrint("[RegNtPreQueryKey]获取注册表路径失败\r\n");
	//		break;
	//	}
	//	// 显示
	//	DbgPrint("[%s][RegNtPreQueryKey][%wZ]\n", pProcName, &RegPath);
	//	break;
	// 修改键值之前
	case RegNtPreSetValueKey:
		if (!GetRegistryObjectCompleteName(&RegPath, NULL, ((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->Object)) {
			DbgPrint("[RegNtPreSetValueKey]获取注册表路径失败\r\n");
			break;
		}
		pValue = ((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->ValueName->Buffer;
		//判断是否需要保护
		//if (wcsstr(pValue, ProtectedRegKey)) {
		//	DbgPrint("[RegNtPreSetValueKey][%wZ][%ws]\r\n", &RegPath, pValue);
		//	if (pProcName) {
		//		DbgPrint("进程[%s]试图修改注册表,拦截成功\r\n", pProcName);
		//	}
		//	CallbackStatus = STATUS_ACCESS_DENIED;    //对操作进行拦截
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
		// 修改键值之后
	case RegNtPostSetValueKey:
		if (!GetRegistryObjectCompleteName(&RegPath, NULL, ((PREG_POST_OPERATION_INFORMATION)Argument2)->Object)) {
			DbgPrint("[RegNtPostSetValueKey]获取注册表路径失败\r\n");
			break;
		}
		DbgPrint("[%s][%s][RegNtPostSetValueKey][%wZ][%wZ]", getCurrentTime(), pProcName, &RegPath,((PREG_QUERY_VALUE_KEY_INFORMATION)((PREG_POST_OPERATION_INFORMATION)Argument2)->PreInformation)->ValueName);
		kvstring = (PCHAR)ExAllocatePool(NonPagedPool, 1024);
		RegReadTest(RegPath, ((PREG_QUERY_VALUE_KEY_INFORMATION)((PREG_POST_OPERATION_INFORMATION)Argument2)->PreInformation)->ValueName, kvstring);
		kvstring[1020] = '\0';
		log = (PCHAR)ExAllocatePool(NonPagedPool, 4096);
		sprintf(log, "[%s][%s][RegNtPostSetValueKey][%wZ][%wZ]%s\0", getCurrentTime(), pProcName, &RegPath, ((PREG_QUERY_VALUE_KEY_INFORMATION)((PREG_POST_OPERATION_INFORMATION)Argument2)->PreInformation)->ValueName, kvstring);
		//DbgPrint("[lenth:%d][%s]\n", strlen(log), log);
		// PreInformation的具体信息在：https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_reg_post_operation_information
		break;
	// 删除注册表键之前
	case RegNtPreDeleteKey:
		if (!GetRegistryObjectCompleteName(&RegPath, NULL, ((PREG_DELETE_KEY_INFORMATION)Argument2)->Object)) {
			DbgPrint("[RegNtPreDeleteKey]获取注册表路径失败\r\n");
			break;
		}
		DbgPrint("[%s][%s][RegNtPreDeleteKey][%wZ]\r\n", getCurrentTime(), pProcName, &RegPath);
		
		log = (PCHAR)ExAllocatePool(NonPagedPool, 4096);
		sprintf(log, "[%s][%s][RegNtPreDeleteKey][%wZ]\n\0", getCurrentTime(), pProcName, &RegPath);

		//DbgPrint("DeleteKey:%wZ", RegPath);
		break;
	// 删除注册表键之前
	/*case RegNtPreRenameKey:
		if (!GetRegistryObjectCompleteName(&RegPath, NULL, ((PREG_RENAME_KEY_INFORMATION)Argument2)->Object)) {
			DbgPrint("[RegNtPreRenameKey]获取注册表路径失败\r\n");
		}
		DbgPrint("[RegNtPreRenameKey][%wZ][%s]\n", &RegPath, ((PREG_RENAME_KEY_INFORMATION)Argument2)->NewName);
		break;*/
	// 删除注册表值之前
	case RegNtPreDeleteValueKey:
		if (!GetRegistryObjectCompleteName(&RegPath, NULL, ((PREG_DELETE_KEY_INFORMATION)Argument2)->Object)) {
			DbgPrint("[RegNtPreSetValueKey]获取注册表路径失败\r\n");
			break;
		}
		//pValue = ((PREG_DELETE_VALUE_KEY_INFORMATION)Argument2)->ValueName->Buffer;
		////判断是否需要保护
		//if (wcsstr(pValue, ProtectedRegKey) || wcsstr(pValue, ProtectedRegKey))
		//{
		//	DbgPrint("[RegNtPreSetValueKey][%wZ][%ws]\r\n", &RegPath, pValue);
		//	if (pProcName) {
		//		DbgPrint("进程[%s]试图修改注册表,拦截成功\r\n", pProcName);
		//	}
		//	CallbackStatus = STATUS_ACCESS_DENIED;    //对操作进行拦截
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
		DbgPrint("回调函数设置失败 0x%X\r\n", status);
	} else {
		DbgPrint("回调函数设置成功\r\n");
		initLogFile();
	}
//exit:
	driver->DriverUnload = Unload;
	return STATUS_SUCCESS;
}

