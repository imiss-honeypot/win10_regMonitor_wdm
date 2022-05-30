#include <ntddk.h>

#define REGISTRY_POOL_TAG 'lxw'

LARGE_INTEGER	cookie;

NTKERNELAPI NTSTATUS ObQueryNameString
(
	IN  PVOID Object,
	OUT POBJECT_NAME_INFORMATION ObjectNameInfo,
	IN  ULONG Length,
	OUT PULONG ReturnLength
);

NTKERNELAPI NTSTATUS RtlUnicodeStringCopy
(
	__out  PUNICODE_STRING DestinationString,
	__in   PUNICODE_STRING SourceString
);


NTSTATUS	Unload(PDRIVER_OBJECT driver)
{
	DbgPrint("unload driver");
	CmUnRegisterCallback(cookie);
	return STATUS_SUCCESS;
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
			pObjectName = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, returnedLength, REGISTRY_POOL_TAG);
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

NTSTATUS RegistryCallback(
	IN PVOID CallbackContext,
	IN PVOID Argument1,//操作类型，
	IN PVOID Argument2//操作的结构体指针
)
{
	long type;
	NTSTATUS	CallbackStatus = STATUS_SUCCESS;
	UNICODE_STRING	RegPath;
	DbgPrint("Enter RegCallback Success");
	RegPath.Length = 0;
	RegPath.MaximumLength = 2048 * sizeof(WCHAR);
	RegPath.Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, RegPath.MaximumLength, REGISTRY_POOL_TAG);
	if (RegPath.Buffer == NULL)
		return STATUS_SUCCESS;
	type = (long)Argument1;
	switch (type)
	{
	case	RegNtPreDeleteKey:
		GetRegistryObjectCompleteName(&RegPath, NULL, ((PREG_DELETE_KEY_INFORMATION)Argument2)->Object);
		DbgPrint("DeleteKey:%wZ", RegPath);
		break;
	case	RegNtPreDeleteValueKey:
		GetRegistryObjectCompleteName(&RegPath, NULL, ((PREG_DELETE_KEY_INFORMATION)Argument2)->Object);
		DbgPrint("DeleteValueValName: %wZ", ((PREG_DELETE_VALUE_KEY_INFORMATION)Argument2)->ValueName);
		DbgPrint("DeleteValue:%wZ", RegPath);
		//return STATUS_ACCESS_DENIED;//防止删除键
		break;
	default:
		break;
	}
	if (RegPath.Buffer != NULL) {
		ExFreePoolWithTag(RegPath.Buffer, REGISTRY_POOL_TAG);
	}
	return CallbackStatus;
}

NTSTATUS	DriverEntry(PDRIVER_OBJECT	driver, PUNICODE_STRING	RegPath)
{
	DbgPrint("Driver Entry");

	driver->DriverUnload = (PDRIVER_UNLOAD)Unload;
	//严重性	代码	说明	项目	文件	行	禁止显示状态	错误(活动)	E0513	不能将 "NTSTATUS (*)(PDRIVER_OBJECT driver)" 类型的值分配到 "PDRIVER_UNLOAD" 类型的实体	MyDriver1	C : \Users\ckl\source\repos\MyDriver1\main.cpp	110


	CmRegisterCallback(RegistryCallback, NULL, &cookie);
	return STATUS_SUCCESS;
}

