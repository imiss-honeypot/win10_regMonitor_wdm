## DbgPrint��ʽ����ο�
https://blog.csdn.net/wowolook/article/details/7588481?spm=1001.2101.3001.6650.1&utm_medium=distribute.pc_relevant.none-task-blog-2%7Edefault%7ECTRLIST%7Edefault-1-7588481-blog-115482281.pc_relevant_default&depth_1-utm_source=distribute.pc_relevant.none-task-blog-2%7Edefault%7ECTRLIST%7Edefault-1-7588481-blog-115482281.pc_relevant_default&utm_relevant_index=2
## Windows�ں˱��֮���ļ�����
http://t.zoukankan.com/qintangtao-p-3067240.html
�ٷ���˵����https://docs.microsoft.com/zh-cn/windows-hardware/drivers/ddi/wdm/nf-wdm-zwwritefile
## Windows���������ڴ泣�ú���
https://blog.csdn.net/m0_46125480/article/details/120587486
## ע����¼����Ӧ�Ľṹ���ϵ
https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-ex_callback_function
REG_NOTIFY_CLASS value	Structure type
RegNtDeleteKey	REG_DELETE_KEY_INFORMATION
RegNtPreDeleteKey	REG_DELETE_KEY_INFORMATION
RegNtPostDeleteKey	REG_POST_OPERATION_INFORMATION
RegNtSetValueKey	REG_SET_VALUE_KEY_INFORMATION
RegNtPreSetValueKey	REG_SET_VALUE_KEY_INFORMATION
RegNtPostSetValueKey	REG_POST_OPERATION_INFORMATION
RegNtDeleteValueKey	REG_DELETE_VALUE_KEY_INFORMATION
RegNtPreDeleteValueKey	REG_DELETE_VALUE_KEY_INFORMATION
RegNtPostDeleteValueKey	REG_POST_OPERATION_INFORMATION
## �����¼
### 1.�ļ�д�뵼������
������������������־д���ļ����ܺ�Ƶ������windows����������`RegistryCallback`�ص������еĽ�β������������־д���ļ��С�
ԭ�������ÿ��д���ļ������У������˴��ļ��������ѯ�ļ����ȣ�д�����ݡ��ڴ����ص�������ִ�е�ʱ�򣬿��ܻ���ڶ��ļ������Դ�����ᣬ�Լ����������ܣ�д���һ�������⣬���յ���ϵͳ������
�Ľ�������
1. ��������ʼ����ʱ��ִ����־�ļ��ĳ�ʼ��������ȫ�ֱ����д洢�ļ������
2. ÿ�δ����ص�����ʱ�����÷�װ�õ�`writeToLog(PCHAR log)`����������־д�뵽�ļ��У�
3. ������ж��ʱ���ر���־�ļ��ľ����