## DbgPrint格式输出参考
https://blog.csdn.net/wowolook/article/details/7588481?spm=1001.2101.3001.6650.1&utm_medium=distribute.pc_relevant.none-task-blog-2%7Edefault%7ECTRLIST%7Edefault-1-7588481-blog-115482281.pc_relevant_default&depth_1-utm_source=distribute.pc_relevant.none-task-blog-2%7Edefault%7ECTRLIST%7Edefault-1-7588481-blog-115482281.pc_relevant_default&utm_relevant_index=2
## Windows内核编程之：文件操作
http://t.zoukankan.com/qintangtao-p-3067240.html
官方库说明：https://docs.microsoft.com/zh-cn/windows-hardware/drivers/ddi/wdm/nf-wdm-zwwritefile
## Windows驱动开发内存常用函数
https://blog.csdn.net/m0_46125480/article/details/120587486
## 注册表事件与对应的结构体关系
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
## 问题记录
### 1.文件写入导致蓝屏
问题描述：当加入日志写入文件功能后，频繁出现windows蓝屏。即在`RegistryCallback`回调函数中的结尾，将产生的日志写入文件中。
原因分析：每次写入文件操作中，包含了打开文件句柄，查询文件长度，写入内容。在大量回调函数被执行的时候，可能会存在对文件句柄资源的争夺，以及并发（可能）写入的一致性问题，最终导致系统蓝屏。
改进方法：
1. 在驱动初始化的时候执行日志文件的初始化，并在全局变量中存储文件句柄；
2. 每次触发回调函数时，调用封装好的`writeToLog(PCHAR log)`函数，将日志写入到文件中；
3. 在驱动卸载时，关闭日志文件的句柄。