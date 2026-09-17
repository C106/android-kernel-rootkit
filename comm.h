#include <linux/slab.h>
#include <linux/random.h>
#include <linux/string.h>

typedef struct _COPY_MEMORY {
    pid_t pid;
    uintptr_t addr;
    void* buffer;
    size_t size;
} COPY_MEMORY, *PCOPY_MEMORY;

typedef struct _proinf{
    uintptr_t cmaddr;
    uintptr_t mbaddr;
    uintptr_t isreadaddr;
    int isread;
}proinf, *PCOPY_proinf;

typedef struct _MODULE_BASE {
    pid_t pid;
    char* name;
    uintptr_t base;
} MODULE_BASE, *PMODULE_BASE;

// ==================== 硬件断点相关结构 ====================

// 创建断点请求
typedef struct _BP_CREATE_REQ {
    unsigned long addr;      // 断点地址
    int type;                // 断点类型 (0=exec, 1=read, 2=write, 3=rw)
    int len;                 // 断点长度 (1/2/4/8)
    pid_t pid;               // 目标进程PID（0=全局）
    int max_records;         // 最大保存记录数
    int bp_id;               // 返回的断点ID
} BP_CREATE_REQ, *PBP_CREATE_REQ;

// 删除断点请求
typedef struct _BP_REMOVE_REQ {
    int bp_id;               // 断点ID
} BP_REMOVE_REQ, *PBP_REMOVE_REQ;

// 获取命中记录请求
typedef struct _BP_GET_HITS_REQ {
    int bp_id;               // 断点ID
    void* buffer;            // 用户空间缓冲区
    int max_count;           // 最多获取多少条
    int actual_count;        // 实际返回的记录数
} BP_GET_HITS_REQ, *PBP_GET_HITS_REQ;

// 修改寄存器请求
typedef struct _BP_MODIFY_REG_REQ {
    int bp_id;               // 断点ID
    int record_index;        // 记录索引（-1表示下次命中）
    int reg_index;           // 寄存器索引
    unsigned long value;     // 新值
} BP_MODIFY_REG_REQ, *PBP_MODIFY_REG_REQ;

// 清除记录请求
typedef struct _BP_CLEAR_REQ {
    int bp_id;               // 断点ID
} BP_CLEAR_REQ, *PBP_CLEAR_REQ;

char *get_rand_str(void)
{
    int seed;
    int flag;
    int i;
    unsigned short lstr;
    char *string = kmalloc(10 * sizeof(char), GFP_KERNEL);
    const char *str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    lstr = strlen(str);
    if (!string) {
        printk("驱动名称申请内存失败");
        return NULL;
    }
	for (i = 0; i < 6; i++) {
		get_random_bytes(&seed, sizeof(int));
		flag = seed % lstr;
		if (flag < 0)
			flag = flag * -1;
		string[i] = str[flag];
	}
	string[6] = '\0';
	return string;
}

int dispatch_open(struct inode *node, struct file *file);
int dispatch_close(struct inode *node, struct file *file);
