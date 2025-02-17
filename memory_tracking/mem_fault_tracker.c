#define LINUX

#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/workqueue.h>
#include <linux/proc_fs.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/timer.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/cdev.h>
#include "util.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Heramb Joshi herambku@gmail.com");

struct proc_dir_entry *proc_dir;
static long* virtual_buffer;
static int write_index = 0;
static struct cdev monitor_device;
static struct mutex pid_list_lock;
struct list_head pid_linkedlist;
static long size_of_pid_linkedlist = 0;
struct kmem_cache *proc_node_allocator = NULL;
struct timer_list wakeup_timer;
static struct workqueue_struct *list_update_workqueue;
static struct work_struct update_task;
struct mp3_task_struct {
	int pid;
	struct task_struct* user_task;
	unsigned long user_time; // in jiffies
	unsigned long system_time; // in jiffies
	unsigned long minor_faults;
	unsigned long major_faults;
	struct list_head list;
};
static bool work_queue_initialized = false;

#define DEBUG 1
#define LINE_LENGTH 17 // 16 character pid + '\n'
#define PROC_NAME "status"
#define PROC_DIR "mem_fault"
#define REGISTER 'R'
#define UNREGISTER 'U'
#define PAGE_COUNT 256
#define KMEM_LABEL "mem_fault/status"
#define PROFILING_DELAY 50
#define MAJOR_NUMBER 423
#define IDENTIFIER "node"

void timer_callback(struct timer_list *timer) {
	queue_work(list_update_workqueue, &update_task);
	if (work_queue_initialized) {
		mod_timer(&wakeup_timer, jiffies + msecs_to_jiffies(PROFILING_DELAY));
	}
}

void write_content_to_buffer(unsigned long cpu_use, unsigned long major_fault, unsigned long minor_fault) {
	if (write_index == 0) {
		virtual_buffer[write_index] = -1;
		write_index++;
	}
	virtual_buffer[write_index] = jiffies;
	write_index++;
	virtual_buffer[write_index] = minor_fault;
	write_index++;
	virtual_buffer[write_index] = major_fault;
	write_index++;
	virtual_buffer[write_index] = cpu_use;
	write_index++;
	virtual_buffer[write_index] = -1;
}

static void queue_work_function(struct work_struct *work) {
	struct mp3_task_struct *tmp, *data;
	unsigned long user_time, system_time, minor_faults, major_faults;
	unsigned long total_cpu_time = 0, total_minor_faults = 0, total_major_faults = 0;

	mutex_lock(&pid_list_lock);

	list_for_each_entry_safe(data, tmp, &pid_linkedlist, list) {
		if (get_cpu_use(data->pid, &minor_faults, &major_faults, &user_time, &system_time)) {
			list_del(&data->list);
			kmem_cache_free(proc_node_allocator, data);
			size_of_pid_linkedlist--;
		} else {
			data->user_time = user_time;
			data->system_time = system_time;
			data->minor_faults = minor_faults;
			data->major_faults = major_faults;
			total_cpu_time += user_time + system_time;
			total_minor_faults += minor_faults;
			total_major_faults += major_faults;
		}
	}

	if (size_of_pid_linkedlist == 0) {
		work_queue_initialized = false;
		mutex_unlock(&pid_list_lock);
		return;
	}

	write_content_to_buffer(total_cpu_time, major_faults, minor_faults);

	mutex_unlock(&pid_list_lock);
}

static int register_process(int pid) {
	struct mp3_task_struct *new_proc_data;

	new_proc_data = kmem_cache_alloc(proc_node_allocator, GFP_KERNEL);

	if (!new_proc_data) {
		pr_warn(KERN_ALERT "Failed to allocate memory for new node to process list\n");
		return -ENOMEM;
	}

	new_proc_data->pid = pid;
	new_proc_data->user_task = find_task_by_pid((unsigned int)pid);
	new_proc_data->user_time = 0;
	new_proc_data->system_time = 0;
	new_proc_data->minor_faults = 0;
	new_proc_data->major_faults = 0;

	list_add_tail(&new_proc_data->list, &pid_linkedlist);
	size_of_pid_linkedlist++;

	return 0;
}


static int unregister_process(int pid) {
	struct mp3_task_struct *tmp, *data;

	list_for_each_entry_safe(data, tmp, &pid_linkedlist, list) {
		if (data->pid == pid) {
			list_del(&data->list);
			kmem_cache_free(proc_node_allocator, data);
			size_of_pid_linkedlist--;
		} 
	}

	return 0;
} 


static bool check_invalid_token(char token) { 
	return token != REGISTER && token != UNREGISTER;
}

static ssize_t proc_write(struct file* file, const char __user *buffer, size_t len, loff_t *offset) {
	char input[18]; // input consists of 1 decision token, 16 char pid
	char decision;
	int pid;
	int result = 0;

	mutex_lock(&pid_list_lock);

	memset(input, 0, sizeof(input));
	
	if (copy_from_user(input, buffer, len)) {
		// trying to access bad address
		mutex_unlock(&pid_list_lock);
		return -EFAULT;
	}

	if(sscanf(input, "%c %d", &decision, &pid) != 2) {
		pr_warn(KERN_ALERT "Invalid input format, required '<U/R> <pid>'\n");
		mutex_unlock(&pid_list_lock);
		return EINVAL;
	}

	if (check_invalid_token(decision)) {
		pr_warn(KERN_ALERT "Invalid token %c\n", decision);
		mutex_unlock(&pid_list_lock);
		return EINVAL;
	}

	switch (decision) {
		case REGISTER:
			result = register_process(pid);
			mutex_unlock(&pid_list_lock);
			if (!work_queue_initialized) {
				mod_timer(&wakeup_timer, jiffies + msecs_to_jiffies(PROFILING_DELAY));
				work_queue_initialized = true;
			}
			if (result < 0) {
				return result;
			}
			return len; 
			break;
		
		case UNREGISTER:
			unregister_process(pid);
			mutex_unlock(&pid_list_lock);
			return len; 
			break;
	}

	return len;
}

void clear_list(void) {
	struct mp3_task_struct *tmp, *data;

	list_for_each_entry_safe(data, tmp, &pid_linkedlist, list) {
		list_del(&data->list);
		kmem_cache_free(proc_node_allocator, data);
	}

	size_of_pid_linkedlist = 0;
}

static int device_mmap(struct file *file, struct vm_area_struct* vm) {
	unsigned long physical_page_number;
	int result, i;

	for (i = 0; i < (vm -> vm_end - vm -> vm_start) / PAGE_SIZE; i++) {
		physical_page_number = vmalloc_to_pfn((char *) virtual_buffer + i * PAGE_SIZE);
		result = remap_pfn_range(vm, vm -> vm_start + i * PAGE_SIZE, physical_page_number, PAGE_SIZE, vm -> vm_page_prot);
		if (result < 0) {
			printk(KERN_ALERT "Failed to remap memory\n");
			return result;
		} 
	}

	return 0;
}

// Returns pointer to a buffer containing line by line output in <pid>\n format 
// @length: variable to which the number of bytes returned to the buffer is written
static char* pid_list_to_char(int *length) {
		
	char *write_buffer = kmalloc(sizeof(char) * (size_of_pid_linkedlist) * LINE_LENGTH, GFP_KERNEL);
	int total_write_bytes = 0;
	struct mp3_task_struct *data;
	char *write_pointer;
	write_pointer = write_buffer;

	list_for_each_entry(data, &pid_linkedlist, list) {
		int temp_write_count = snprintf(write_pointer, LINE_LENGTH, "%d\n", data->pid);
		total_write_bytes += temp_write_count;
		write_pointer += temp_write_count;
	}

	*length = total_write_bytes;

	return write_buffer;
}

static ssize_t proc_read(struct file *file, char __user *buffer, size_t len, loff_t *offset) {
	
	int length; // represents number of bytes to return in this read call
	char *output; 
	
	mutex_lock(&pid_list_lock);

	// no data to print or output was already given out for current file descriptor
	if (size_of_pid_linkedlist == 0 || *offset > 0) { 
		mutex_unlock(&pid_list_lock);
		return 0;
	}
		
	output = pid_list_to_char(&length);
		
	if (copy_to_user(buffer, output, length)) {
		mutex_unlock(&pid_list_lock);
		return -EFAULT;
	}

	*offset = length;

	kfree(output); // clearing output buffer after copying

	mutex_unlock(&pid_list_lock);

	return length;
}

static int proc_show(struct seq_file *m, void *v) {
	return 0;
}

static int proc_open(struct inode *inode, struct file *file) {
	return single_open(file, proc_show, NULL);
}

static int proc_release(struct inode *inode, struct file *file) {
	return single_release(inode, file);
}

static int monitor_open(struct inode *inode, struct file *file) {
	return 0;
}

static int monitor_release(struct inode *inode, struct file *file) {
	return 0;
}

static const struct proc_ops proc_fops = {
	.proc_open = proc_open,
	.proc_read = proc_read,
	.proc_write = proc_write,
	.proc_release = proc_release
};

static const struct file_operations monitor_fops = {
	.owner = THIS_MODULE,
	.open = monitor_open,
	.release = monitor_release,
	.mmap = device_mmap
};

int reserve_pages(void) {
	struct page* page;
	int i;
	for (i = 0; i < PAGE_COUNT; i++) {
		page = vmalloc_to_page((char *)virtual_buffer + i * PAGE_SIZE);
		if (!page) {
			printk(KERN_ALERT "Failed to get page from virtual buffer after i = %d\n",i);
			return -EINVAL;
		}
		SetPageReserved(page);
	}
	return 0;
}

void clear_page_reservation(void) {
	struct page* page;
	int i;
	for (i = 0; i < PAGE_COUNT; i++) {
		page = vmalloc_to_page((char *)virtual_buffer + i * PAGE_SIZE);
		ClearPageReserved(page);
	}
}

void step_wise_clearance(int step) {

	if (step > 6) {
		clear_page_reservation();
		vfree(virtual_buffer);
	} 

	if (step > 5) {
		cdev_del(&monitor_device);
	}

	if (step > 4) {
		unregister_chrdev_region(MKDEV(MAJOR_NUMBER, 0), 1);
	}

	if (step > 3) {
		del_timer(&wakeup_timer);
		flush_workqueue(list_update_workqueue);
		destroy_workqueue(list_update_workqueue);
	}

	if (step > 2) {
		kmem_cache_destroy(proc_node_allocator);
	}

	if (step > 1) {
		remove_proc_entry(PROC_NAME, proc_dir);
	}

	if (step > 0) {
		remove_proc_entry(PROC_DIR, NULL);
	}
}

// mp3_init - Called when module is loaded
int __init mp3_init(void)
{
	#ifdef DEBUG
	printk(KERN_ALERT "MP3 MODULE LOADING\n");
	#endif
	// Insert your code here ...

	proc_dir = proc_mkdir(PROC_DIR, NULL);

	if (!proc_dir) {
		pr_warn(KERN_WARNING "Unable to create dir, may be out of memory\n");
		return -ENOMEM;
	}

	if (!proc_create(PROC_NAME, 0666, proc_dir, &proc_fops)) {
		pr_warn(KERN_WARNING "Unable to create file, may be out of memory\n");
		step_wise_clearance(1);
		return -ENOMEM;
	}

	proc_node_allocator = kmem_cache_create(KMEM_LABEL, sizeof(struct mp3_task_struct), 0, SLAB_HWCACHE_ALIGN, NULL);

	if (!proc_node_allocator) {
		printk(KERN_WARNING "Failed to create slab cache\n");
		step_wise_clearance(2);
		return -ENOMEM;
	}

	mutex_init(&pid_list_lock);

	INIT_LIST_HEAD(&pid_linkedlist);

	list_update_workqueue = create_singlethread_workqueue(KMEM_LABEL);
	INIT_WORK(&update_task, queue_work_function);

	timer_setup(&wakeup_timer, timer_callback, 0);

	if (register_chrdev_region(MKDEV(MAJOR_NUMBER, 0), 1, IDENTIFIER) < 0) {
		printk(KERN_WARNING "Failed to create character device\n");
		step_wise_clearance(4);
		return -1;
	}

	cdev_init(&monitor_device, &monitor_fops);

	if (cdev_add(&monitor_device, MKDEV(MAJOR_NUMBER, 0), 1) < 0) {
		printk(KERN_WARNING "Failed to register character device\n");
		step_wise_clearance(5);
		return -ENOMEM;
	}

	virtual_buffer = vmalloc(PAGE_COUNT * PAGE_SIZE);

	if (!virtual_buffer) {
		printk(KERN_WARNING "Failed to allocate contiguous virtual memory\n");
		step_wise_clearance(6);
		return -ENOMEM;
	}

	if (reserve_pages()) {
		step_wise_clearance(6);
		return -EINVAL;
	}

	printk(KERN_ALERT "MODULE LOADED\n");
	return 0;   
}


// - Called when module is unloaded
void __exit mp3_exit(void)
{
	#ifdef DEBUG
	printk(KERN_ALERT "MODULE UNLOADING\n");
	#endif
	// Insert your code here ...

	clear_list();

	step_wise_clearance(7);

	printk(KERN_ALERT "MODULE UNLOADED\n");
}

// Register init and exit funtions
module_init(mp3_init);
module_exit(mp3_exit);
