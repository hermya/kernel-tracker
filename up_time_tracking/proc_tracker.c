// 39 = 16 (char size of pid) + 2 (size of ": ") + 20 (char size to represent long long) + 1 (\n)
#define LINE_LENGTH 39 
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#define PROC_NAME "status"
#define PROC_DIR "uptime"
#define KMEM_LABEL "uptime/status"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include "util.h"
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>

MODULE_AUTHOR("Heramb Joshi herambku@gmail.com");
MODULE_LICENSE("GPL");

static struct timer_list pid_update_timer;
static struct workqueue_struct *list_update_workqueue;
static struct work_struct update_task;
static struct mutex pid_list_lock;
struct proc_dir_entry *proc_dir;
struct kmem_cache *proc_node_allocator = NULL;

struct process_data {
	int pid;
	long cpu_time;
	struct list_head list;
};
struct list_head pid_linkedlist;
static long size_of_pid_linkedlist = 0;

// This function either removes a list node whose pid is inactive or updates its latest cpu time
static void queue_work_function(struct work_struct *work) {
	struct process_data *tmp, *data;
	long temp_cpu_time;

	mutex_lock(&pid_list_lock);

	list_for_each_entry_safe(data, tmp, &pid_linkedlist, list) {
		if (get_cpu_use(data->pid, &temp_cpu_time)) {
			list_del(&data->list);
			kmem_cache_free(proc_node_allocator, data);
			size_of_pid_linkedlist--;
		} else {
			data->cpu_time = temp_cpu_time;
		}
	}

	mutex_unlock(&pid_list_lock);
}

void clear_list(void) {
	struct process_data *tmp, *data;

	list_for_each_entry_safe(data, tmp, &pid_linkedlist, list) {
		list_del(&data->list);
		kmem_cache_free(proc_node_allocator, data);
	}

	size_of_pid_linkedlist = 0;
}

// Pushes the queue_work_function on work queue every 5 seconds
void timer_callback(struct timer_list *timer) {

	queue_work(list_update_workqueue, &update_task);

	mod_timer(&pid_update_timer, jiffies + 5 * HZ);

}

static ssize_t proc_write(struct file* file, const char __user *buffer, size_t len, loff_t *offset) {
	char char_rep_of_pid[16];
	int new_pid;
	int str_to_int_result_check;
	struct process_data *new_proc_data = kmem_cache_alloc(proc_node_allocator, GFP_KERNEL);

	mutex_lock(&pid_list_lock);

	if (copy_from_user(char_rep_of_pid, buffer, len)) {
		// trying to access bad address
		mutex_unlock(&pid_list_lock);
		return -EFAULT;
	}

	char_rep_of_pid[len] = '\0';
	str_to_int_result_check = kstrtoint(char_rep_of_pid, 10, &new_pid);
	
	if (str_to_int_result_check < 0) {
		printk(KERN_WARNING "Invalid format of pid entered");
		mutex_unlock(&pid_list_lock);
		return str_to_int_result_check;
	}


	if (!new_proc_data) {
		printk(KERN_WARNING "Failed to allocate memory for new node to process list");
		mutex_unlock(&pid_list_lock);
		return -ENOMEM;
	}

	new_proc_data->pid = new_pid;

	list_add_tail(&new_proc_data->list, &pid_linkedlist);
	size_of_pid_linkedlist++;
	
	mutex_unlock(&pid_list_lock);

	return len;
}

// Returns pointer to a buffer containing line by line output in <pid>: <cpu-time>\n format 
// @length: variable to which the number of bytes returned to the buffer is written
static char* pid_list_to_char(int *length) {
		
	char *write_buffer = kmalloc(sizeof(char) * (size_of_pid_linkedlist) * LINE_LENGTH, GFP_KERNEL);
	int total_write_bytes = 0;
	struct process_data *data;
	char *write_pointer;
	write_pointer = write_buffer;

	list_for_each_entry(data, &pid_linkedlist, list) {
		int temp_write_count = snprintf(write_pointer, LINE_LENGTH, "%d: %ld\n", data->pid, data->cpu_time);
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

static const struct proc_ops proc_fops = {
	.proc_open = proc_open,
	.proc_read = proc_read,
	.proc_write = proc_write,
	.proc_release = proc_release
};

static int __init test_module_init(void)
{
	INIT_LIST_HEAD(&pid_linkedlist);
	
	proc_node_allocator = kmem_cache_create(KMEM_LABEL, sizeof(struct process_data), 0, SLAB_HWCACHE_ALIGN, NULL);

	timer_setup(&pid_update_timer, timer_callback, 0);

	list_update_workqueue = create_singlethread_workqueue(KMEM_LABEL);
	INIT_WORK(&update_task, queue_work_function);

	mutex_init(&pid_list_lock);

	if (!proc_node_allocator) {
		printk(KERN_WARNING "Failed to create slab cache\n");
		return -ENOMEM;
	}

	proc_dir = proc_mkdir(PROC_DIR, NULL);

	if (!proc_dir) {
		printk(KERN_WARNING "Unable to create dir, may be out of memory\n");
		return -ENOMEM;
	}

	if (!proc_create(PROC_NAME, 0666, proc_dir, &proc_fops)) {
		printk(KERN_WARNING "Unable to create file, may be out of memory\n");
		remove_proc_entry(PROC_DIR, NULL);
		return -ENOMEM;
	}

	printk(KERN_WARNING "Proc file entry : /proc/%s/%s created\n", PROC_DIR, PROC_NAME);

	mod_timer(&pid_update_timer, jiffies + 5 * HZ);

	return 0;
}

module_init(test_module_init);

static void __exit test_module_exit(void)
{
	remove_proc_entry(PROC_NAME, proc_dir);
	remove_proc_entry(PROC_DIR, NULL);

	del_timer(&pid_update_timer);

	flush_workqueue(list_update_workqueue);
	destroy_workqueue(list_update_workqueue);

	clear_list();

	kmem_cache_destroy(proc_node_allocator);

	printk(KERN_WARNING "Proc file entry : /proc/%s/%s removed\n", PROC_DIR, PROC_NAME);
}

module_exit(test_module_exit);
