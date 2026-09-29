#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/version.h>

#include "infra/symbol_resolver.h"

// https://github.com/torvalds/linux/commit/89245600941e4e0f87d77f60ee269b5e61ef4e49
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define USE_KCFI 1
#else
#define USE_KCFI 0
#endif

// It's not guaranteed to have this symbol exist in 5.x kernel
// https://github.com/torvalds/linux/commit/d721def7392a7348ffb9f3583b264239cbd3702c
// https://github.com/gregkh/linux/commit/2aa861ec72908b4bdc20d74725dc1c8c71a8d214
// https://github.com/gregkh/linux/commit/318a206633c248d876ea72f7133d2a2e50ad7e35
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
#define ALWAYS_HAVE_ON_EACH_SYMBOL 1
#else
#define ALWAYS_HAVE_ON_EACH_SYMBOL 0
#endif

#if !ALWAYS_HAVE_ON_EACH_SYMBOL
static int (*kallsyms_on_each_symbol_fn)(int (*fn)(void *, const char *, struct module *, unsigned long),
                                         void *data) = NULL;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define HAVE_ON_EACH_MATCH_SYMBOL 1
#else
#define HAVE_ON_EACH_MATCH_SYMBOL 0
#endif

// https://github.com/torvalds/linux/commit/4dc533e0f2c04174e1ae4aa98e7cffc1c04b9998
#if HAVE_ON_EACH_MATCH_SYMBOL
static int (*kallsyms_on_each_match_symbol_fn)(int (*fn)(void *, unsigned long), const char *name, void *data) = NULL;
static int find_kernel_symbol_exact_cb(void *data, unsigned long addr)
{
    *(unsigned long *)data = addr;
    return 0;
}
#endif

struct ksu_lookup_symbol_ctx {
    const char *symbol_name;
    size_t symbol_len;
    int match_count;
    void *match;
};

unsigned long __nocfi find_kernel_symbol_exact(const char *symbol_name)
{
    unsigned long addr = 0;
#if HAVE_ON_EACH_MATCH_SYMBOL
    if (likely(kallsyms_on_each_match_symbol_fn)) {
        kallsyms_on_each_match_symbol_fn(find_kernel_symbol_exact_cb, symbol_name, &addr);
        return addr;
    }
#endif
    char *module_name = NULL;
    char buf[KSYM_SYMBOL_LEN];

    addr = kallsyms_lookup_name(symbol_name);
    // check if it is kernel symbol
    kallsyms_lookup(addr, NULL, NULL, &module_name, buf);
    if (unlikely(module_name)) {
        pr_warn("ignore symbol %s of module %s\n", symbol_name, module_name);
        return 0;
    }
    return addr;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static int count_lto_clones_cb(void *data, const char *name, unsigned long addr)
#else
static int count_lto_clones_cb(void *data, const char *name, struct module *mod, unsigned long addr)
#endif
{
    struct ksu_lookup_symbol_ctx *ctx = data;

    if (!name || !addr)
        return 0;

    if (strncmp(name, ctx->symbol_name, ctx->symbol_len) != 0)
        return 0;

    if (strncmp(name + ctx->symbol_len, ".lto_priv.", 10) != 0)
        return 0;

    ctx->match_count++;
    return 0;
}

static __nocfi void *resolve_lto_symbol(const char *symbol_name, size_t symbol_len)
{
    char lto_name[KSYM_NAME_LEN];
    void *addr;
    struct ksu_lookup_symbol_ctx ctx = {
        .symbol_name = symbol_name,
        .symbol_len = symbol_len,
        .match_count = 0,
    };

    snprintf(lto_name, sizeof(lto_name), "%s.lto_priv.0", symbol_name);
    addr = (void *)find_kernel_symbol_exact(lto_name);
    if (!addr)
        return NULL;

#if !ALWAYS_HAVE_ON_EACH_SYMBOL
    if (kallsyms_on_each_symbol_fn)
        kallsyms_on_each_symbol_fn(count_lto_clones_cb, &ctx);
#else
    kallsyms_on_each_symbol(count_lto_clones_cb, &ctx);
#endif

    if (ctx.match_count > 1) {
        pr_warn("symbol %s has %d LTO clones, refusing to resolve\n",
                symbol_name, ctx.match_count);
        return NULL;
    }

    pr_info("resolved LTO symbol: %s\n", lto_name);
    return addr;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static int find_llvm_symbol_cb(void *data, const char *name, unsigned long addr)
#else
static int find_llvm_symbol_cb(void *data, const char *name, struct module *mod, unsigned long addr)
#endif
{
    struct ksu_lookup_symbol_ctx *ctx = data;

    if (!name || !addr)
        return 0;

    if (strncmp(name, ctx->symbol_name, ctx->symbol_len) != 0)
        return 0;

    if (strncmp(name + ctx->symbol_len, ".llvm.", 6) != 0)
        return 0;

    ctx->match = (void *)addr;
    ctx->match_count++;
    return 0;
}

static __nocfi void *resolve_llvm_symbol(const char *symbol_name, size_t symbol_len)
{
    struct ksu_lookup_symbol_ctx ctx = {
        .symbol_name = symbol_name,
        .symbol_len = symbol_len,
        .match_count = 0,
        .match = NULL,
    };

#if !ALWAYS_HAVE_ON_EACH_SYMBOL
    if (kallsyms_on_each_symbol_fn)
        kallsyms_on_each_symbol_fn(find_llvm_symbol_cb, &ctx);
#else
    kallsyms_on_each_symbol(find_llvm_symbol_cb, &ctx);
#endif

    if (!ctx.match)
        return NULL;

    if (ctx.match_count > 1) {
        pr_warn("symbol %s has %d LLVM LTO variants, refusing to resolve\n",
                symbol_name, ctx.match_count);
        return NULL;
    }

    pr_info("resolved LLVM LTO symbol: %s.llvm.*\n", symbol_name);
    return ctx.match;
}

void *ksu_resolve_symbol_for_functable_hook(const char *symbol_name)
{
    void *addr;
    size_t symbol_len;

    if (!symbol_name || !symbol_name[0])
        return NULL;

    symbol_len = strlen(symbol_name);

#if !USE_KCFI
    // Try .cfi_jt suffix first (pre-6.1 kCFI)
    char cfi_name[KSYM_NAME_LEN];
    snprintf(cfi_name, sizeof(cfi_name), "%s.cfi_jt", symbol_name);
    addr = (void *)find_kernel_symbol_exact(cfi_name);
    if (addr)
        return addr;
#endif

    addr = (void *)find_kernel_symbol_exact(symbol_name);
    if (addr)
        return addr;

    addr = resolve_lto_symbol(symbol_name, symbol_len);
    if (addr)
        return addr;

    return resolve_llvm_symbol(symbol_name, symbol_len);
}

void __init ksu_init_symbol_resolver()
{
#if !ALWAYS_HAVE_ON_EACH_SYMBOL
    kallsyms_on_each_symbol_fn = find_kernel_symbol_exact("kallsyms_on_each_symbol");
    if (!kallsyms_on_each_symbol_fn) {
        pr_warn("kallsyms_on_each_symbol not found!\n");
    }
#endif
#if HAVE_ON_EACH_MATCH_SYMBOL
    kallsyms_on_each_match_symbol_fn = find_kernel_symbol_exact("kallsyms_on_each_match_symbol");
    if (!kallsyms_on_each_match_symbol_fn) {
        pr_warn("kallsyms_on_each_match_symbol not found!\n");
    }
#endif
}
