// Cyanide 1.17.0 — runtime Chinese localisation shim (arm64e dylib).
//
// Mechanism (verified offline against the shipped binary):
//   * All UI text is a plain C string in __cstring, referenced ONLY through a
//     CFString record in __cfstring (isa/info/data/length, stride 32).
//   * `data` holds a sign-extended 40-bit offset from the mach_header; the
//     records are NOT reached by direct ADRP from code, so repointing data +
//     length is enough to change what every caller sees.
//   * Each English string maps to exactly ONE record (no aliasing), so no
//     neighbouring entry can be corrupted.
//   * The app binary's bytes are never modified: chained fixups, PAC and the
//     code signature all stay intact.
//
// Build: see Makefile. Inject as a normal dylib into Cyanide.app/Cyanide.


#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// cz_table is exported by table.c

typedef struct { const char *en; const char *zh; } CZEntry;
extern const CZEntry cz_table[];
extern const unsigned long cz_table_count;

#define LOG(fmt, ...) fprintf(stderr, "[CyanideZH] " fmt "\n", ##__VA_ARGS__)

typedef struct {
    void     *isa;
    uintptr_t info;
    uintptr_t data;      // sign-extended 40-bit offset from mach_header
    uint64_t  length;    // UTF-8 byte count for these ASCII strings
} CZRec;

static inline int64_t sext40(uintptr_t w) {
    w &= 0xFFFFFFFFFFULL;
    if (w & (1ULL << 39)) w -= (1ULL << 40);
    return (int64_t)w;
}

// ---- lookup table index ----------------------------------------------------
// cz_table[] is ~1259 entries; a linear scan per CFString record would be
// 4284*1259 strcmp. Build a small open-addressing hash once instead.

#define CZ_HASH_SIZE 4096   // power of two > 2*CZ_TABLE_COUNT

typedef struct { const char *en; const char *zh; size_t zlen; } CZSlot;
static CZSlot cz_hash[CZ_HASH_SIZE];

static inline uint64_t fnv1a(const char *s, size_t n) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
    return h;
}

static void cz_hash_build(void) {
    for (size_t i = 0; i < cz_table_count; i++) {
        size_t el = strlen(cz_table[i].en);
        uint64_t h = fnv1a(cz_table[i].en, el);
        size_t p = (size_t)(h & (CZ_HASH_SIZE - 1));
        while (cz_hash[p].en) p = (p + 1) & (CZ_HASH_SIZE - 1);
        cz_hash[p].en   = cz_table[i].en;
        cz_hash[p].zh   = cz_table[i].zh;
        cz_hash[p].zlen = strlen(cz_table[i].zh);
    }
}

static inline const char *cz_lookup(const char *s, size_t len, size_t *zlen) {
    uint64_t h = fnv1a(s, len);
    size_t p = (size_t)(h & (CZ_HASH_SIZE - 1));
    for (size_t probe = 0; probe < CZ_HASH_SIZE; probe++, p = (p + 1) & (CZ_HASH_SIZE - 1)) {
        const char *en = cz_hash[p].en;
        if (!en) return NULL;
        if (strlen(en) == len && memcmp(en, s, len) == 0) {
            *zlen = cz_hash[p].zlen;
            return cz_hash[p].zh;
        }
    }
    return NULL;
}

// ---- page protection -------------------------------------------------------
// __cfstring lives in __DATA_CONST, which dyld may map read-only. Try to add
// write permission without ever lowering max_prot; bail out per-page on failure
// instead of crashing.

#ifndef trunc_page
#define trunc_page(x)  ((x) & ~(uintptr_t)(vm_page_size - 1))
#endif
#ifndef round_page
#define round_page(x)  (((x) + (vm_page_size - 1)) & ~(uintptr_t)(vm_page_size - 1))
#endif

static int make_writable(uintptr_t addr, size_t len) {
    task_port_t self = mach_task_self();
    vm_address_t start = trunc_page(addr);
    vm_address_t end   = round_page(addr + len);
    vm_address_t cur   = start;
    while (cur < end) {
        vm_size_t sz = 0;
        vm_region_basic_info_data_64_t info;
                mach_msg_type_number_t icnt = VM_REGION_BASIC_INFO_COUNT_64;
        vm_region_flavor_t flav = VM_REGION_BASIC_INFO_64;
        kern_return_t kr = vm_region_recurse_64(self, &flav, &cur, &sz,
                                                (vm_region_recurse_info_t)&info, &icnt);
        if (kr != KERN_SUCCESS) return 0;
        if (sz == 0) return 0;
        if (!(info.protection & VM_PROT_WRITE)) {
            vm_prot_t want = info.protection | VM_PROT_WRITE;
            if ((want & info.maxprot) != want) return 0;
            kr = vm_protect(self, cur, sz, FALSE, want);
            if (kr != KERN_SUCCESS) return 0;
        }
        cur += sz;
    }
    return 1;
}

// ---- main scan -------------------------------------------------------------
static void patch_image(const struct mach_header_64 *mh) {
    const uint8_t *base = (const uint8_t *)mh;
    uint32_t off = sizeof(struct mach_header_64);
    const struct section_64 *cfsec = NULL;
    const struct segment_command_64 *cfseg = NULL;

    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)(base + off);
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            uint32_t so = off + sizeof(struct segment_command_64);
            for (uint32_t j = 0; j < sg->nsects; j++) {
                const struct section_64 *sec = (const struct section_64 *)(base + so);
                so += sizeof(struct section_64);
                if (strcmp(sec->sectname, "__cfstring") == 0 && !cfsec) {
                    cfsec = sec;
                    cfseg = sg;
                }
            }
        }
        off += lc->cmdsize;
    }
    if (!cfsec) { LOG("no __cfstring section found"); return; }

    // Convert section VM address -> in-memory pointer using its own segment slide.
    intptr_t seg_slide = 0;
    {
        // For a PIE arm64e binary the whole image shares one slide; derive it by
        // comparing the first __TEXT segment's vmaddr with the header address.
        const struct segment_command_64 *t = NULL;
        uint32_t o2 = sizeof(struct mach_header_64);
        for (uint32_t i = 0; i < mh->ncmds; i++) {
            const struct load_command *lc = (const struct load_command *)(base + o2);
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
                if (strcmp(sg->segname, "__PAGEZERO") != 0 && !t) t = sg;
            }
            o2 += lc->cmdsize;
        }
        if (t) seg_slide = (intptr_t)mh - (intptr_t)t->vmaddr;
    }

    uintptr_t rec_vm  = cfsec->addr;
    size_t    rec_n   = cfsec->size / sizeof(CZRec);
    CZRec    *recs    = (CZRec *)(rec_vm + seg_slide);

    LOG("__cfstring @%p (%zu records)", (void*)recs, rec_n);

    if (!make_writable((uintptr_t)recs, cfsec->size)) {
        LOG("WARNING: could not make __cfstring writable; "
            "will attempt per-record and count failures");
    }

    size_t hit = 0, prot_fail = 0;
    for (size_t k = 0; k < rec_n; k++) {
        CZRec *r = &recs[k];
        if (r->data == 0 || r->length == 0 || r->length > 8192) continue;
        int64_t rel = sext40(r->data);
        if (rel <= 0) continue;
        const char *s = (const char *)mh + rel;
        if ((uintptr_t)s < (uintptr_t)mh) continue;

        size_t zl = 0;
        const char *zh = cz_lookup(s, (size_t)r->length, &zl);
        if (!zh) continue;

        if (!make_writable((uintptr_t)r, sizeof(*r))) { prot_fail++; continue; }
        r->data   = (uintptr_t)zh;
        r->length = (uint64_t)zl;
        hit++;
    }
    LOG("done: patched=%zu prot_blocked=%zu", hit, prot_fail);
}

__attribute__((constructor))
static void cyanide_zh_init(void) {
    cz_hash_build();
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const struct mach_header *mh = _dyld_get_image_header(i);
        if (!mh) continue;
        if (((const struct mach_header_64 *)mh)->filetype != MH_EXECUTE) continue;
        patch_image((const struct mach_header_64 *)mh);
        break;   // main executable only
    }
}
