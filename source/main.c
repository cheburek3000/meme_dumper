// Required header
#include <ps5/payload_main.h>

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <ps5/libkernel.h>
#include <ps5/libc.h>
#include <ps5/kernel.h>

#define PC_IP "10.0.0.193"
#define PC_LOG_PORT 5655

#define DUMP_SERVER_PORT 9081
// #define LOG_PDE

enum Errors {
  ERR_LOG_SOCK = 1,
  ERR_LOG_CONNECT,
  ERR_PMAP_OFFSET_GUESS,
  ERR_DUMPER_BUF_MALLOC,
  ERR_DUMPER_SOCK,
  ERR_DUMPER_SETSOCKOPT,
  ERR_DUMPER_BIND,
  ERR_DUMPER_LISTEN,
  ERR_DUMPER_CMD_READ,
  ERR_DUMP_COPYOUT,
  ERR_DUMP_WRITE,
  ERR_PADDR_NEGATIVE,
  ERR_VADDR_NOT_PRESENT,
  ERR_VADDR_NO_LEAF,
};

int err_to_return(int value) { return (value << 16) + errno; }

const char CMD_DUMP_ABS[] = "dump_abs";
const char CMD_DUMP_BASE[] = "dump_base";
const char CMD_DUMP_VADDR[] = "dump_vaddr";
const char CMD_DUMP_PADDR[] = "dump_paddr";
const char CMD_DUMP_RANGES[] = "dump_ranges";
const char CMD_STOP[] = "stop";

#define CMD_IS(x) \
  (cmd_sz >= (sizeof(x) - 1) && memcmp((x), cmd_buf, (sizeof(x) - 1)) == 0)

const size_t CMD_BUF_SIZE = 0x100;
const size_t DUMP_BUF_SIZE = 0x100000;  // 1Mb
const size_t PMAP_LOOKUP_PREFIX =
    0x4000000;  // 64Mb, should be multiple of DUMP_BUF_SIZE

void sock_print(int sock, char *str) {
  size_t size;

  size = strlen(str);
  _write(sock, str, size);
}

int write_buf(int sock, char *buf, size_t size) {
  size_t written = 0;
  while (written < size) {
    ssize_t ret = _write(sock, buf + written, size - written);
    if (ret < 0) {
      return -1;
    }
    written += ret;
  }
  return 0;
}

struct flat_pmap {
  uint64_t mtx_name_ptr;
  uint64_t mtx_flags;
  uint64_t mtx_data;
  uint64_t mtx_lock;
  uint64_t pm_pml4;
  uint64_t pm_cr3;
};

ssize_t guess_kernel_pmap_store_offset(size_t kdata_base) {
  char *kdata;
  ssize_t result = -1;
  ssize_t offset;
  struct flat_pmap pmap;

  kdata = malloc(DUMP_BUF_SIZE);
  if (kdata == NULL) {
    result = -ERR_DUMPER_BUF_MALLOC;
    goto guess_offset_out;
  }
  for (offset = 0; offset + sizeof(struct flat_pmap) < 0x4000000; ++offset) {
    if ((offset % DUMP_BUF_SIZE) == 0) {
      // get next chunk of kdata
      kernel_copyout(kdata_base + offset, kdata, DUMP_BUF_SIZE);
    }
    memcpy(&pmap, kdata + (offset % DUMP_BUF_SIZE), sizeof(pmap));
    if (pmap.mtx_flags == 0x1430000 && pmap.mtx_data == 0x0 &&
        pmap.mtx_lock == 0x4 && pmap.pm_pml4 != 0 &&
        (pmap.pm_pml4 & 0xFFFFFFFFULL) == pmap.pm_cr3) {
      result = offset;
      // last one is the best, so continue the search
    }
  }
guess_offset_out:
  if (kdata != NULL) {
    free(kdata);
  }
  return result;
}

struct page_level {
  int from;
  int to;
  size_t size;
  int sign_ext;
  int leaf;
};

const struct page_level LEVELS[] = {
    {.from = 39, .to = 47, .size = 1ULL << 39, .sign_ext = 1, .leaf = 0},
    {.from = 30, .to = 38, .size = 1ULL << 30, .sign_ext = 0, .leaf = 0},
    {.from = 21, .to = 29, .size = 1ULL << 21, .sign_ext = 0, .leaf = 0},
    {.from = 12, .to = 20, .size = 1ULL << 12, .sign_ext = 0, .leaf = 1},
};

enum pde_shift {
  PDE_PRESENT = 0,
  PDE_RW,
  PDE_USER,
  PDE_WRITE_THROUGH,
  PDE_CACHE_DISABLE,
  PDE_ACCESSED,
  PDE_DIRTY,
  PDE_PS,
  PDE_GLOBAL,
  PDE_PROTECTION_KEY = 59,
  PDE_EXECUTE_DISABLE = 63
};

const size_t PDE_PRESENT_MASK = 1;
const size_t PDE_RW_MASK = 1;
const size_t PDE_USER_MASK = 1;
const size_t PDE_WRITE_THROUGH_MASK = 1;
const size_t PDE_CACHE_DISABLE_MASK = 1;
const size_t PDE_ACCESSED_MASK = 1;
const size_t PDE_DIRTY_MASK = 1;
const size_t PDE_PS_MASK = 1;
const size_t PDE_GLOBAL_MASK = 1;
const size_t PDE_PROTECTION_KEY_MASK = 0xF;
const size_t PDE_EXECUTE_DISABLE_MASK = 1;

#define PDE_FIELD(pde, name) (((pde) >> PDE_##name) & PDE_##name##_MASK)

const size_t PDE_ADDR_MASK = 0xffffffffff800ULL;  // bits [12, 51]

#define PADDR_TO_DMAP(paddr) ((paddr) + dmap_base)

ssize_t vaddr_to_paddr(size_t vaddr, size_t dmap_base, size_t cr3,
                       size_t *page_end, int log_sock) {
  ssize_t paddr = cr3;
  uint64_t pd[512];
  const struct page_level *level;
#ifdef LOG_PDE
  char printbuf[512];
#endif

  for (size_t level_idx = 0; level_idx < 4; ++level_idx) {
    level = LEVELS + level_idx;
    if (paddr < 0) {
      // something is wrong
      return -ERR_PADDR_NEGATIVE;
    }
    kernel_copyout(PADDR_TO_DMAP(paddr), &pd, sizeof(pd));
    int idx_bits = (level->to - level->from) + 1;
    size_t idx_mask = (1ULL << idx_bits) - 1ULL;
    size_t idx = (vaddr >> level->from) & idx_mask;

    uint64_t pde = pd[idx];
    paddr = pde & PDE_ADDR_MASK;
    size_t leaf = level->leaf || PDE_FIELD(pde, PS);
#ifdef LOG_PDE
    sprintf(
        printbuf,
        "[+] level %p, idx 0x%p, paddr 0x%p, leaf %p\n"
        "    present %p, rw %p, user %p, write_through %p, cache_disable %p,\n"
        "    accessed %p, dirty %p, ps %p, global %p, protection_key %p,\n"
        "    execute_disable %p\n",
        level_idx, idx, paddr, leaf, PDE_FIELD(pde, PRESENT),
        PDE_FIELD(pde, RW), PDE_FIELD(pde, USER), PDE_FIELD(pde, WRITE_THROUGH),
        PDE_FIELD(pde, CACHE_DISABLE), PDE_FIELD(pde, ACCESSED),
        PDE_FIELD(pde, DIRTY), PDE_FIELD(pde, PS), PDE_FIELD(pde, GLOBAL),
        PDE_FIELD(pde, PROTECTION_KEY), PDE_FIELD(pde, EXECUTE_DISABLE));
    sock_print(log_sock, printbuf);
#endif

    if (!PDE_FIELD(pde, PRESENT)) {
      // something is wrong
      return -ERR_VADDR_NOT_PRESENT;
    }

    if (leaf) {
      *page_end = paddr + level->size;
      return paddr | (vaddr & (level->size - 1));
    }
  }
  return -ERR_VADDR_NO_LEAF;
}

struct vaddr_paddr_range {
  size_t vaddr_begin, vaddr_end;
  size_t paddr_begin, paddr_end;
  size_t pte_flags;
};

struct vaddr_paddr_ranges {
  struct vaddr_paddr_range *ranges;
  size_t len;
  size_t cap;
};

const size_t PTE_FLAGS_MASK =
    (PDE_RW_MASK << PDE_RW) |
    (PDE_USER_MASK << PDE_USER) |
    (PDE_WRITE_THROUGH_MASK << PDE_WRITE_THROUGH) |
    (PDE_CACHE_DISABLE_MASK << PDE_CACHE_DISABLE) |
    (PDE_GLOBAL_MASK << PDE_GLOBAL) |
    (PDE_EXECUTE_DISABLE_MASK << PDE_EXECUTE_DISABLE) |
    (PDE_PROTECTION_KEY_MASK << PDE_PROTECTION_KEY);

ssize_t append_range(size_t vaddr, size_t paddr, size_t size, size_t pte,
                     struct vaddr_paddr_ranges *ranges) {
  if (ranges->len + 1 > ranges->cap) {
    struct vaddr_paddr_range *old_ranges = ranges->ranges;
    size_t old_cap = ranges->cap;
    ranges->cap = ranges->cap ? ranges->cap * 2 : 8096;
    ranges->ranges = malloc(ranges->cap * sizeof(struct vaddr_paddr_range));
    if (ranges->ranges == NULL) {
      if (old_ranges != NULL) {
        free(old_ranges);
      }
      return -ranges->cap;
    }
    if (old_ranges != NULL) {
      memcpy(ranges->ranges, old_ranges,
             old_cap * sizeof(struct vaddr_paddr_range));
      free(old_ranges);
    }
  }
  struct vaddr_paddr_range new_range = {.vaddr_begin = vaddr,
                                        .vaddr_end = vaddr + size,
                                        .paddr_begin = paddr,
                                        .paddr_end = paddr + size,
                                        .pte_flags = pte & PTE_FLAGS_MASK};
  struct vaddr_paddr_range *old_range =
      ranges->len > 0 ? &ranges->ranges[ranges->len - 1] : NULL;
  if (old_range && old_range->vaddr_end == new_range.vaddr_begin &&
      old_range->paddr_end == new_range.paddr_begin &&
      old_range->pte_flags == new_range.pte_flags) {
    old_range->vaddr_end = new_range.vaddr_end;
    old_range->paddr_end = new_range.paddr_end;
  } else {
    ranges->ranges[ranges->len++] = new_range;
  }
  return 0;
}

const size_t SIGN_EXT_MASK = 0xffff000000000000;

ssize_t collect_ranges(size_t dmap_base, size_t paddr, size_t vaddr,
                       size_t level_idx, struct vaddr_paddr_ranges *ranges) {
  ssize_t ret = 0;
  uint64_t pd[512];
  const struct page_level *level;

  level = LEVELS + level_idx;
  kernel_copyout(PADDR_TO_DMAP(paddr), &pd, sizeof(pd));
  for (size_t idx = 0; idx < 512; ++idx) {
    uint64_t pde = pd[idx];
    size_t next_paddr = pde & PDE_ADDR_MASK;
    size_t next_vaddr = vaddr | (idx << level->from);
    if (level->sign_ext && ((idx >> (level->to - level->from)) & 1)) {
      next_vaddr |= SIGN_EXT_MASK;
    }

    size_t leaf = level->leaf || PDE_FIELD(pde, PS);

    if (!PDE_FIELD(pde, PRESENT)) {
      continue;
    }

    if (leaf) {
      ret = append_range(next_vaddr, next_paddr, level->size, pde, ranges);
    } else {
      ret = collect_ranges(dmap_base, next_paddr, next_vaddr, level_idx + 1,
                           ranges);
    }
    if (ret < 0) {
      return ret;
    }
  }
  return ret;
}

void print_ranges(struct vaddr_paddr_ranges *ranges, int sock) {
  char printbuf[256];
  for (size_t i = 0; i < ranges->len; ++i) {
    struct vaddr_paddr_range *range = &ranges->ranges[i];
    size_t pde = range->pte_flags;
    sprintf(printbuf,
            "[%p, %p) -> [%p, %p), rw %p, x %p, user %p, glob %p, pk %p, wt %p, cd %p\n",
            range->vaddr_begin, range->vaddr_end, range->paddr_begin,
            range->paddr_end, PDE_FIELD(pde, RW),
            !PDE_FIELD(pde, EXECUTE_DISABLE), PDE_FIELD(pde, USER),
            PDE_FIELD(pde, GLOBAL), PDE_FIELD(pde, PROTECTION_KEY),
            PDE_FIELD(pde, WRITE_THROUGH), PDE_FIELD(pde, CACHE_DISABLE));
    sock_print(sock, printbuf);
  }
}

int payload_main(struct payload_args *args) {
  int exit_code = 0;
  int ret;
  int log_sock = -1, dumper_sock = -1;
  int running = 1;
  int client = 0;
  char cmd_buf[CMD_BUF_SIZE];
  char *dump_buf = NULL;
  ssize_t cmd_sz = 0;
  char printbuf[128];
  struct sockaddr_in log_addr, dumper_addr;
  uint64_t kdata_base;
  ssize_t pmap_offset = -1;
  struct flat_pmap kernel_pmap_store;
  size_t dmap_base = 0;
  struct vaddr_paddr_ranges mem_ranges = {.ranges = NULL, .cap = 0, .len = 0};

  kdata_base = args->kdata_base_addr;

  // Open a debug socket to log to PC
  log_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (log_sock < 0) {
    exit_code = err_to_return(ERR_LOG_SOCK);
    goto out;
  }

  inet_pton(AF_INET, PC_IP, &log_addr.sin_addr);
  log_addr.sin_family = AF_INET;
  log_addr.sin_len = sizeof(log_addr);
  log_addr.sin_port = htons(PC_LOG_PORT);

  ret = connect(log_sock, (const struct sockaddr *)&log_addr, sizeof(log_addr));
  if (ret < 0) {
    exit_code = err_to_return(ERR_LOG_CONNECT);
    goto out;
  }

  // Open socket to dump data to PC
  dumper_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (dumper_sock < 0) {
    exit_code = err_to_return(ERR_DUMPER_SOCK);
    goto out;
  }
  const int enable = 1;
  ret = setsockopt(dumper_sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
  if (ret < 0) {
    exit_code = err_to_return(ERR_DUMPER_SETSOCKOPT);
    goto out;
  }

  memset(&dumper_addr, 0, sizeof(dumper_addr));
  dumper_addr.sin_family = AF_INET;
  dumper_addr.sin_len = sizeof(dumper_addr);
  dumper_addr.sin_port = htons(DUMP_SERVER_PORT);
  dumper_addr.sin_addr.s_addr = INADDR_ANY;

  ret = bind(dumper_sock, (const struct sockaddr *)&dumper_addr,
             sizeof(dumper_addr));
  if (ret < 0) {
    exit_code = err_to_return(ERR_DUMPER_BIND);
    goto out;
  }
  ret = listen(dumper_sock, 5);
  if (ret < 0) {
    exit_code = err_to_return(ERR_DUMPER_LISTEN);
    goto out;
  }

  // Print basic info
  struct flat_pmap {
    uint64_t mtx_name_ptr;
    uint64_t mtx_flags;
    uint64_t mtx_data;
    uint64_t mtx_lock;
    uint64_t pm_pml4;
    uint64_t pm_cr3;
  };
  sprintf(printbuf,
          "[+] kernel .data base is %p, pipe %d->%d, rw pair %d->%d, pipe addr "
          "is %p\n",
          args->kdata_base_addr, args->rwpipe[0], args->rwpipe[1],
          args->rwpair[0], args->rwpair[1], args->kpipe_addr);
  sock_print(log_sock, printbuf);

  // Initialize kernel read/write helpers
  kernel_init_rw(args->rwpair[0], args->rwpair[1], args->rwpipe,
                 args->kpipe_addr);

  pmap_offset = guess_kernel_pmap_store_offset(kdata_base);
  if (pmap_offset < 0) {
    sprintf(printbuf,
            "[+] failed to guess kernel_pmap_store offset, code = %zu\n",
            -pmap_offset);
    sock_print(log_sock, printbuf);
    exit_code = ERR_PMAP_OFFSET_GUESS;
    goto out;
  } else {
    kernel_copyout(kdata_base + pmap_offset, &kernel_pmap_store,
                   sizeof(kernel_pmap_store));
    dmap_base = kernel_pmap_store.pm_pml4 - kernel_pmap_store.pm_cr3;

    // Print pmap info
    sprintf(printbuf,
            "[+] kernel_pmap_store offset 0x%p, pm_pml4 0x%p, pm_cr3 0x%p, "
            "dmap_base 0x%p\n",
            pmap_offset, kernel_pmap_store.pm_pml4, kernel_pmap_store.pm_cr3,
            dmap_base);
    sock_print(log_sock, printbuf);
  }

  dump_buf = malloc(DUMP_BUF_SIZE);
  if (dump_buf == NULL) {
    exit_code = ERR_DUMPER_BUF_MALLOC;
    goto out;
  }

  // Accept clients
  while (running > 0) {
    client = _accept(dumper_sock, 0, 0);

    if (client > 0) {
      cmd_sz = _read(client, cmd_buf, CMD_BUF_SIZE - 1);
      if (cmd_sz < 0) {
        return err_to_return(ERR_DUMPER_CMD_READ);
      }
      cmd_buf[cmd_sz] = '\0';  // just in case
      sprintf(printbuf, "[+] got command = %s\n", cmd_buf);
      sock_print(log_sock, printbuf);

      size_t dump_address = 0;
      size_t dump_size = 0;
      size_t vaddr_to_paddr_mode = 0;
      if (CMD_IS(CMD_STOP)) {
        running = 0;
        sprintf(printbuf, "[+] stopping\n");
        sock_print(log_sock, printbuf);
        goto client_close;
      } else if (CMD_IS(CMD_DUMP_ABS)) {
        ret = sscanf(cmd_buf + sizeof(CMD_DUMP_ABS), "0x%zx 0x%zx",
                     &dump_address, &dump_size);
      } else if (CMD_IS(CMD_DUMP_BASE)) {
        ret = sscanf(cmd_buf + sizeof(CMD_DUMP_BASE), "0x%zx 0x%zx",
                     &dump_address, &dump_size);
        dump_address += kdata_base;
      } else if (CMD_IS(CMD_DUMP_PADDR)) {
        ret = sscanf(cmd_buf + sizeof(CMD_DUMP_PADDR), "0x%zx 0x%zx",
                     &dump_address, &dump_size);
        dump_address += dmap_base;
      } else if (CMD_IS(CMD_DUMP_VADDR)) {
        ret = sscanf(cmd_buf + sizeof(CMD_DUMP_VADDR), "0x%zx 0x%zx",
                     &dump_address, &dump_size);
        vaddr_to_paddr_mode = 1;
      } else if (CMD_IS(CMD_DUMP_RANGES)) {
        mem_ranges.len = 0;
        ret = collect_ranges(dmap_base, kernel_pmap_store.pm_cr3, 0, 0,
                             &mem_ranges);
        sprintf(printbuf, "%d\n", ret < 0 ? ret : mem_ranges.len);
        sock_print(client, printbuf);
        if (ret == 0) {
          print_ranges(&mem_ranges, client);
        }
        goto client_close;
      } else {
        goto client_close;
      }
      if (ret < 2) {
        goto client_close;
      }
      sprintf(printbuf, "[+] dumping 0x%zx bytes from 0x%zx\n", dump_size,
              dump_address);
      sock_print(log_sock, printbuf);

      size_t kpos = vaddr_to_paddr_mode ? 0 : dump_address;
      size_t page_end = 0;
      size_t dumped = 0;
      while (dumped < dump_size) {
        if (vaddr_to_paddr_mode && kpos == page_end) {
          // load new page
          size_t vaddr = dump_address + dumped;
          ssize_t paddr = vaddr_to_paddr(
              vaddr, dmap_base, kernel_pmap_store.pm_cr3, &page_end, log_sock);
          if (paddr < 0) {
            sprintf(printbuf,
                    "[+] failed to convert vaddr to paddr, code = %zu\n",
                    -paddr);
            sock_print(log_sock, printbuf);
            goto client_close;
          }
          sprintf(printbuf,
                  "[+] vaddr %p converted to paddr %p (next page on %p)\n",
                  vaddr, paddr, page_end);
          sock_print(log_sock, printbuf);
          kpos = PADDR_TO_DMAP(paddr);
          page_end = PADDR_TO_DMAP(page_end);
        }

        size_t left = dump_size - dumped;
        if (vaddr_to_paddr_mode && ((page_end - kpos) < left)) {
          left = page_end - kpos;
        }
        size_t block_size = DUMP_BUF_SIZE;
        if (block_size > left) {
          block_size = left;
        }
        kernel_copyout(kpos, dump_buf, block_size);
        ret = write_buf(client, dump_buf, block_size);
        if (ret < 0) {
          sprintf(printbuf, "[+] error while writing to client\n");
          sock_print(log_sock, printbuf);
          exit_code = err_to_return(ERR_DUMP_WRITE);
          running = 0;
          goto out;
        }
        kpos += block_size;
        dumped += block_size;
      }
    client_close:
      _close(client);
    }
  }

out:
  if (dump_buf != NULL) {
    free(dump_buf);
    dump_buf = NULL;
  }
  if (dumper_sock >= 0) {
    shutdown(dumper_sock, SHUT_RDWR);
    _close(dumper_sock);
    dumper_sock = -1;
  }
  if (log_sock >= 0) {
    sprintf(printbuf, "stopped\n", cmd_buf);
    sock_print(log_sock, printbuf);
    shutdown(log_sock, SHUT_RDWR);
    _close(log_sock);
    log_sock = -1;
  }
  return exit_code;
}
