// husk — read-only ELF / permissions / capability inspector
//
// Parses an ELF binary straight from its bytes (no libelf, no libcap) and
// reports its security posture without ever executing it: exploit mitigations
// (PIE, NX, RELRO, stack canary, FORTIFY, RPATH/RUNPATH), loadable segments
// and their R/W/X bits, dynamic dependencies, risky libc imports, on-disk
// permission bits (setuid/setgid/sticky/world-writable) and POSIX file
// capabilities decoded from the security.capability extended attribute.
//
// The target file is only ever opened O_RDONLY and read into memory. husk
// performs no writes and never maps the file executable.
//
// Build:  make           (or: g++ -std=c++17 -O2 -Wall -Wextra husk.cpp -o husk)
// Usage:  husk [options] <file> [file...]

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <set>
#include <unordered_set>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/xattr.h>

// ---- ELF constants (kept local so we don't depend on <elf.h>) --------------
namespace elf {
constexpr unsigned char MAG[4] = {0x7f, 'E', 'L', 'F'};
enum { CLASS32 = 1, CLASS64 = 2 };
enum { DATA_LSB = 1, DATA_MSB = 2 };

// e_type
enum { ET_NONE = 0, ET_REL = 1, ET_EXEC = 2, ET_DYN = 3, ET_CORE = 4 };

// p_type
enum {
  PT_NULL = 0, PT_LOAD = 1, PT_DYNAMIC = 2, PT_INTERP = 3, PT_NOTE = 4,
  PT_PHDR = 6, PT_TLS = 7,
  PT_GNU_EH_FRAME = 0x6474e550, PT_GNU_STACK = 0x6474e551,
  PT_GNU_RELRO = 0x6474e552, PT_GNU_PROPERTY = 0x6474e553
};
// p_flags
enum { PF_X = 1, PF_W = 2, PF_R = 4 };

// sh_type
enum { SHT_SYMTAB = 2, SHT_STRTAB = 3, SHT_DYNSYM = 11 };
// sh_flags
enum { SHF_WRITE = 0x1, SHF_ALLOC = 0x2, SHF_EXECINSTR = 0x4 };

// d_tag
enum {
  DT_NULL = 0, DT_NEEDED = 1, DT_STRTAB = 5, DT_SONAME = 14, DT_RPATH = 15,
  DT_BIND_NOW = 24, DT_RUNPATH = 29, DT_FLAGS = 30, DT_TEXTREL = 22,
  DT_FLAGS_1 = 0x6ffffffb
};
enum { DF_BIND_NOW = 0x8, DF_TEXTREL = 0x4 };
enum { DF_1_NOW = 0x1, DF_1_PIE = 0x08000000 };
}  // namespace elf

// ---- ANSI colour -----------------------------------------------------------
static bool g_color = true;
static std::string col(const char* code, const std::string& s) {
  if (!g_color) return s;
  return std::string("\033[") + code + "m" + s + "\033[0m";
}
static std::string B(const std::string& s)   { return col("1", s); }
static std::string DIMc(const std::string& s) { return col("2", s); }
static std::string RED(const std::string& s)  { return col("1;31", s); }
static std::string GRN(const std::string& s)  { return col("32", s); }
static std::string YEL(const std::string& s)  { return col("33", s); }
static std::string CYN(const std::string& s)  { return col("36", s); }

// ---- endian-aware bounded reader ------------------------------------------
struct Reader {
  const uint8_t* p = nullptr;
  size_t n = 0;
  bool lsb = true;

  // Read an n-byte little/big-endian integer at off. Out-of-range -> ok=false.
  uint64_t u(size_t off, int sz, bool& ok) const {
    if (off + sz > n) { ok = false; return 0; }
    uint64_t v = 0;
    for (int i = 0; i < sz; i++) {
      uint64_t b = p[off + (lsb ? i : sz - 1 - i)];
      v |= b << (8 * i);
    }
    return v;
  }
  // Read a NUL-terminated string starting at off (bounded).
  std::string str(size_t off) const {
    if (off >= n) return std::string();
    std::string s;
    for (size_t i = off; i < n && p[i]; i++) s += static_cast<char>(p[i]);
    return s;
  }
};

// ---- lookup tables ---------------------------------------------------------
static const char* machine_name(uint64_t m) {
  switch (m) {
    case 3:   return "Intel 80386";
    case 62:  return "AMD x86-64";
    case 40:  return "ARM";
    case 183: return "AArch64";
    case 243: return "RISC-V";
    case 8:   return "MIPS";
    case 20:  return "PowerPC";
    case 21:  return "PowerPC64";
    case 22:  return "IBM S/390";
    default:  return nullptr;
  }
}
static const char* osabi_name(uint64_t a) {
  switch (a) {
    case 0:  return "UNIX - System V";
    case 3:  return "Linux";
    case 6:  return "Solaris";
    case 9:  return "FreeBSD";
    default: return nullptr;
  }
}
static std::string ptype_name(uint64_t t) {
  switch (t) {
    case elf::PT_NULL:         return "NULL";
    case elf::PT_LOAD:         return "LOAD";
    case elf::PT_DYNAMIC:      return "DYNAMIC";
    case elf::PT_INTERP:       return "INTERP";
    case elf::PT_NOTE:         return "NOTE";
    case elf::PT_PHDR:         return "PHDR";
    case elf::PT_TLS:          return "TLS";
    case elf::PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
    case elf::PT_GNU_STACK:    return "GNU_STACK";
    case elf::PT_GNU_RELRO:    return "GNU_RELRO";
    case elf::PT_GNU_PROPERTY: return "GNU_PROPERTY";
    default: { char b[24]; snprintf(b, sizeof b, "0x%llx",
                                    (unsigned long long)t); return b; }
  }
}

// Linux capability bit -> name (0..40).
static const char* CAP_NAMES[] = {
  "cap_chown","cap_dac_override","cap_dac_read_search","cap_fowner",
  "cap_fsetid","cap_kill","cap_setgid","cap_setuid","cap_setpcap",
  "cap_linux_immutable","cap_net_bind_service","cap_net_broadcast",
  "cap_net_admin","cap_net_raw","cap_ipc_lock","cap_ipc_owner",
  "cap_sys_module","cap_sys_rawio","cap_sys_chroot","cap_sys_ptrace",
  "cap_sys_pacct","cap_sys_admin","cap_sys_boot","cap_sys_nice",
  "cap_sys_resource","cap_sys_time","cap_sys_tty_config","cap_mknod",
  "cap_lease","cap_audit_write","cap_audit_control","cap_setfcap",
  "cap_mac_override","cap_mac_admin","cap_syslog","cap_wake_alarm",
  "cap_block_suspend","cap_audit_read","cap_perfmon","cap_bpf",
  "cap_checkpoint_restore"
};
static constexpr int CAP_LAST = 40;

// Classic dangerous / noteworthy libc imports.
static const std::set<std::string> RISKY_IMPORTS = {
  "gets","strcpy","strcat","sprintf","vsprintf","scanf","sscanf","fscanf",
  "system","popen","exec","execl","execle","execlp","execv","execve","execvp",
  "mktemp","tmpnam","tempnam","getwd","rand","random","srand",
  "alloca","getpass"
};

// ---- helpers ---------------------------------------------------------------
static std::string perm_str(uint64_t f) {
  std::string s;
  s += (f & elf::PF_R) ? 'R' : '-';
  s += (f & elf::PF_W) ? 'W' : '-';
  s += (f & elf::PF_X) ? 'X' : '-';
  return s;
}
static void hdr(const std::string& t) {
  printf("\n%s\n", B(CYN(t)).c_str());
}
static std::string yn_good(bool good, const std::string& yes,
                           const std::string& no) {
  return good ? GRN(yes) : RED(no);
}

// ---- per-file analysis -----------------------------------------------------
static bool read_file(const char* path, std::vector<uint8_t>& out) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return false;
  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) { close(fd); return false; }
  out.resize(static_cast<size_t>(st.st_size));
  size_t got = 0;
  while (got < out.size()) {
    ssize_t r = read(fd, out.data() + got, out.size() - got);
    if (r <= 0) break;
    got += static_cast<size_t>(r);
  }
  close(fd);
  out.resize(got);
  return true;
}

static void show_permissions(const char* path) {
  hdr("File permissions");
  struct stat st;
  if (lstat(path, &st) != 0) { printf("  (stat failed)\n"); return; }
  char mode[5];
  snprintf(mode, sizeof mode, "%04o",
           static_cast<unsigned>(st.st_mode & 07777));
  printf("  %-18s %s   uid=%u gid=%u\n", "mode", mode,
         (unsigned)st.st_uid, (unsigned)st.st_gid);

  bool flagged = false;
  if (st.st_mode & S_ISUID) {
    printf("  %-18s %s\n", "setuid",
           (st.st_uid == 0 ? RED("yes (setuid root)") : RED("yes")).c_str());
    flagged = true;
  }
  if (st.st_mode & S_ISGID) {
    printf("  %-18s %s\n", "setgid", RED("yes").c_str());
    flagged = true;
  }
  if (st.st_mode & S_ISVTX) {
    printf("  %-18s %s\n", "sticky", YEL("yes").c_str());
    flagged = true;
  }
  if (st.st_mode & S_IWOTH) {
    printf("  %-18s %s\n", "world-writable", RED("yes").c_str());
    flagged = true;
  }
  if (!flagged)
    printf("  %-18s %s\n", "special bits", DIMc("none").c_str());
}

static uint32_t le32(const unsigned char* b) {
  return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
         ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static void show_capabilities(const char* path) {
  hdr("File capabilities");
  unsigned char buf[64];
  ssize_t sz = getxattr(path, "security.capability", buf, sizeof buf);
  if (sz < 8) {  // ENODATA or too small -> no capabilities
    printf("  %s\n", DIMc("none").c_str());
    return;
  }
  uint32_t magic = le32(buf);
  uint32_t rev = magic & 0xFF000000u;
  bool effective = magic & 0x000000FFu;  // VFS_CAP_FLAGS_EFFECTIVE

  uint64_t permitted = le32(buf + 4);
  uint64_t inheritable = le32(buf + 8);
  if (sz >= 20 && rev >= 0x02000000u) {
    permitted   |= (uint64_t)le32(buf + 12) << 32;
    inheritable |= (uint64_t)le32(buf + 16) << 32;
  }

  auto names = [](uint64_t mask) {
    std::string s;
    for (int i = 0; i <= CAP_LAST; i++)
      if (mask & (1ull << i)) { s += (s.empty() ? "" : ", "); s += CAP_NAMES[i]; }
    if (s.empty()) s = "(none)";
    return s;
  };
  printf("  %-14s %s\n", "permitted", RED(names(permitted)).c_str());
  if (inheritable)
    printf("  %-14s %s\n", "inheritable", YEL(names(inheritable)).c_str());
  printf("  %-14s %s\n", "effective",
         effective ? RED("yes (caps active on exec)").c_str()
                   : DIMc("no").c_str());
}

// Main ELF parse + mitigation analysis.
static void analyze_elf(const std::vector<uint8_t>& data, bool verbose) {
  Reader R{data.data(), data.size(), true};
  bool ok = true;

  if (data.size() < 64 || memcmp(data.data(), elf::MAG, 4) != 0) {
    printf("  %s\n", RED("not an ELF file (bad magic)").c_str());
    return;
  }
  int cls = data[4];
  R.lsb = (data[5] != elf::DATA_MSB);
  bool is64 = (cls == elf::CLASS64);
  if (cls != elf::CLASS32 && cls != elf::CLASS64) {
    printf("  %s\n", RED("unknown ELF class").c_str());
    return;
  }

  // --- ELF header fields (offsets differ by class) ---
  uint64_t e_type   = R.u(16, 2, ok);
  uint64_t e_mach   = R.u(18, 2, ok);
  uint64_t e_entry  = is64 ? R.u(24, 8, ok) : R.u(24, 4, ok);
  uint64_t e_phoff  = is64 ? R.u(32, 8, ok) : R.u(28, 4, ok);
  uint64_t e_shoff  = is64 ? R.u(40, 8, ok) : R.u(32, 4, ok);
  uint64_t e_phentsz = R.u(is64 ? 54 : 42, 2, ok);
  uint64_t e_phnum  = R.u(is64 ? 56 : 44, 2, ok);
  uint64_t e_shentsz = R.u(is64 ? 58 : 46, 2, ok);
  uint64_t e_shnum  = R.u(is64 ? 60 : 48, 2, ok);
  uint64_t e_shstrndx = R.u(is64 ? 62 : 50, 2, ok);
  unsigned ei_osabi = data[7];

  hdr("ELF header");
  printf("  %-14s %s, %s\n", "format", is64 ? "ELF64" : "ELF32",
         R.lsb ? "little-endian" : "big-endian");
  const char* mn = machine_name(e_mach);
  if (mn) printf("  %-14s %s\n", "machine", mn);
  else    printf("  %-14s 0x%llx\n", "machine", (unsigned long long)e_mach);
  const char* an = osabi_name(ei_osabi);
  if (an) printf("  %-14s %s\n", "abi", an);
  const char* tn;
  switch (e_type) {
    case elf::ET_REL:  tn = "REL (relocatable)"; break;
    case elf::ET_EXEC: tn = "EXEC (executable)"; break;
    case elf::ET_DYN:  tn = "DYN (shared object / PIE)"; break;
    case elf::ET_CORE: tn = "CORE"; break;
    default:           tn = "NONE"; break;
  }
  printf("  %-14s %s\n", "type", tn);
  printf("  %-14s 0x%llx\n", "entry", (unsigned long long)e_entry);

  // --- program headers / segments ---
  bool has_interp = false, has_gnu_stack = false, stack_exec = false;
  bool has_relro = false, has_dynamic = false, has_rwx = false;
  uint64_t dyn_off = 0, dyn_sz = 0;
  struct Load { uint64_t vaddr, off, filesz; };
  std::vector<Load> loads;

  std::vector<std::string> seg_rows;
  for (uint64_t i = 0; i < e_phnum; i++) {
    uint64_t base = e_phoff + i * e_phentsz;
    uint64_t p_type = R.u(base, 4, ok);
    uint64_t p_flags, p_off, p_vaddr, p_filesz, p_memsz;
    if (is64) {
      p_flags  = R.u(base + 4, 4, ok);
      p_off    = R.u(base + 8, 8, ok);
      p_vaddr  = R.u(base + 16, 8, ok);
      p_filesz = R.u(base + 32, 8, ok);
      p_memsz  = R.u(base + 40, 8, ok);
    } else {
      p_off    = R.u(base + 4, 4, ok);
      p_vaddr  = R.u(base + 8, 4, ok);
      p_filesz = R.u(base + 16, 4, ok);
      p_memsz  = R.u(base + 20, 4, ok);
      p_flags  = R.u(base + 24, 4, ok);
    }
    if (!ok) break;

    if (p_type == elf::PT_INTERP)  has_interp = true;
    if (p_type == elf::PT_DYNAMIC) { has_dynamic = true; dyn_off = p_off; dyn_sz = p_filesz; }
    if (p_type == elf::PT_LOAD)    loads.push_back({p_vaddr, p_off, p_filesz});
    if (p_type == elf::PT_GNU_RELRO) has_relro = true;
    if (p_type == elf::PT_GNU_STACK) {
      has_gnu_stack = true;
      stack_exec = (p_flags & elf::PF_X);
    }
    if ((p_flags & elf::PF_W) && (p_flags & elf::PF_X)) has_rwx = true;

    char row[160];
    snprintf(row, sizeof row, "  %-13s %s  off=0x%-8llx vaddr=0x%-10llx memsz=0x%llx",
             ptype_name(p_type).c_str(), perm_str(p_flags).c_str(),
             (unsigned long long)p_off, (unsigned long long)p_vaddr,
             (unsigned long long)p_memsz);
    std::string r = row;
    if ((p_flags & elf::PF_W) && (p_flags & elf::PF_X)) r += RED("  <- W+X");
    seg_rows.push_back(r);
  }

  // Translate a virtual address to a file offset via PT_LOAD segments.
  auto vaddr_to_off = [&](uint64_t va, bool& good) -> uint64_t {
    for (const auto& l : loads)
      if (va >= l.vaddr && va < l.vaddr + l.filesz) { good = true; return l.off + (va - l.vaddr); }
    good = false; return 0;
  };

  // --- dynamic section (works even when section headers are stripped) ---
  std::vector<std::string> needed;
  std::string soname, rpath, runpath;
  bool bind_now = false, textrel = false, df1_pie = false;
  uint64_t dt_strtab_va = 0; bool have_strtab = false;
  std::vector<std::pair<uint64_t,uint64_t>> dyn_entries;  // (tag,val)

  if (has_dynamic) {
    uint64_t esz = is64 ? 16 : 8;
    for (uint64_t off = dyn_off; off + esz <= dyn_off + dyn_sz; off += esz) {
      uint64_t tag = is64 ? R.u(off, 8, ok) : R.u(off, 4, ok);
      uint64_t val = is64 ? R.u(off + 8, 8, ok) : R.u(off + 4, 4, ok);
      if (!ok) break;
      dyn_entries.push_back({tag, val});
      if (tag == elf::DT_NULL) break;
      switch (tag) {
        case elf::DT_STRTAB:  dt_strtab_va = val; have_strtab = true; break;
        case elf::DT_BIND_NOW: bind_now = true; break;
        case elf::DT_TEXTREL:  textrel = true; break;
        case elf::DT_FLAGS:
          if (val & elf::DF_BIND_NOW) bind_now = true;
          if (val & elf::DF_TEXTREL) textrel = true;
          break;
        case elf::DT_FLAGS_1:
          if (val & elf::DF_1_NOW) bind_now = true;
          if (val & elf::DF_1_PIE) df1_pie = true;
          break;
      }
    }
    // Resolve string-table-relative names now that we know DT_STRTAB.
    if (have_strtab) {
      bool g; uint64_t stroff = vaddr_to_off(dt_strtab_va, g);
      if (g) {
        for (auto& e : dyn_entries) {
          if (e.first == elf::DT_NEEDED)  needed.push_back(R.str(stroff + e.second));
          else if (e.first == elf::DT_SONAME)  soname  = R.str(stroff + e.second);
          else if (e.first == elf::DT_RPATH)   rpath   = R.str(stroff + e.second);
          else if (e.first == elf::DT_RUNPATH) runpath = R.str(stroff + e.second);
        }
      }
    }
  }

  // --- symbols (need section headers): collect names for mitigation hints ---
  std::unordered_set<std::string> symbols;
  bool have_sections = (e_shnum > 0 && e_shoff != 0);
  std::vector<std::string> wx_sections;
  if (have_sections) {
    auto sh_field = [&](uint64_t idx, int which) -> uint64_t {
      uint64_t b = e_shoff + idx * e_shentsz;
      // which: 0 name,1 type,2 flags,4 offset,5 size,6 link,8 entsize
      if (is64) {
        switch (which) {
          case 0: return R.u(b, 4, ok); case 1: return R.u(b + 4, 4, ok);
          case 2: return R.u(b + 8, 8, ok); case 4: return R.u(b + 24, 8, ok);
          case 5: return R.u(b + 32, 8, ok); case 6: return R.u(b + 40, 4, ok);
          case 8: return R.u(b + 56, 8, ok);
        }
      } else {
        switch (which) {
          case 0: return R.u(b, 4, ok); case 1: return R.u(b + 4, 4, ok);
          case 2: return R.u(b + 8, 4, ok); case 4: return R.u(b + 16, 4, ok);
          case 5: return R.u(b + 20, 4, ok); case 6: return R.u(b + 24, 4, ok);
          case 8: return R.u(b + 36, 4, ok);
        }
      }
      return 0;
    };
    // section-header string table (for W+X section names)
    uint64_t shstr_off = 0;
    if (e_shstrndx < e_shnum) shstr_off = sh_field(e_shstrndx, 4);

    for (uint64_t i = 0; i < e_shnum; i++) {
      uint64_t type = sh_field(i, 1);
      uint64_t flags = sh_field(i, 2);
      if ((flags & elf::SHF_WRITE) && (flags & elf::SHF_EXECINSTR)) {
        std::string nm = shstr_off ? R.str(shstr_off + sh_field(i, 0)) : "?";
        wx_sections.push_back(nm.empty() ? "?" : nm);
      }
      if (type == elf::SHT_DYNSYM || type == elf::SHT_SYMTAB) {
        uint64_t link = sh_field(i, 6);
        uint64_t stroff = (link < e_shnum) ? sh_field(link, 4) : 0;
        uint64_t off = sh_field(i, 4), size = sh_field(i, 5);
        uint64_t entsz = sh_field(i, 8); if (!entsz) entsz = is64 ? 24 : 16;
        for (uint64_t s = off; s + entsz <= off + size; s += entsz) {
          uint64_t st_name = R.u(s, 4, ok);
          if (!ok) break;
          if (st_name && stroff) {
            std::string nm = R.str(stroff + st_name);
            if (!nm.empty()) symbols.insert(nm);
          }
        }
      }
    }
  }

  bool canary = symbols.count("__stack_chk_fail") || symbols.count("__stack_chk_guard");
  int fortify = 0;
  for (const auto& s : symbols) if (s.size() > 5 && s.compare(s.size()-5,5,"_chk")==0) fortify++;
  // (compare above tolerant: also catch *_chk)
  if (fortify == 0)
    for (const auto& s : symbols)
      if (s.size() >= 4 && s.compare(s.size()-4,4,"_chk")==0) { fortify++; }

  // --- mitigations summary ---
  hdr("Exploit mitigations");
  // PIE
  std::string pie;
  if (e_type == elf::ET_EXEC) pie = RED("Disabled (no PIE)");
  else if (e_type == elf::ET_DYN && (has_interp || df1_pie)) pie = GRN("Enabled (PIE)");
  else if (e_type == elf::ET_DYN) pie = CYN("Shared object (DSO)");
  else pie = DIMc("n/a");
  printf("  %-16s %s\n", "PIE", pie.c_str());

  // NX
  std::string nx;
  if (!has_gnu_stack) nx = YEL("Unknown (no GNU_STACK)");
  else nx = stack_exec ? RED("Disabled (exec stack)") : GRN("Enabled");
  printf("  %-16s %s\n", "NX (no-exec)", nx.c_str());

  // RELRO
  std::string relro;
  if (!has_relro) relro = RED("None");
  else relro = bind_now ? GRN("Full") : YEL("Partial");
  printf("  %-16s %s\n", "RELRO", relro.c_str());

  // Canary / Fortify only meaningful when we could read symbols
  if (have_sections && !symbols.empty()) {
    printf("  %-16s %s\n", "Stack canary",
           yn_good(canary, "Found", "Not found").c_str());
    std::string fort = fortify
        ? GRN(std::to_string(fortify) + " fortified calls")
        : DIMc("none detected");
    printf("  %-16s %s\n", "FORTIFY", fort.c_str());
  } else {
    printf("  %-16s %s\n", "Stack canary", DIMc("symbols stripped").c_str());
  }

  // RPATH / RUNPATH
  if (!rpath.empty())
    printf("  %-16s %s\n", "RPATH", RED(rpath + "  (insecure)").c_str());
  if (!runpath.empty())
    printf("  %-16s %s\n", "RUNPATH", YEL(runpath).c_str());
  if (rpath.empty() && runpath.empty())
    printf("  %-16s %s\n", "RPATH/RUNPATH", GRN("none").c_str());

  if (textrel)
    printf("  %-16s %s\n", "TEXTREL", RED("yes (writable code relocs)").c_str());
  if (has_rwx)
    printf("  %-16s %s\n", "W+X segment", RED("yes").c_str());
  for (const auto& s : wx_sections)
    printf("  %-16s %s\n", "W+X section", RED(s).c_str());

  // --- dynamic dependencies ---
  if (has_dynamic) {
    hdr("Dynamic linking");
    if (!soname.empty()) printf("  %-10s %s\n", "soname", soname.c_str());
    printf("  %-10s %s\n", "bind-now", bind_now ? GRN("yes").c_str() : DIMc("no").c_str());
    if (needed.empty()) printf("  %-10s %s\n", "needed", DIMc("(none)").c_str());
    for (const auto& n : needed) printf("  %-10s %s\n", "needed", n.c_str());
  }

  // --- risky imports ---
  std::vector<std::string> risky;
  for (const auto& s : symbols) {
    std::string base = s;
    // strip a leading "__" wrapper or trailing version not handled; keep simple
    if (RISKY_IMPORTS.count(base)) risky.push_back(base);
  }
  if (!risky.empty()) {
    std::sort(risky.begin(), risky.end());
    hdr("Noteworthy imports");
    for (const auto& s : risky)
      printf("  %s\n", YEL(s).c_str());
  }

  // --- verbose: full segment list ---
  if (verbose) {
    hdr("Segments");
    for (const auto& r : seg_rows) printf("%s\n", r.c_str());
  }

  if (!ok)
    printf("\n  %s\n", YEL("note: file appears truncated or malformed; "
                           "some fields may be incomplete").c_str());
}

// ---- CLI -------------------------------------------------------------------
static void usage() {
  printf(
    "husk — read-only ELF / permissions / capability inspector\n\n"
    "Usage: husk [options] <file> [file...]\n\n"
    "Options:\n"
    "  -a, --all        verbose (also list every loadable segment)\n"
    "      --no-color   disable ANSI colour\n"
    "  -h, --help       show this help\n\n"
    "husk never executes the target; it only reads it.\n");
}

int main(int argc, char** argv) {
  bool verbose = false;
  std::vector<const char*> files;
  g_color = isatty(STDOUT_FILENO);

  for (int i = 1; i < argc; i++) {
    std::string a = argv[i];
    if (a == "-h" || a == "--help") { usage(); return 0; }
    else if (a == "-a" || a == "--all") verbose = true;
    else if (a == "--no-color") g_color = false;
    else if (a == "--color") g_color = true;
    else if (!a.empty() && a[0] == '-') {
      fprintf(stderr, "husk: unknown option '%s'\n", a.c_str());
      return 2;
    } else files.push_back(argv[i]);
  }
  if (files.empty()) { usage(); return 2; }

  int rc = 0;
  for (size_t i = 0; i < files.size(); i++) {
    const char* path = files[i];
    if (i) printf("\n");
    printf("%s %s\n", B("==>").c_str(), B(path).c_str());

    std::vector<uint8_t> data;
    if (!read_file(path, data)) {
      printf("  %s\n", RED("cannot read file (missing, not regular, "
                           "or permission denied)").c_str());
      rc = 1;
      continue;
    }
    printf("  %-14s %zu bytes\n", "size", data.size());
    show_permissions(path);
    show_capabilities(path);
    analyze_elf(data, verbose);
  }
  return rc;
}
