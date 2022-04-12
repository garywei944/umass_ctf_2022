// https://code.woboq.org/userspace/glibc/elf/dl-runtime.c.html

_dl_fixup(struct link_map *l, ElfW(Word) reloc_arg) {
  // Load address of DT_SYMTAB from link_map
  const ElfW(Sym) *const symtab = (const void *)D_PTR(l, l_info[DT_SYMTAB]);
  // Load address of DT_SYMTAB from link_map
  const char *strtab = (const void *)D_PTR(l, l_info[DT_STRTAB]);
  // Load the coresponding struct from .rela.plt
  const PLTREL *const reloc =
      (const void *)(D_PTR(l, l_info[DT_JMPREL]) + reloc_offset);
  // Load the coresponding struct from .symtab
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM)(reloc->r_info)];
  const ElfW(Sym) *refsym = sym;

  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
  lookup_t result;
  DL_FIXUP_VALUE_TYPE value;

  /* Sanity check that we're really looking at a PLT relocation.  */
  // Check if the least bit of r_info is 7
  assert(ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);
  /* Look up the target symbol.  If the normal lookup rules are not
     used don't look in the global scope.  */
  // Check if sym->st_other == 0, normally it should be
  if (__builtin_expect(ELFW(ST_VISIBILITY)(sym->st_other), 0) == 0) {
    const struct r_found_version *version = NULL;

    // Check if DT_VERSYM in link_map is NULL, normally it's not
    if (l->l_info[VERSYMIDX(DT_VERSYM)] != NULL) {
      /* ***********************************************************************
        Segmentation fault: this is where ret2dlresolve doesn't work on 64-bit
        machine with large page.

        When executing vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff to compute
        the version number, the big gap between BSS and SYMTAB makes
        reloc->r_info too large and finally lead to a segmentation fault.

        To work around it, the first choice is to make the DT_VERSYM in link_map
        to be NULL. To do so, we need to leak the address of link_map, which
        then we makes ret2dlresolve dumb.

        The second choice is to make the outter if failed, so we need to set
        sym->st_other (the 6th byte of the struct) not equals to 0, and jump to
        the next else.
      *********************************************************************** */
      const ElfW(Half) *vernum =
          (const void *)D_PTR(l, l_info[VERSYMIDX(DT_VERSYM)]);
      ElfW(Half) ndx = vernum[ELFW(R_SYM)(reloc->r_info)] & 0x7fff;
      version = &l->l_versions[ndx];
      if (version->hash == 0) version = NULL;
    }
    /* We need to keep the scope around so do some locking.  This is
       not necessary for objects which cannot be unloaded or when
       we are not using any threads (yet).  */
    int flags = DL_LOOKUP_ADD_DEPENDENCY;
    if (!RTLD_SINGLE_THREAD_P) {
      THREAD_GSCOPE_SET_FLAG();
      flags |= DL_LOOKUP_GSCOPE_LOCK;
    }

    // The program won't crash in 32-bit machine and result is the successfully
    // loaded base address of libc.
    result = _dl_lookup_symbol_x(strtab + sym->st_name, l, &sym, l->l_scope,
                                 version, ELF_RTYPE_CLASS_PLT, flags, NULL);
    /* We are done with the global scope.  */
    if (!RTLD_SINGLE_THREAD_P) THREAD_GSCOPE_RESET_FLAG();
    /* Currently result contains the base load address (or link map)
       of the object that defines sym.  Now add in the symbol
       offset.  */
    // Similarly, on 32-bit machine, the function address is computed by
    // value = result + st_value
    value = DL_FIXUP_MAKE_VALUE(result, SYMBOL_ADDRESS(result, sym, false));
  } else {
    /* *************************************************************************
      This is the key point for my approach, if we make the if statement above
      failed, the function address is computed by

      value = l->l_addr + st_value

      Theoretically, we can contol these 2 parameter in .symtab and link_map and
      resolve to the function that we need by set

      l_addr = addr_system - addr_xxxx

      and

      value = addr_system - addr_xxxx + real_xxxx = real_system
    ************************************************************************* */
    /* We already found the symbol.  The module (and therefore its load
       address) is also known.  */
    value = DL_FIXUP_MAKE_VALUE(l, SYMBOL_ADDRESS(l, sym, true));
    result = l;
  }
  /* And now perhaps the relocation addend.  */
  value = elf_machine_plt_value(l, reloc, value);
  if (sym != NULL &&
      __builtin_expect(ELFW(ST_TYPE)(sym->st_info) == STT_GNU_IFUNC, 0))
    value = elf_ifunc_invoke(DL_FIXUP_VALUE_ADDR(value));
  /* Finally, fix up the plt itself.  */
  if (__glibc_unlikely(GLRO(dl_bind_not))) return value;

  // FInally, write value into GOT
  return elf_machine_fixup_plt(l, result, refsym, sym, reloc, rel_addr, value);
}

typedef struct {
  Elf64_Word st_name;      // 4 bytes /* Symbol name (string tbl index) */
  unsigned char st_info;   // 1 byte  /* Symbol type and binding */
  unsigned char st_other;  // 1 byte  /* Symbol visibility */
  Elf64_Section st_shndx;  // 2 bytes /* Section index */
  Elf64_Addr st_value;     // 8 bytes /* Symbol value */
  Elf64_Xword st_size;     // 8 bytes /* Symbol size */
} Elf64_Sym;

struct link_map {
  /* Difference between the address in the ELF
   file and the addresses in memory.  */
  Elf64_Addr l_addr;  // 8 bytes

  char *l_name;     // 8 bytes /* Absolute file name object was found in.  */
  Elf64_Dyn *l_ld;  // 8 bytes /* Dynamic section of the shared object.  */
  struct link_map *l_next;  // 8 bytes /* Chain of loaded objects.  */
  struct link_map *l_prev;  // 8 bytes /* Chain of loaded objects.  */

  /* All following members are internal to the dynamic linker.
     They may change without notice.  */
  /* This is an element which is only ever different from a pointer to
     the very same copy of this type for ld.so when it is used in more
     than one namespace.  */
  struct link_map *l_real;  // 8 bytes
  /* Number of the namespace this link map belongs to.  */
  Lmid_t l_ns;                     // 8 bytes
  struct libname_list *l_libname;  // 8 bytes
  // l_info contains all the sym tables, 77 * 8 bytes
  // l_info[5] is ptr to DT_STRTAB
  // l_info[6] is ptr to DT_SYMTAB
  // l_info[23] is ptr to DT_JMPREL
  Elf64_Dyn *l_info[77];
  ... size_t l_tls_firstbyte_offset;
  ptrdiff_t l_tls_offset;
  size_t l_tls_modid;
  size_t l_tls_dtor_count;
  Elf64_Addr l_relro_addr;
  size_t l_relro_size;
  unsigned long long l_serial;
  struct auditstate l_audit[];
}
