_dl_fixup (struct link_map *l, ElfW(Word) reloc_arg) // 第一个参数link_map，也就是got[1]
{
    // 获取link_map中存放DT_SYMTAB的地址
  const ElfW(Sym) *const symtab = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
    // 获取link_map中存放DT_STRTAB的地址
  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);
	// reloc_offset就是reloc_arg,获取重定位表项中对应函数的结构体
  const PLTREL *const reloc = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
    // 根据重定位结构体的r_info得到symtab表中对应的结构体
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
    
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
  lookup_t result;
  DL_FIXUP_VALUE_TYPE value;

  /* Sanity check that we're really looking at a PLT relocation.  */
  assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT); // 检查r_info的最低位是不是7

   /* Look up the target symbol.  If the normal lookup rules are not
      used don't look in the global scope.  */
  if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0) // 这里是一层检测，检查sym结构体中的st_other是否为0，正常情况下为0，执行下面代码
    {
      const struct r_found_version *version = NULL;
	// 这里也是一层检测，检查link_map中的DT_VERSYM是否为NULL，正常情况下不为NULL，执行下面代码
      if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
	{
      // 到了这里就是64位下报错的位置，在计算版本号时，vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff的过程中，由于我们一般伪造的symtab
      // 位于bss段，就导致在64位下reloc->r_info比较大,故程序会发生错误。所以要使程序不发生错误，自然想到的办法就是不执行这里的代码，分析上面的
      // 代码我们就可以得到两种手段，第一种手段就是使上一行的if不成立，也就是设置link_map中的DT_VERSYM为NULL，那我们就要泄露出link_map的地址，
      // 而如果我们能泄露地址，根本用不着ret2dlresolve。第二种手段就是使最外层的if不成立，也就是使sym结构体中的st_other不为0，直接跳到后面的else语句执行。
	  const ElfW(Half) *vernum = (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
	  ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
	  version = &l->l_versions[ndx];
	  if (version->hash == 0)
	    version = NULL;
	}

      /* We need to keep the scope around so do some locking.  This is
	 not necessary for objects which cannot be unloaded or when
	 we are not using any threads (yet).  */
      int flags = DL_LOOKUP_ADD_DEPENDENCY;
      if (!RTLD_SINGLE_THREAD_P)
	{
	  THREAD_GSCOPE_SET_FLAG ();
	  flags |= DL_LOOKUP_GSCOPE_LOCK;
	}

      RTLD_ENABLE_FOREIGN_CALL;
	// 在32位情况下，上面代码运行中不会出错，就会走到这里，这里通过strtab+sym->st_name找到符号表字符串，result为libc基地址
      result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
				    version, ELF_RTYPE_CLASS_PLT, flags, NULL);

      /* We are done with the global scope.  */
      if (!RTLD_SINGLE_THREAD_P)
	THREAD_GSCOPE_RESET_FLAG ();

      RTLD_FINALIZE_FOREIGN_CALL;

      /* Currently result contains the base load address (or link map)
	 of the object that defines sym.  Now add in the symbol
	 offset.  */
      // 同样，如果正常执行，接下来会来到这里，得到value的值，为libc基址加上要解析函数的偏移地址，也即实际地址，即result+st_value
      value = DL_FIXUP_MAKE_VALUE (result, sym ? (LOOKUP_VALUE_ADDRESS (result) + sym->st_value) : 0);
    }
  else
    { 
      // 这里就是64位下利用的关键，在最上面的if不成立后，就会来到这里,这里value的计算方式是 l->l_addr + st_value,我们的目的是使value为我们所需要的函数的地址，所以就得控制两个参数，l_addr 和 st_value
      /* We already found the symbol.  The module (and therefore its load
	 address) is also known.  */
      value = DL_FIXUP_MAKE_VALUE (l, l->l_addr + sym->st_value);
      result = l;
    }

  /* And now perhaps the relocation addend.  */
  value = elf_machine_plt_value (l, reloc, value);

  if (sym != NULL
      && __builtin_expect (ELFW(ST_TYPE) (sym->st_info) == STT_GNU_IFUNC, 0))
    value = elf_ifunc_invoke (DL_FIXUP_VALUE_ADDR (value));

  /* Finally, fix up the plt itself.  */
  if (__glibc_unlikely (GLRO(dl_bind_not)))
    return value;
  // 最后把value写入相应的GOT表条目中
  return elf_machine_fixup_plt (l, result, reloc, rel_addr, value);
}

