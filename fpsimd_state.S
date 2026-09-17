#include <linux/linkage.h>
#include <asm/assembler.h>
#include <asm/fpsimdmacros.h>

SYM_FUNC_START(lk1337_fpsimd_save)
	fpsimd_save x0, 8
	ret
SYM_FUNC_END(lk1337_fpsimd_save)

SYM_FUNC_START(lk1337_fpsimd_load)
	fpsimd_restore x0, 8
	ret
SYM_FUNC_END(lk1337_fpsimd_load)

#ifdef CONFIG_ARM64_SVE
SYM_FUNC_START(lk1337_sve_save)
	sve_save 0, x1, 2
	ret
SYM_FUNC_END(lk1337_sve_save)

SYM_FUNC_START(lk1337_sve_load)
	sve_load 0, x1, x2, 3, x4
	ret
SYM_FUNC_END(lk1337_sve_load)
#endif
