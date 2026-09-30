#include <linux/linkage.h>
#include <asm/assembler.h>
#include <asm/fpsimdmacros.h>
#include <linux/version.h>

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
#ifdef LK1337_HAS_THREAD_SVE_VL
	mov x3, #1
	sve_save 0, x1, x3, 2
#else
	sve_save 0, x1, 2
#endif
	ret
SYM_FUNC_END(lk1337_sve_save)

SYM_FUNC_START(lk1337_sve_load)
#ifdef LK1337_HAS_THREAD_SVE_VL
	sve_load 0, x1, x2, 3
#else
	sve_load 0, x1, x2, 3, x4
#endif
	ret
SYM_FUNC_END(lk1337_sve_load)
#endif
