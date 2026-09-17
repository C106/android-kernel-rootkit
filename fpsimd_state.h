#ifndef LK1337_FPSIMD_H
#define LK1337_FPSIMD_H

#include <asm/fpsimd.h>
#include <asm/simd.h>
#include "debugger_uapi.h"

void lk1337_fpsimd_save(struct user_fpsimd_state *state);
void lk1337_fpsimd_load(struct user_fpsimd_state *state);
#ifdef CONFIG_ARM64_SVE
void lk1337_sve_save(void *state, u32 *fpsr);
void lk1337_sve_load(const void *state, const u32 *fpsr, unsigned long vq_minus_one);
#endif

static bool lk1337_fp_capture(struct lk1337_snapshot *snapshot)
{
	struct user_fpsimd_state *state = &current->thread.uw.fpsimd_state;
	bool live = !test_thread_flag(TIF_FOREIGN_FPSTATE);
	unsigned int index;

	if (in_nmi() || in_irq() || __this_cpu_read(fpsimd_context_busy))
		return false;
#ifdef CONFIG_ARM64_SVE
	if (test_thread_flag(TIF_SVE)) {
		if (!current->thread.sve_state || !current->thread.sve_vl)
			return false;
		if (live)
			lk1337_sve_save(sve_pffr(&current->thread), &state->fpsr);
		for (index = 0; index < 32; index++)
			memcpy(&snapshot->vregs[index],
			       (char *)current->thread.sve_state +
			       index * current->thread.sve_vl, 16);
	} else
#endif
	{
		if (live)
			lk1337_fpsimd_save(state);
		memcpy(snapshot->vregs, state->vregs, sizeof(snapshot->vregs));
	}
	snapshot->fpsr = state->fpsr;
	snapshot->fpcr = state->fpcr;
	return true;
}

/* Update the task's saved user FPSIMD state.  The architecture return-to-user
 * path observes TIF_FOREIGN_FPSTATE and restores this state after the debug
 * exception; no FPSIMD instructions are executed from the breakpoint handler.
 */
static bool lk1337_fp_stage_template(const struct lk1337_template *change)
{
	struct user_fpsimd_state *state = &current->thread.uw.fpsimd_state;
	unsigned int index;

	if (!system_supports_fpsimd())
		return false;
	/* The saved state is authoritative when the CPU copy is foreign. */
	/* Do not execute FPSIMD instructions here: this function may run from the
	 * architectural debug exception path with interrupts disabled. */
	for (index = 0; index < 32; index++)
		if (change->fp_mask & BIT(index))
			state->vregs[index] = ((__uint128_t)change->values.vregs[index].high << 64) |
					change->values.vregs[index].low;
	if (change->control_mask & 1)
		state->fpsr = change->values.fpsr;
	if (change->control_mask & 2)
		state->fpcr = change->values.fpcr;
	set_thread_flag(TIF_FOREIGN_FPSTATE);
	return true;
}

static __maybe_unused void lk1337_fp_apply(const struct lk1337_snapshot *snapshot)
{
	struct user_fpsimd_state *state = &current->thread.uw.fpsimd_state;
	bool live = !test_thread_flag(TIF_FOREIGN_FPSTATE);
	unsigned int index;

	memcpy(state->vregs, snapshot->vregs, sizeof(snapshot->vregs));
	state->fpsr = snapshot->fpsr;
	state->fpcr = snapshot->fpcr;
#ifdef CONFIG_ARM64_SVE
	if (test_thread_flag(TIF_SVE)) {
		for (index = 0; index < 32; index++)
			memcpy((char *)current->thread.sve_state +
			       index * current->thread.sve_vl,
			       &snapshot->vregs[index], 16);
		if (live)
			lk1337_sve_load(sve_pffr(&current->thread), &state->fpsr,
				    sve_vq_from_vl(current->thread.sve_vl) - 1);
	} else
#endif
	if (live)
		lk1337_fpsimd_load(state);
}

#endif
