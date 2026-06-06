/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Nathaniel Filardo
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/counter.h>

#include <machine/_inttypes.h>
#include <machine/cheric.h>
#include <cheri/cheri.h>
#include <cheri/cheric.h>
#include <cheri/revoke.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_param.h>
#include <vm/vm_map.h>
#include <vm/vm_cheri_revoke.h>

/* Check the coarse-grained MAP bitmap */
static inline unsigned long
vm_cheri_revoke_test_mem_map(const uint8_t * __capability crshadow,
    uintcap_t cut)
{
	uint8_t bmbits;
	const uint8_t * __capability bmloc;

	ptraddr_t va = cheri_getbase(cut);

	bmloc = crshadow - VM_CHERI_REVOKE_BSZ_OTYPE -
	    (va / VM_CHERI_REVOKE_GSZ_MEM_MAP / 8);

#ifdef CHERI_CAPREVOKE_FAST_COPYIN
	/* XXX This is terribly, terribly unsafe and should go away. */
	bmbits = *bmloc;
#else
	{
		int bmbits_ext = fubyte(bmloc);
		if (bmbits_ext == -1) {
			printf("%s: failed to read shadow for %#.16lp"
			    "(s=%#.16lp); assuming not revoked!\n",
			    __func__, (void * __capability)cut, crshadow);
			return (0);
		}
		bmbits = bmbits_ext & 0xFF;
	}
#endif

	/* Fast path: often these are all zeros */

	if (bmbits == 0) {
		return (0);
	}

	return (bmbits & (1 << ((va / VM_CHERI_REVOKE_GSZ_MEM_MAP) % 8)));
}

/* Check the fine-grained NOMAP bitmap */
static inline unsigned long
vm_cheri_revoke_test_mem_nomap(const uint8_t * __capability crshadow,
    uintcap_t cut)
{
	(void)crshadow;
	(void)cut;
	return 0;
}

static inline unsigned
vm_cheri_revoke_test_range(vm_offset_t start, vm_offset_t end, uintcap_t cut)
{
	ptraddr_t va = cheri_getbase(cut);

	return (va >= start && va < end);
}

// TODO: if ((perms & CHERI_PERMS_HWALL_OTYPE) != 0)
// TODO: if ((perms & CHERI_PERMS_HWALL_CID) != 0)

static unsigned long
vm_cheri_revoke_test_just_mem(const uint8_t * __capability crshadow,
    uintcap_t cut, unsigned long perms, vm_offset_t start, vm_offset_t end)
{
	if ((perms & (CHERI_PERMS_HWALL_MEMORY | CHERI_PERM_SW_VMEM)) != 0) {
		if (vm_cheri_revoke_test_mem_map(crshadow, cut))
			return (1);

		if ((perms & CHERI_PERM_SW_VMEM) == 0)
			return (vm_cheri_revoke_test_mem_nomap(crshadow, cut));
	}

	return (0);
}

static unsigned long
vm_cheri_revoke_test_just_mem_fine(const uint8_t * __capability crshadow,
    uintcap_t cut, unsigned long perms, vm_offset_t start, vm_offset_t end)
{
	/*
	 * Most capabilities are memory capabilities, most are unrevoked,
	 * and comparatively few are VMMAP-bearing.... so do the load
	 * first and only then do the permissions checks.
	 */

	if (vm_cheri_revoke_test_mem_nomap(crshadow, cut)) {
		if (__builtin_expect(perms & CHERI_PERM_SW_VMEM,0)) {
			return (0);
		}

		return ((perms & CHERI_PERMS_HWALL_MEMORY) != 0);
	}

	return (0);
}

static unsigned long
vm_cheri_revoke_test_mem_fine_range(const uint8_t * __capability crshadow,
    uintcap_t cut, unsigned long perms, vm_offset_t start, vm_offset_t end)
{
	/*
	 * Only check the capability if it has some memory permissions.
	 */
	if ((perms & CHERI_PERMS_HWALL_MEMORY) != 0) {
		if (vm_cheri_revoke_test_range(start, end, cut))
			return (1);

		if ((perms & CHERI_PERM_SW_VMEM) == 0) {
			return vm_cheri_revoke_test_mem_nomap(crshadow, cut);
		}
	}

	return (0);
}

#ifdef CHERI_CAPREVOKE_CAPID
/*
 * If the capability under test is valid and has some memory permissions:
 * Check for CapID: if the CapID is non-zero, probe the capability to verify
 * whether CapID == QUARANTINED_CAPID.
 * If the CapID == 0, revoke using the shadow bitmap.
 */
static unsigned long
vm_cheri_revoke_test_capid(const uint8_t * __capability crshadow __unused,
    uintcap_t cut, unsigned long perms, vm_offset_t start __unused,
    vm_offset_t end __unused)
{
	void * __capability priv_cut;
	int capid;
	int err;

	if (__builtin_expect(perms & CHERI_PERM_SW_VMEM, 0)) {
		return (0);
	}

	/*
	 * We must tolerate page faults during the CapID probe.
	 * These are user page faults coming from kernel space.
	 * To do this we need CAPREVOKE_FAST_COPYIN or fuecapid to
	 * install a custom pcb_onfault.
	 * If we get a page fault, this also means that we may get
	 * a recurive page scan, because the revoker needs to observe
	 * that page. Luckily the CapID probe is nominally a data load
	 * and should never trigger a CRG fault.
	 * The recursive page scan MUST be avoided to keep the fucapid
	 * computationally bounded.
	 * To do so, we make sure to fault-in the pages without capability
	 * permission bits, to ensure that a full scan will occur at a later
	 * stage.
	 *
	 * Note that the cut capability needs to be re-derived here, because to
	 * perform the CapID probe:
	 * - It can not be sealed
	 * - It must permit PERM_LOAD (XXX-AM maybe?)
	 * - It must have CapID == 0 (XXX-AM or maybe bear PERM_CAPID?)
	 * XXX-AM: We should use cheri_capability_build_user_rwx, but
	 * it will lock the curthread map and lookup the mapping to
	 * check that the reservation layout is sensible.
	 * We use the userspace root cap here to avoid doing
	 * this in the revoker loop.
	 */
	if (cheri_capid_get(cut) != 0) {
		priv_cut = cheri_setoffset(userspace_root_cap,
		    cheri_getbase(cut));
		priv_cut = cheri_setbounds(priv_cut, cheri_getlen(cut));
		priv_cut = cheri_capid_mode_set(priv_cut,
		    cheri_capid_mode_get(cut));
		priv_cut = cheri_capid_loc_set(priv_cut,
		    cheri_capid_loc_get(cut));
		err = fuecapid(priv_cut, &capid);

		counter_u64_add(cheri_capid_probe_count, 1);
		if (err != KERN_SUCCESS)
			counter_u64_add(cheri_capid_probe_fail, 1);

		/*
		 * The capid probe has an interesting failure mode when the
		 * underlying memory is not backed (e.g. stack guard pages).
		 * These cases are suspicious because we should never see
		 * a capability with CapID != 0 that points to unmapped
		 * memory? Or maybe we can, if somebody calls munmap() but
		 * the entry is not revoked yet...
		 * In these cases it seems prudent to fail-close and invalidate
		 * the capability.
		 */
		return (err != KERN_SUCCESS || capid == CAPID_QUARANTINED);
	}

	counter_u64_add(cheri_capid_fallback, 1);
	if (vm_cheri_revoke_test_mem_nomap(crshadow, cut)) {
		return ((perms & CHERI_PERMS_HWALL_MEMORY) != 0);
	}

	return (0);
}

/*
 * Same as vm_cheri_revoke_test_capid, but also check the revoked map entry.
 */
static unsigned long
vm_cheri_revoke_test_capid_just_mem(const uint8_t * __capability crshadow __unused,
    uintcap_t cut, unsigned long perms, vm_offset_t start __unused,
    vm_offset_t end __unused)
{

	if ((perms & CHERI_PERMS_HWALL_MEMORY) != 0) {
		if (vm_cheri_revoke_test_range(start, end, cut))
			return (1);
		return (vm_cheri_revoke_test_capid(crshadow, cut, perms,
		    start, end));
	}

	return (0);
}
#endif

void
vm_cheri_revoke_set_test(vm_map_t map, int flags)
{
	switch(flags) {
	case VM_CHERI_REVOKE_CF_NO_COARSE_MEM |
	    VM_CHERI_REVOKE_CF_NO_OTYPES |
	    VM_CHERI_REVOKE_CF_NO_CIDS:

		map->vm_cheri_revoke_test = vm_cheri_revoke_test_mem_fine_range;
		break;

	case VM_CHERI_REVOKE_CF_NO_COARSE_MEM |
	    VM_CHERI_REVOKE_CF_NO_OTYPES |
	    VM_CHERI_REVOKE_CF_NO_CIDS |
	    VM_CHERI_REVOKE_CF_NO_REV_ENTRY:

		map->vm_cheri_revoke_test = vm_cheri_revoke_test_just_mem_fine;
		break;

	case VM_CHERI_REVOKE_CF_NO_OTYPES |
	    VM_CHERI_REVOKE_CF_NO_CIDS |
	    VM_CHERI_REVOKE_CF_NO_REV_ENTRY:

		map->vm_cheri_revoke_test = vm_cheri_revoke_test_just_mem;
		break;

#ifdef CHERI_CAPREVOKE_CAPID
	case VM_CHERI_REVOKE_CF_CAPID |
	    VM_CHERI_REVOKE_CF_NO_COARSE_MEM |
	    VM_CHERI_REVOKE_CF_NO_OTYPES |
	    VM_CHERI_REVOKE_CF_NO_CIDS:
		map->vm_cheri_revoke_test = vm_cheri_revoke_test_capid;
		break;

	case VM_CHERI_REVOKE_CF_CAPID |
	    VM_CHERI_REVOKE_CF_NO_COARSE_MEM |
	    VM_CHERI_REVOKE_CF_NO_OTYPES |
	    VM_CHERI_REVOKE_CF_NO_CIDS |
	    VM_CHERI_REVOKE_CF_NO_REV_ENTRY:
		map->vm_cheri_revoke_test = vm_cheri_revoke_test_capid_just_mem;
		break;
#endif

	default:
		panic("Bad cheri_revoke cookie flags 0x%x\n", flags);
	}
}
