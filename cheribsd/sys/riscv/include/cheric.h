/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 John Baldwin
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

#ifndef _MACHINE_CHERIC_H_
#define	_MACHINE_CHERIC_H_

#if __has_feature(capabilities)
#define	cheri_capmode(cap)	cheri_setflags(cap, CHERI_FLAGS_CAP_MODE)
#endif

#ifdef _KERNEL
/* XXX: Convert faulting CBuildCap into tag-stripping. */
extern void * __capability cheri_buildcap_safe(void * __capability, intcap_t);

#undef cheri_buildcap
#define	cheri_buildcap(x, y)	cheri_buildcap_safe((x), (y))
#endif

#ifdef __CHERI_PURE_CAPABILITY__
/* CHERI Cap-ID intrinsics */
#define	cheri_capid_set(x, id) __extension__({			\
	__typeof__(x) __result;					\
	__asm__ __volatile__("csetmte %0, %1, %2"		\
	    : "=C" (__result) : "C" (x), "r" (id));		\
	__result; })

#define	cheri_capid_loc_set(x, loc) __extension__({		\
	__typeof__(x) __result;					\
	__asm__ __volatile__("csettloc %0, %1, %2"		\
	    : "=C" (__result) : "C" (x), "r" (loc));		\
	__result; })

#define	cheri_capid_mode_set(x, mode) __extension__({		\
	__typeof__(x) __result;					\
	__asm__ __volatile__("csettmode %0, %1, %2"		\
	    : "=C" (__result) : "C" (x), "r" (mode));		\
	__result; })

#define	cheri_capid_get(x) __extension__({			\
	int __result;						\
	__asm__ __volatile__("cgetmte %0, %1"			\
	    : "=r" (__result) : "C" (x));			\
	__result; })

#define	cheri_capid_loc_get(x) __extension__({			\
	int __result;						\
	__asm__ __volatile__("cgettloc %0, %1"			\
	    : "=r" (__result) : "C" (x));			\
	__result; })

#define	cheri_capid_mode_get(x) __extension__({			\
	int __result;						\
	__asm__ __volatile__("cgettmode %0, %1"			\
	    : "=r" (__result) : "C" (x));			\
	__result; })

#define	cheri_capid_load(x) __extension__({			\
	int __result;						\
	__asm__ __volatile__("cgetmemmte %0, %1"		\
	    : "=r" (__result) : "C" (x));			\
	__result; })

#define	cheri_capid_store(x, id)				\
	__asm__ __volatile__("csetmemmte %0, %0, %1"		\
	    : : "C" (x), "r" (id))
#endif

#endif /* !_MACHINE_CHERIC_H_ */
