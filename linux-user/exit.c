/*
 *  exit support for qemu
 *
 *  Copyright (c) 2018 Alex Bennée <alex.bennee@linaro.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"
#include "qemu.h"

#ifdef CONFIG_GCOV
extern void __gcov_dump(void);
#endif

void preexit_cleanup(CPUArchState *env, int code)
{
    extern int cas_count;
    qemu_log("end::CAS_COUNT: %d\n", cas_count);
    extern int ldex_count;
    extern int stex_count;
    qemu_log( "ldex_count %d, stex_count %d, ratio %f\n", ldex_count, stex_count, (double)stex_count / (double)ldex_count);
#ifdef TARGET_GPROF
        _mcleanup();
#endif
#ifdef CONFIG_GCOV
        __gcov_dump();
#endif
        gdb_exit(env, code);
}
