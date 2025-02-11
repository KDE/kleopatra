/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <Libkleo/KleoException>

#include <assert.h>

#define S(x) #x
#define S_(x) S(x)
#define S_LINE S_(__LINE__)

#define kleo_assert_fail_impl(cond, file, line) throw Kleo::Exception(gpg_error(GPG_ERR_INTERNAL), "assertion \"" #cond "\" failed at " file ":" line)
#define kleo_assert_fail_impl_func(cond, file, line, func)                                                                                                     \
    throw Kleo::Exception(gpg_error(GPG_ERR_INTERNAL), std::string("assertion \"" #cond "\" failed in ") + func + " (" file ":" line ")")

#define kleo_assert_impl(cond, file, line)                                                                                                                     \
    if (cond) {                                                                                                                                                \
    } else                                                                                                                                                     \
        kleo_assert_fail_impl(cond, file, line)
#define kleo_assert_impl_func(cond, file, line, func)                                                                                                          \
    if (cond) {                                                                                                                                                \
    } else                                                                                                                                                     \
        kleo_assert_fail_impl_func(cond, file, line, func)

// from glibc's assert.h:
/* Version 2.4 and later of GCC define a magical variable `__PRETTY_FUNCTION__'
   which contains the name of the function currently being defined.
   This is broken in G++ before version 2.6.
   C9x has a similar variable called __func__, but prefer the GCC one since
   it demangles C++ function names.  */

#if defined(__GNUC_PREREQ)
#define KLEO_GNUC_PREREQ __GNUC_PREREQ
#elif defined(__MINGW_GNUC_PREREQ)
#define KLEO_GNUC_PREREQ __MINGW_GNUC_PREREQ
#else
#define KLEO_GNUC_PREREQ(maj, min) 0
#endif

#if KLEO_GNUC_PREREQ(2, 6)
#define kleo_assert(cond) kleo_assert_impl_func(cond, __FILE__, S_LINE, __PRETTY_FUNCTION__)
#define kleo_assert_fail(cond) kleo_assert_fail_impl_func(cond, __FILE__, S_LINE, __PRETTY_FUNCTION__)
#define notImplemented() throw Exception(gpg_error(GPG_ERR_NOT_IMPLEMENTED), __PRETTY_FUNCTION__)
#elif defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L
#define kleo_assert(cond) kleo_assert_impl_func(cond, __FILE__, S_LINE, __func__)
#define kleo_assert_fail(cond) kleo_assert_fail_impl_func(cond, __FILE__, S_LINE, __func__)
#define notImplemented() throw Exception(gpg_error(GPG_ERR_NOT_IMPLEMENTED), __func__)
#endif

#undef KLEO_GNUC_PREREQ

#ifndef kleo_assert
#define kleo_assert(cond) kleo_assert_impl(cond, __FILE__, S_LINE)
#endif

#ifndef kleo_assert_fail
#define kleo_assert_fail(cond) kleo_assert_fail_impl(cond, __FILE__, S_LINE)
#endif

#ifndef notImplemented
#define notImplemented() kleo_assert(!"Sorry, not yet implemented")
#endif
