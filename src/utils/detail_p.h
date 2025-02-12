/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <assuan.h>

#ifdef _WIN32
#include <io.h>
#endif

namespace Kleo
{
namespace _detail
{

template<template<typename U> class Op>
struct ByName {
    using result_type = bool;

    template<typename T>
    bool operator()(const T &lhs, const T &rhs) const
    {
        return Op<int>()(qstricmp(lhs->name(), rhs->name()), 0);
    }
    template<typename T>
    bool operator()(const T &lhs, const char *rhs) const
    {
        return Op<int>()(qstricmp(lhs->name(), rhs), 0);
    }
    template<typename T>
    bool operator()(const char *lhs, const T &rhs) const
    {
        return Op<int>()(qstricmp(lhs, rhs->name()), 0);
    }
    bool operator()(const char *lhs, const char *rhs) const
    {
        return Op<int>()(qstricmp(lhs, rhs), 0);
    }
};

// inspired by GnuPG's translate_sys2libc_fd, this converts a HANDLE
// to int fd on Windows, and is a NO-OP on POSIX:
static inline int translate_sys2libc_fd(assuan_fd_t fd, bool for_write)
{
    if (fd == ASSUAN_INVALID_FD) {
        return -1;
    }
#if defined(_WIN32)
    return _open_osfhandle((intptr_t)fd, for_write);
#else
    (void)for_write;
    return fd;
#endif
}

static inline assuan_fd_t translate_libc2sys_fd(int fd)
{
    if (fd == -1) {
        return ASSUAN_INVALID_FD;
    }
#if defined(_WIN32)
    return (assuan_fd_t)_get_osfhandle(fd);
#else
    return fd;
#endif
}

// returns an integer representation of the assuan_fd_t,
// suitable for debug output
static inline qulonglong assuanFD2int(assuan_fd_t fd)
{
#ifdef _WIN32
    return reinterpret_cast<qulonglong>(fd);
#else
    return static_cast<qulonglong>(fd);
#endif
}
}
}
