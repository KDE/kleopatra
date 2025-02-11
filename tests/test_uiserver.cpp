/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

//
// Usage: test_uiserver <socket> --verify-detached <signed data> <signature>
//

#include <config-kleopatra.h>

#include <assuan.h>
#include <gpg-error.h>

#include <Libkleo/Hex>
#include <Libkleo/KleoException>

#include "utils/wsastarter.h"

#ifndef Q_OS_WIN
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <cstdlib>
#include <iostream>
#include <map>
#include <string>
#include <vector>

using namespace Kleo;

#ifdef Q_OS_WIN
static const bool HAVE_FD_PASSING = false;
#else
static const bool HAVE_FD_PASSING = true;
#endif

static const unsigned int ASSUAN_CONNECT_FLAGS = HAVE_FD_PASSING ? 1 : 0;

static std::vector<int> inFDs, outFDs, msgFDs;
static std::vector<std::string> inFiles, outFiles, msgFiles;
static std::map<std::string, std::string> inquireData;

static void usage(const std::string &msg = std::string())
{
    std::cerr << msg << std::endl
              << "\n"
                 "Usage: test_uiserver <socket> [<io>] [<options>] [<inquire>] command [<args>]\n"
                 "where:\n"
#ifdef Q_OS_WIN
                 "      <io>: [--input[-fd] <file>] [--output[-fd] <file>] [--message[-fd] <file>]\n"
#else
                 "      <io>: [--input <file>] [--output <file>] [--message <file>]\n"
#endif
                 " <options>: *[--option name=value]\n"
                 " <inquire>: [--inquire keyword=<file>]\n";
    exit(1);
}

static gpg_error_t data(void *void_ctx, const void *buffer, size_t len)
{
    (void)void_ctx;
    (void)buffer;
    (void)len;
    return 0; // ### implement me
}

static gpg_error_t status(void *void_ctx, const char *line)
{
    (void)void_ctx;
    (void)line;
    return 0;
}

static gpg_error_t inquire(void *void_ctx, const char *keyword)
{
    assuan_context_t ctx = (assuan_context_t)void_ctx;
    Q_ASSERT(ctx);
    const std::map<std::string, std::string>::const_iterator it = inquireData.find(keyword);
    if (it == inquireData.end()) {
        return gpg_error(GPG_ERR_UNKNOWN_COMMAND);
    }

    if (!it->second.empty() && it->second[0] == '@') {
        return gpg_error(GPG_ERR_NOT_IMPLEMENTED);
    }

    if (const gpg_error_t err = assuan_send_data(ctx, it->second.c_str(), it->second.size())) {
        qDebug("assuan_write_data: %s", gpg_strerror(err));
        return err;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    const Kleo::WSAStarter _wsastarter;

    assuan_set_gpg_err_source(GPG_ERR_SOURCE_DEFAULT);

    if (argc < 3) {
        usage(); // need socket and command, at least
    }

    const char *socket = argv[1];

    std::vector<const char *> options;

    std::string command;
    for (int optind = 2; optind < argc; ++optind) {
        const char *const arg = argv[optind];
        if (qstrcmp(arg, "--input") == 0) {
            const std::string file = argv[++optind];
            inFiles.push_back(file);
        } else if (qstrcmp(arg, "--output") == 0) {
            const std::string file = argv[++optind];
            outFiles.push_back(file);
        } else if (qstrcmp(arg, "--message") == 0) {
            const std::string file = argv[++optind];
            msgFiles.push_back(file);
#ifndef Q_OS_WIN
        } else if (qstrcmp(arg, "--input-fd") == 0) {
            int inFD;
            if ((inFD = open(argv[++optind], O_RDONLY)) == -1) {
                perror("--input-fd open()");
                return 1;
            }
            inFDs.push_back(inFD);
        } else if (qstrcmp(arg, "--output-fd") == 0) {
            int outFD;
            if ((outFD = open(argv[++optind], O_WRONLY | O_CREAT, 0666)) == -1) {
                perror("--output-fd open()");
                return 1;
            }
            outFDs.push_back(outFD);
        } else if (qstrcmp(arg, "--message-fd") == 0) {
            int msgFD;
            if ((msgFD = open(argv[++optind], O_RDONLY)) == -1) {
                perror("--message-fd open()");
                return 1;
            }
            msgFDs.push_back(msgFD);
#endif
        } else if (qstrcmp(arg, "--option") == 0) {
            options.push_back(argv[++optind]);
        } else if (qstrcmp(arg, "--inquire") == 0) {
            const std::string inqval = argv[++optind];
            const size_t pos = inqval.find('=');
            // ### implement indirection with "@file"...
            inquireData[inqval.substr(0, pos)] = inqval.substr(pos + 1);
        } else {
            while (optind < argc) {
                if (!command.empty()) {
                    command += ' ';
                }
                command += argv[optind++];
            }
        }
    }
    if (command.empty()) {
        usage("Command expected, but only options found");
    }

    assuan_context_t ctx = nullptr;

    if (const gpg_error_t err = assuan_new(&ctx)) {
        qDebug("%s", Exception(err, "assuan_new").what());
        return 1;
    }

    if (const gpg_error_t err = assuan_socket_connect(ctx, socket, -1, ASSUAN_CONNECT_FLAGS)) {
        qDebug("%s", Exception(err, "assuan_socket_connect").what());
        return 1;
    }

    assuan_set_log_stream(ctx, stderr);

#ifndef Q_OS_WIN
    for (std::vector<int>::const_iterator it = inFDs.begin(), end = inFDs.end(); it != end; ++it) {
        if (const gpg_error_t err = assuan_sendfd(ctx, *it)) {
            qDebug("%s", Exception(err, "assuan_sendfd( inFD )").what());
            return 1;
        }

        if (const gpg_error_t err = assuan_transact(ctx, "INPUT FD", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) {
            qDebug("%s", Exception(err, "INPUT FD").what());
            return 1;
        }
    }

    for (std::vector<int>::const_iterator it = msgFDs.begin(), end = msgFDs.end(); it != end; ++it) {
        if (const gpg_error_t err = assuan_sendfd(ctx, *it)) {
            qDebug("%s", Exception(err, "assuan_sendfd( msgFD )").what());
            return 1;
        }

        if (const gpg_error_t err = assuan_transact(ctx, "MESSAGE FD", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) {
            qDebug("%s", Exception(err, "MESSAGE FD").what());
            return 1;
        }
    }

    for (std::vector<int>::const_iterator it = outFDs.begin(), end = outFDs.end(); it != end; ++it) {
        if (const gpg_error_t err = assuan_sendfd(ctx, *it)) {
            qDebug("%s", Exception(err, "assuan_sendfd( outFD )").what());
            return 1;
        }

        if (const gpg_error_t err = assuan_transact(ctx, "OUTPUT FD", nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) {
            qDebug("%s", Exception(err, "OUTPUT FD").what());
            return 1;
        }
    }
#endif

    for (std::vector<std::string>::const_iterator it = inFiles.begin(), end = inFiles.end(); it != end; ++it) {
        char buffer[1024];
        sprintf(buffer, "INPUT FILE=%s", hexencode(*it).c_str());

        if (const gpg_error_t err = assuan_transact(ctx, buffer, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) {
            qDebug("%s", Exception(err, buffer).what());
            return 1;
        }
    }

    for (std::vector<std::string>::const_iterator it = msgFiles.begin(), end = msgFiles.end(); it != end; ++it) {
        char buffer[1024];
        sprintf(buffer, "MESSAGE FILE=%s", hexencode(*it).c_str());

        if (const gpg_error_t err = assuan_transact(ctx, buffer, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) {
            qDebug("%s", Exception(err, buffer).what());
            return 1;
        }
    }

    for (std::vector<std::string>::const_iterator it = outFiles.begin(), end = outFiles.end(); it != end; ++it) {
        char buffer[1024];
        sprintf(buffer, "OUTPUT FILE=%s", hexencode(*it).c_str());

        if (const gpg_error_t err = assuan_transact(ctx, buffer, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) {
            qDebug("%s", Exception(err, buffer).what());
            return 1;
        }
    }

    for (const char *opt : std::as_const(options)) {
        std::string line = "OPTION ";
        line += opt;
        if (const gpg_error_t err = assuan_transact(ctx, line.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) {
            qDebug("%s", Exception(err, line).what());
            return 1;
        }
    }

    if (const gpg_error_t err = assuan_transact(ctx, command.c_str(), data, ctx, inquire, ctx, status, ctx)) {
        qDebug("%s", Exception(err, command).what());
        return 1;
    }

    assuan_release(ctx);

    return 0;
}
