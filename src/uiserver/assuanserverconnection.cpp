/* -*- mode: c++; c-basic-offset:4 -*-
    uiserver/assuanserverconnection.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#ifndef QT_NO_CAST_TO_ASCII
#define QT_NO_CAST_TO_ASCII
#endif
#ifndef QT_NO_CAST_FROM_ASCII
#define QT_NO_CAST_FROM_ASCII
#endif

#include <config-kleopatra.h>
#include <version-kleopatra.h>

#include "assuancommand.h"
#include "assuanserverconnection.h"
#include "sessiondata.h"

#include <utils/detail_p.h>
#include <utils/input.h>
#include <utils/kleo_assert.h>
#include <utils/log.h>
#include <utils/output.h>

#include <Libkleo/Formatting>
#include <Libkleo/GnuPG>
#include <Libkleo/Hex>
#include <Libkleo/KeyCache>
#include <Libkleo/KleoException>
#include <Libkleo/Stl_Util>

#include <gpgme++/data.h>
#include <gpgme++/key.h>

#include <KMime/HeaderParsing>

#include "kleopatra_debug.h"
#include <KLocalizedString>
#include <KWindowSystem>

#include <QCoreApplication>
#include <QFileInfo>
#include <QPointer>
#include <QRegularExpression>
#include <QSocketNotifier>
#include <QStringList>
#include <QTimer>
#include <QVariant>
#include <QWidget>

#include <algorithm>
#include <functional>
#include <map>
#include <type_traits>

#include <cerrno>

#ifdef __GLIBCXX__
#include <ext/algorithm> // for is_sorted
#endif

#ifdef Q_OS_WIN
#include <io.h>
#include <process.h>
#else
#include <sys/types.h>
#include <unistd.h>
#endif
using namespace Kleo;

static const unsigned int INIT_SOCKET_FLAGS = 3; // says info assuan...
// static int(*USE_DEFAULT_HANDLER)(assuan_context_t,char*) = 0;
static const int FOR_READING = 0;
static const unsigned int MAX_ACTIVE_FDS = 32;

static void my_assuan_release(assuan_context_t ctx)
{
    if (ctx) {
        assuan_release(ctx);
    }
}

// std::shared_ptr for assuan_context_t w/ deleter enforced to assuan_deinit_server:
using AssuanContextBase = std::shared_ptr<std::remove_pointer<assuan_context_t>::type>;
struct AssuanContext : AssuanContextBase {
    AssuanContext()
        : AssuanContextBase()
    {
    }
    explicit AssuanContext(assuan_context_t ctx)
        : AssuanContextBase(ctx, &my_assuan_release)
    {
    }

    void reset(assuan_context_t ctx = nullptr)
    {
        AssuanContextBase::reset(ctx, &my_assuan_release);
    }
};

static inline gpg_error_t assuan_process_done_msg(assuan_context_t ctx, gpg_error_t err, const char *err_msg)
{
    return assuan_process_done(ctx, assuan_set_error(ctx, err, err_msg));
}

static inline gpg_error_t assuan_process_done_msg(assuan_context_t ctx, gpg_error_t err, const QString &err_msg)
{
    return assuan_process_done_msg(ctx, err, err_msg.toUtf8().constData());
}

static std::map<std::string, std::string> upcase_option(const char *option, std::map<std::string, std::string> options)
{
    std::string value;
    bool value_found = false;
    auto it = options.begin();
    while (it != options.end())
        if (qstricmp(it->first.c_str(), option) == 0) {
            value = it->second;
            options.erase(it++);
            value_found = true;
        } else {
            ++it;
        }
    if (value_found) {
        options[option] = value;
    }
    return options;
}

static std::map<std::string, std::string> parse_commandline(const char *line)
{
    std::map<std::string, std::string> result;
    if (line) {
        const char *begin = line;
        const char *lastEQ = nullptr;
        while (*line) {
            if (*line == ' ' || *line == '\t') {
                if (begin != line) {
                    if (begin[0] == '-' && begin[1] == '-') {
                        begin += 2; // skip initial "--"
                    }
                    if (lastEQ && lastEQ > begin) {
                        result[std::string(begin, lastEQ - begin)] = hexdecode(std::string(lastEQ + 1, line - (lastEQ + 1)));
                    } else {
                        result[std::string(begin, line - begin)] = std::string();
                    }
                }
                begin = line + 1;
            } else if (*line == '=') {
                if (line == begin)
                    throw Exception(gpg_error(GPG_ERR_ASS_SYNTAX), i18n("No option name given"));
                else {
                    lastEQ = line;
                }
            }
            ++line;
        }
        if (begin != line) {
            if (begin[0] == '-' && begin[1] == '-') {
                begin += 2; // skip initial "--"
            }
            if (lastEQ && lastEQ > begin) {
                result[std::string(begin, lastEQ - begin)] = hexdecode(std::string(lastEQ + 1, line - (lastEQ + 1)));
            } else {
                result[begin] = std::string();
            }
        }
    }

    return result;
}

static WId wid_from_string(const QString &winIdStr, bool *ok = nullptr)
{
    return static_cast<WId>(winIdStr.toULongLong(ok, 16));
}

static void apply_window_id(QWidget *widget, const QString &winIdStr)
{
    if (!widget || winIdStr.isEmpty()) {
        return;
    }
    bool ok = false;
    const WId wid = wid_from_string(winIdStr, &ok);
    if (!ok) {
        qCDebug(KLEOPATRA_LOG) << "window-id value" << wid << "doesn't look like a number";
        return;
    }
    if (QWidget *pw = QWidget::find(wid)) {
        widget->setParent(pw, widget->windowFlags());
    } else {
        widget->setAttribute(Qt::WA_NativeWindow, true);
        KWindowSystem::setMainWindow(widget->windowHandle(), wid);
    }
}

//
//
// AssuanServerConnection:
//
//

class AssuanServerConnection::Private : public QObject
{
    Q_OBJECT
    friend class ::Kleo::AssuanServerConnection;
    friend class ::Kleo::AssuanCommandFactory;
    friend class ::Kleo::AssuanCommand;
    AssuanServerConnection *const q;

public:
    Private(assuan_fd_t fd_, const std::vector<std::shared_ptr<AssuanCommandFactory>> &factories_, AssuanServerConnection *qq);
    ~Private() override;

Q_SIGNALS:
    void startKeyManager();

public Q_SLOTS:
    void slotReadActivity(intptr_t)
    {
        Q_ASSERT(ctx);
        int done = false;
        if (const int err = assuan_process_next(ctx.get(), &done) || done) {
            // if ( err == -1 || gpg_err_code(err) == GPG_ERR_EOF ) {
            topHalfDeletion();
            if (nohupedCommands.empty()) {
                bottomHalfDeletion();
            }
            //} else {
            // assuan_process_done( ctx.get(), err );
            // return;
            //}
        }
    }

    int startCommandBottomHalf();

private:
    void nohupDone(AssuanCommand *cmd)
    {
        const auto it = std::find_if(nohupedCommands.begin(), nohupedCommands.end(), [cmd](const std::shared_ptr<AssuanCommand> &other) {
            return other.get() == cmd;
        });
        Q_ASSERT(it != nohupedCommands.end());
        nohupedCommands.erase(it);
        if (nohupedCommands.empty() && closed) {
            bottomHalfDeletion();
        }
    }

    void commandDone(AssuanCommand *cmd)
    {
        if (!cmd || cmd != currentCommand.get()) {
            return;
        }
        currentCommand.reset();
    }

    void topHalfDeletion()
    {
        if (currentCommand) {
            currentCommand->canceled();
        }
        if (fd != ASSUAN_INVALID_FD) {
#if defined(Q_OS_WIN)
            CloseHandle(fd);
#else
            ::close(fd);
#endif
        }
        notifiers.clear();
        closed = true;
    }

    void bottomHalfDeletion()
    {
        if (sessionId) {
            SessionDataHandler::instance()->exitSession(sessionId);
        }
        cleanup();
        const QPointer<Private> that = this;
        Q_EMIT q->closed(q);
        if (that) { // still there
            q->deleteLater();
        }
    }

private:
    static gpg_error_t reset_handler(assuan_context_t ctx_, char *)
    {
        Q_ASSERT(assuan_get_pointer(ctx_));

        AssuanServerConnection::Private &conn = *static_cast<AssuanServerConnection::Private *>(assuan_get_pointer(ctx_));

        conn.reset();

        return 0;
    }

    static gpg_error_t option_handler(assuan_context_t ctx_, const char *key, const char *value)
    {
        Q_ASSERT(assuan_get_pointer(ctx_));

        AssuanServerConnection::Private &conn = *static_cast<AssuanServerConnection::Private *>(assuan_get_pointer(ctx_));

        if (key && key[0] == '-' && key[1] == '-') {
            key += 2; // skip "--"
        }
        conn.options[key] = QString::fromUtf8(value);

        return 0;
        // return gpg_error( GPG_ERR_UNKNOWN_OPTION );
    }

    static gpg_error_t session_handler(assuan_context_t ctx_, char *line)
    {
        Q_ASSERT(assuan_get_pointer(ctx_));
        AssuanServerConnection::Private &conn = *static_cast<AssuanServerConnection::Private *>(assuan_get_pointer(ctx_));

        const QString str = QString::fromUtf8(line);
        static const QRegularExpression rx(QRegularExpression::anchoredPattern(uR"((\d+)(?:\s+(.*))?)"));
        const QRegularExpressionMatch match = rx.match(str);
        if (!match.hasMatch()) {
            static const QString errorString = i18n("Parse error");
            return assuan_process_done_msg(ctx_, gpg_error(GPG_ERR_ASS_SYNTAX), errorString);
        }
        bool ok = false;
        if (const qulonglong id = match.captured(1).toULongLong(&ok)) {
            if (ok && id <= std::numeric_limits<unsigned int>::max()) {
                SessionDataHandler::instance()->enterSession(id);
                conn.sessionId = id;
            } else {
                static const QString errorString = i18n("Parse error: numeric session id too large");
                return assuan_process_done_msg(ctx_, gpg_error(GPG_ERR_ASS_SYNTAX), errorString);
            }
        }

        const QString cap2 = match.captured(2);
        if (!cap2.isEmpty()) {
            conn.sessionTitle = cap2;
        }
        qCDebug(KLEOPATRA_LOG) << "session_handler: "
                               << "id=" << static_cast<unsigned long>(conn.sessionId) << ", title=" << qPrintable(conn.sessionTitle);
        return assuan_process_done(ctx_, 0);
    }

    static gpg_error_t capabilities_handler(assuan_context_t ctx_, char *line)
    {
        if (!QByteArray(line).trimmed().isEmpty()) {
            static const QString errorString = i18n("CAPABILITIES does not take arguments");
            return assuan_process_done_msg(ctx_, gpg_error(GPG_ERR_ASS_PARAMETER), errorString);
        }
        static const char capabilities[] =
            "SENDER=info\n"
            "RECIPIENT=info\n"
            "SESSION\n";
        return assuan_process_done(ctx_, assuan_send_data(ctx_, capabilities, sizeof capabilities - 1));
    }

    static gpg_error_t getinfo_handler(assuan_context_t ctx_, char *line)
    {
        Q_ASSERT(assuan_get_pointer(ctx_));
        AssuanServerConnection::Private &conn = *static_cast<AssuanServerConnection::Private *>(assuan_get_pointer(ctx_));

        if (qstrcmp(line, "version") == 0) {
            static const char version[] = "Kleopatra " KLEOPATRA_VERSION_STRING;
            return assuan_process_done(ctx_, assuan_send_data(ctx_, version, sizeof version - 1));
        }

        QByteArray ba;
        if (qstrcmp(line, "pid") == 0) {
            ba = QByteArray::number(QCoreApplication::applicationPid());
        } else if (qstrcmp(line, "options") == 0) {
            ba = conn.dumpOptions();
        } else if (qstrcmp(line, "x-mementos") == 0) {
            ba = conn.dumpMementos();
        } else if (qstrcmp(line, "senders") == 0) {
            ba = conn.dumpSenders();
        } else if (qstrcmp(line, "recipients") == 0) {
            ba = conn.dumpRecipients();
        } else if (qstrcmp(line, "x-files") == 0) {
            ba = conn.dumpFiles();
        } else {
            static const QString errorString = i18n("Unknown value for WHAT");
            return assuan_process_done_msg(ctx_, gpg_error(GPG_ERR_ASS_PARAMETER), errorString);
        }
        return assuan_process_done(ctx_, assuan_send_data(ctx_, ba.constData(), ba.size()));
    }

    static gpg_error_t start_keymanager_handler(assuan_context_t ctx_, char *line)
    {
        Q_ASSERT(assuan_get_pointer(ctx_));
        AssuanServerConnection::Private &conn = *static_cast<AssuanServerConnection::Private *>(assuan_get_pointer(ctx_));

        if (line && *line) {
            static const QString errorString = i18n("START_KEYMANAGER does not take arguments");
            return assuan_process_done_msg(ctx_, gpg_error(GPG_ERR_ASS_PARAMETER), errorString);
        }

        Q_EMIT conn.q->startKeyManagerRequested();

        return assuan_process_done(ctx_, 0);
    }

    static gpg_error_t start_confdialog_handler(assuan_context_t ctx_, char *line)
    {
        Q_ASSERT(assuan_get_pointer(ctx_));
        AssuanServerConnection::Private &conn = *static_cast<AssuanServerConnection::Private *>(assuan_get_pointer(ctx_));

        if (line && *line) {
            static const QString errorString = i18n("START_CONFDIALOG does not take arguments");
            return assuan_process_done_msg(ctx_, gpg_error(GPG_ERR_ASS_PARAMETER), errorString);
        }

        Q_EMIT conn.q->startConfigDialogRequested();

        return assuan_process_done(ctx_, 0);
    }

    template<bool in>
    struct Input_or_Output : std::conditional<in, Input, Output> {
    };

    // format: TAG (FD|FD=\d+|FILE=...)
    template<bool in, typename T_memptr>
    static gpg_error_t IO_handler(assuan_context_t ctx_, char *line_, T_memptr which)
    {
        Q_ASSERT(assuan_get_pointer(ctx_));
        AssuanServerConnection::Private &conn = *static_cast<AssuanServerConnection::Private *>(assuan_get_pointer(ctx_));

        char *binOpt = strstr(line_, "--binary");

        if (binOpt && !in) {
            /* Note there is also --armor and --base64 allowed but we don't need
             * to parse those because they are default.
             * We remove it here so that it is not parsed as an Option.*/
            memset(binOpt, ' ', 8);
        }

        try {
            /*const*/ std::map<std::string, std::string> options = upcase_option("FD", upcase_option("FILE", parse_commandline(line_)));
            if (options.size() < 1 || options.size() > 2) {
                throw gpg_error(GPG_ERR_ASS_SYNTAX);
            }

            std::shared_ptr<typename Input_or_Output<in>::type> io;

            if (options.count("FD")) {
                if (options.count("FILE")) {
                    throw gpg_error(GPG_ERR_CONFLICT);
                }

                assuan_fd_t fd = ASSUAN_INVALID_FD;

                const std::string fdstr = options["FD"];

                if (fdstr.empty()) {
                    if (const gpg_error_t err = assuan_receivefd(conn.ctx.get(), &fd)) {
                        throw err;
                    }
                } else {
#if defined(Q_OS_WIN)
                    fd = (assuan_fd_t)std::stoi(fdstr);
#else
                    fd = std::stoi(fdstr);
#endif
                }

                io = Input_or_Output<in>::type::createFromPipeDevice(fd, in ? i18n("Message #%1", (conn.*which).size() + 1) : QString());

                options.erase("FD");

            } else if (options.count("FILE")) {
                if (options.count("FD")) {
                    throw gpg_error(GPG_ERR_CONFLICT);
                }

                const QString filePath = QFile::decodeName(options["FILE"].c_str());
                if (filePath.isEmpty()) {
                    throw Exception(gpg_error(GPG_ERR_ASS_SYNTAX), i18n("Empty file path"));
                }
                const QFileInfo fi(filePath);
                if (!fi.isAbsolute()) {
                    throw Exception(gpg_error(GPG_ERR_INV_ARG), i18n("Only absolute file paths are allowed"));
                }
                if (!fi.isFile()) {
                    throw Exception(gpg_error(GPG_ERR_INV_ARG), i18n("Only files are allowed in INPUT/OUTPUT FILE"));
                } else {
                    io = Input_or_Output<in>::type::createFromFile(fi.absoluteFilePath(), true);
                }

                options.erase("FILE");

            } else {
                throw gpg_error(GPG_ERR_ASS_PARAMETER);
            }

            if (options.size()) {
                throw gpg_error(GPG_ERR_UNKNOWN_OPTION);
            }

            (conn.*which).push_back(io);

            if (binOpt && !in) {
                auto out = reinterpret_cast<Output *>(io.get());
                out->setBinaryOpt(true);
                qCDebug(KLEOPATRA_LOG) << "Configured output for binary data";
            }

            qCDebug(KLEOPATRA_LOG) << "AssuanServerConnection: added" << io->label();

            return assuan_process_done(conn.ctx.get(), 0);
        } catch (const GpgME::Exception &e) {
            return assuan_process_done_msg(conn.ctx.get(), e.error().encodedError(), e.message().c_str());
        } catch (const std::exception &) {
            return assuan_process_done(conn.ctx.get(), gpg_error(GPG_ERR_ASS_SYNTAX));
        } catch (const gpg_error_t &e) {
            return assuan_process_done(conn.ctx.get(), e);
        } catch (...) {
            return assuan_process_done_msg(conn.ctx.get(), gpg_error(GPG_ERR_UNEXPECTED), "unknown exception caught");
        }
    }

    static gpg_error_t input_handler(assuan_context_t ctx, char *line)
    {
        return IO_handler<true>(ctx, line, &Private::inputs);
    }

    static gpg_error_t output_handler(assuan_context_t ctx, char *line)
    {
        return IO_handler<false>(ctx, line, &Private::outputs);
    }

    static gpg_error_t message_handler(assuan_context_t ctx, char *line)
    {
        return IO_handler<true>(ctx, line, &Private::messages);
    }

    static gpg_error_t file_handler(assuan_context_t ctx_, char *line)
    {
        Q_ASSERT(assuan_get_pointer(ctx_));
        AssuanServerConnection::Private &conn = *static_cast<AssuanServerConnection::Private *>(assuan_get_pointer(ctx_));

        try {
            const QFileInfo fi(QFile::decodeName(hexdecode(line).c_str()));
            if (!fi.isAbsolute()) {
                throw Exception(gpg_error(GPG_ERR_INV_ARG), i18n("Only absolute file paths are allowed"));
            }
            if (!fi.exists()) {
                throw gpg_error(GPG_ERR_ENOENT);
            }
            if (!fi.isReadable() || (fi.isDir() && !fi.isExecutable())) {
                throw gpg_error(GPG_ERR_EPERM);
            }

            conn.files.push_back(fi.absoluteFilePath());

            return assuan_process_done(conn.ctx.get(), 0);
        } catch (const Exception &e) {
            return assuan_process_done_msg(conn.ctx.get(), e.error().encodedError(), e.message().toUtf8().constData());
        } catch (const gpg_error_t &e) {
            return assuan_process_done(conn.ctx.get(), e);
        } catch (...) {
            return assuan_process_done_msg(conn.ctx.get(), gpg_error(GPG_ERR_UNEXPECTED), i18n("unknown exception caught").toUtf8().constData());
        }
    }

    static bool parse_informative(const char *&begin, GpgME::Protocol &protocol)
    {
        protocol = GpgME::UnknownProtocol;
        bool informative = false;
        const char *pos = begin;
        while (true) {
            while (*pos == ' ' || *pos == '\t') {
                ++pos;
            }
            if (qstrnicmp(pos, "--info", strlen("--info")) == 0) {
                informative = true;
                pos += strlen("--info");
                if (*pos == '=') {
                    ++pos;
                    break;
                }
            } else if (qstrnicmp(pos, "--protocol=", strlen("--protocol=")) == 0) {
                pos += strlen("--protocol=");
                if (qstrnicmp(pos, "OpenPGP", strlen("OpenPGP")) == 0) {
                    protocol = GpgME::OpenPGP;
                    pos += strlen("OpenPGP");
                } else if (qstrnicmp(pos, "CMS", strlen("CMS")) == 0) {
                    protocol = GpgME::CMS;
                    pos += strlen("CMS");
                } else {
                    ;
                }
            } else if (qstrncmp(pos, "-- ", strlen("-- ")) == 0) {
                pos += 3;
                while (*pos == ' ' || *pos == '\t') {
                    ++pos;
                }
                break;
            } else {
                break;
            }
        }
        begin = pos;
        return informative;
    }

    template<typename T_memptr, typename T_memptr2>
    static gpg_error_t recipient_sender_handler(T_memptr mp, T_memptr2 info, assuan_context_t ctx, char *line, bool sender = false)
    {
        Q_ASSERT(assuan_get_pointer(ctx));
        AssuanServerConnection::Private &conn = *static_cast<AssuanServerConnection::Private *>(assuan_get_pointer(ctx));

        if (!line || !*line) {
            return assuan_process_done(conn.ctx.get(), gpg_error(GPG_ERR_INV_ARG));
        }
        const char *begin = line;
        const char *const end = begin + qstrlen(line);
        GpgME::Protocol proto = GpgME::UnknownProtocol;
        const bool informative = parse_informative(begin, proto);
        if (!(conn.*mp).empty() && informative != (conn.*info))
            return assuan_process_done_msg(conn.ctx.get(),
                                           gpg_error(GPG_ERR_CONFLICT),
                                           i18n("Cannot mix --info with non-info SENDER or RECIPIENT").toUtf8().constData());
        KMime::Types::Mailbox mb;
        if (!KMime::HeaderParsing::parseMailbox(begin, end, mb))
            return assuan_process_done_msg(conn.ctx.get(), gpg_error(GPG_ERR_INV_ARG), i18n("Argument is not a valid RFC-2822 mailbox").toUtf8().constData());
        if (begin != end)
            return assuan_process_done_msg(conn.ctx.get(),
                                           gpg_error(GPG_ERR_INV_ARG),
                                           i18n("Garbage after valid RFC-2822 mailbox detected").toUtf8().constData());
        (conn.*info) = informative;
        (conn.*mp).push_back(mb);

        const QString email = mb.addrSpec().asString();
        (void)assuan_write_line(conn.ctx.get(), qPrintable(QString::asprintf("# ok, parsed as \"%s\"", qPrintable(email))));
        if (sender && !informative) {
            return AssuanCommandFactory::_handle(conn.ctx.get(), line, "PREP_SIGN");
        } else {
            return assuan_process_done(ctx, 0);
        }
    }

    static gpg_error_t recipient_handler(assuan_context_t ctx, char *line)
    {
        return recipient_sender_handler(&Private::recipients, &Private::informativeRecipients, ctx, line);
    }

    static gpg_error_t sender_handler(assuan_context_t ctx, char *line)
    {
        return recipient_sender_handler(&Private::senders, &Private::informativeSenders, ctx, line, true);
    }

    QByteArray dumpOptions() const
    {
        QByteArray result;
        for (auto it = options.begin(), end = options.end(); it != end; ++it) {
            result += it->first.c_str() + it->second.toString().toUtf8() + '\n';
        }
        return result;
    }

    static QByteArray dumpStringList(const QStringList &sl)
    {
        return sl.join(QLatin1Char('\n')).toUtf8();
    }

    template<typename T_container>
    static QByteArray dumpStringList(const T_container &c)
    {
        QStringList sl;
        std::copy(c.begin(), c.end(), std::back_inserter(sl));
        return dumpStringList(sl);
    }

    template<typename T_container>
    static QByteArray dumpMailboxes(const T_container &c)
    {
        QStringList sl;
        std::transform(c.begin(), c.end(), std::back_inserter(sl), [](typename T_container::const_reference val) {
            return val.prettyAddress();
        });
        return dumpStringList(sl);
    }

    QByteArray dumpSenders() const
    {
        return dumpMailboxes(senders);
    }

    QByteArray dumpRecipients() const
    {
        return dumpMailboxes(recipients);
    }

    QByteArray dumpMementos() const
    {
        QByteArray result;
        for (auto it = mementos.begin(), end = mementos.end(); it != end; ++it) {
            char buf[2 + 2 * sizeof(void *) + 2];
            sprintf(buf, "0x%p\n", (void *)it->second.get());
            buf[sizeof(buf) - 1] = '\0';
            result += it->first + QByteArray::fromRawData(buf, sizeof buf);
        }
        return result;
    }

    QByteArray dumpFiles() const
    {
        QStringList rv;
        rv.reserve(files.size());
        std::copy(files.cbegin(), files.cend(), std::back_inserter(rv));
        return dumpStringList(rv);
    }

    void cleanup();
    void reset()
    {
        options.clear();
        senders.clear();
        informativeSenders = false;
        recipients.clear();
        informativeRecipients = false;
        sessionTitle.clear();
        sessionId = 0;
        mementos.clear();
        files.clear();
        std::for_each(inputs.begin(), inputs.end(), std::mem_fn(&Input::finalize));
        inputs.clear();
        std::for_each(outputs.begin(), outputs.end(), std::mem_fn(&Output::finalize));
        outputs.clear();
        std::for_each(messages.begin(), messages.end(), std::mem_fn(&Input::finalize));
        messages.clear();
        bias = GpgME::UnknownProtocol;
    }

    assuan_fd_t fd;
    AssuanContext ctx;
    bool closed : 1;
    bool cryptoCommandsEnabled : 1;
    bool commandWaitingForCryptoCommandsEnabled : 1;
    bool currentCommandIsNohup : 1;
    bool informativeSenders; // address taken, so no : 1
    bool informativeRecipients; // address taken, so no : 1
    GpgME::Protocol bias;
    QString sessionTitle;
    unsigned int sessionId;
    std::vector<std::shared_ptr<QSocketNotifier>> notifiers;
    std::vector<std::shared_ptr<AssuanCommandFactory>> factories; // sorted: _detail::ByName<std::less>
    std::shared_ptr<AssuanCommand> currentCommand;
    std::vector<std::shared_ptr<AssuanCommand>> nohupedCommands;
    std::map<std::string, QVariant> options;
    std::vector<KMime::Types::Mailbox> senders, recipients;
    std::vector<std::shared_ptr<Input>> inputs, messages;
    std::vector<std::shared_ptr<Output>> outputs;
    std::vector<QString> files;
    std::map<QByteArray, std::shared_ptr<AssuanCommand::Memento>> mementos;
};

void AssuanServerConnection::Private::cleanup()
{
    Q_ASSERT(nohupedCommands.empty());
    reset();
    currentCommand.reset();
    currentCommandIsNohup = false;
    commandWaitingForCryptoCommandsEnabled = false;
    notifiers.clear();
    ctx.reset();
    fd = ASSUAN_INVALID_FD;
}

AssuanServerConnection::Private::Private(assuan_fd_t fd_, const std::vector<std::shared_ptr<AssuanCommandFactory>> &factories_, AssuanServerConnection *qq)
    : QObject()
    , q(qq)
    , fd(fd_)
    , closed(false)
    , cryptoCommandsEnabled(false)
    , commandWaitingForCryptoCommandsEnabled(false)
    , currentCommandIsNohup(false)
    , informativeSenders(false)
    , informativeRecipients(false)
    , bias(GpgME::UnknownProtocol)
    , sessionId(0)
    , factories(factories_)
{
#ifdef __GLIBCXX__
    Q_ASSERT(__gnu_cxx::is_sorted(factories_.begin(), factories_.end(), _detail::ByName<std::less>()));
#endif

    if (fd == ASSUAN_INVALID_FD) {
        throw Exception(gpg_error(GPG_ERR_INV_ARG), "pre-assuan_init_socket_server_ext");
    }

    {
        assuan_context_t naked_ctx = nullptr;
        if (const gpg_error_t err = assuan_new(&naked_ctx)) {
            throw Exception(err, "assuan_new");
        }
        ctx.reset(naked_ctx);
    }
    if (const gpg_error_t err = assuan_init_socket_server(ctx.get(), fd, INIT_SOCKET_FLAGS))
        throw Exception(err, "assuan_init_socket_server_ext");

    // for callbacks, associate the context with this connection:
    assuan_set_pointer(ctx.get(), this);

    FILE *const logFile = Log::instance()->logFile();
    assuan_set_log_stream(ctx.get(), logFile ? logFile : stderr);

    // register FDs with the event loop:
    assuan_fd_t fds[MAX_ACTIVE_FDS];
    const int numFDs = assuan_get_active_fds(ctx.get(), FOR_READING, fds, MAX_ACTIVE_FDS);
    Q_ASSERT(numFDs != -1); // == 1

    if (!numFDs || fds[0] != fd) {
        const std::shared_ptr<QSocketNotifier> sn(new QSocketNotifier((intptr_t)fd, QSocketNotifier::Read), std::mem_fn(&QObject::deleteLater));
        connect(sn.get(), &QSocketNotifier::activated, this, &Private::slotReadActivity);
        notifiers.push_back(sn);
    }

    notifiers.reserve(notifiers.size() + numFDs);
    for (int i = 0; i < numFDs; ++i) {
        const std::shared_ptr<QSocketNotifier> sn(new QSocketNotifier((intptr_t)fds[i], QSocketNotifier::Read), std::mem_fn(&QObject::deleteLater));
        connect(sn.get(), &QSocketNotifier::activated, this, &Private::slotReadActivity);
        notifiers.push_back(sn);
    }

    // register our INPUT/OUTPUT/MESSGAE/FILE handlers:
    if (const gpg_error_t err = assuan_register_command(ctx.get(), "INPUT", input_handler, ""))
        throw Exception(err, "register \"INPUT\" handler");
    if (const gpg_error_t err = assuan_register_command(ctx.get(), "MESSAGE", message_handler, ""))
        throw Exception(err, "register \"MESSAGE\" handler");
    if (const gpg_error_t err = assuan_register_command(ctx.get(), "OUTPUT", output_handler, ""))
        throw Exception(err, "register \"OUTPUT\" handler");
    if (const gpg_error_t err = assuan_register_command(ctx.get(), "FILE", file_handler, ""))
        throw Exception(err, "register \"FILE\" handler");

    // register user-defined commands:
    for (std::shared_ptr<AssuanCommandFactory> fac : std::as_const(factories))
        if (const gpg_error_t err = assuan_register_command(ctx.get(), fac->name(), fac->_handler(), ""))
            throw Exception(err, std::string("register \"") + fac->name() + "\" handler");

    if (const gpg_error_t err = assuan_register_command(ctx.get(), "GETINFO", getinfo_handler, ""))
        throw Exception(err, "register \"GETINFO\" handler");
    if (const gpg_error_t err = assuan_register_command(ctx.get(), "START_KEYMANAGER", start_keymanager_handler, ""))
        throw Exception(err, "register \"START_KEYMANAGER\" handler");
    if (const gpg_error_t err = assuan_register_command(ctx.get(), "START_CONFDIALOG", start_confdialog_handler, ""))
        throw Exception(err, "register \"START_CONFDIALOG\" handler");
    if (const gpg_error_t err = assuan_register_command(ctx.get(), "RECIPIENT", recipient_handler, ""))
        throw Exception(err, "register \"RECIPIENT\" handler");
    if (const gpg_error_t err = assuan_register_command(ctx.get(), "SENDER", sender_handler, ""))
        throw Exception(err, "register \"SENDER\" handler");
    if (const gpg_error_t err = assuan_register_command(ctx.get(), "SESSION", session_handler, ""))
        throw Exception(err, "register \"SESSION\" handler");
    if (const gpg_error_t err = assuan_register_command(ctx.get(), "CAPABILITIES", capabilities_handler, ""))
        throw Exception(err, "register \"CAPABILITIES\" handler");

    assuan_set_hello_line(ctx.get(), "GPG UI server (Kleopatra/" KLEOPATRA_VERSION_STRING ") ready to serve");
    // assuan_set_hello_line( ctx.get(), GPG UI server (qApp->applicationName() + " v" + kapp->applicationVersion() + "ready to serve" )

    // some notifiers we're interested in:
    if (const gpg_error_t err = assuan_register_reset_notify(ctx.get(), reset_handler)) {
        throw Exception(err, "register reset notify");
    }
    if (const gpg_error_t err = assuan_register_option_handler(ctx.get(), option_handler)) {
        throw Exception(err, "register option handler");
    }

    // and last, we need to call assuan_accept, which doesn't block
    // (d/t INIT_SOCKET_FLAGS), but performs vital connection
    // establishing handling:
    if (const gpg_error_t err = assuan_accept(ctx.get())) {
        throw Exception(err, "assuan_accept");
    }
}

AssuanServerConnection::Private::~Private()
{
    cleanup();
}

AssuanServerConnection::AssuanServerConnection(assuan_fd_t fd, const std::vector<std::shared_ptr<AssuanCommandFactory>> &factories, QObject *p)
    : QObject(p)
    , d(new Private(fd, factories, this))
{
}

AssuanServerConnection::~AssuanServerConnection()
{
}

void AssuanServerConnection::enableCryptoCommands(bool on)
{
    if (on == d->cryptoCommandsEnabled) {
        return;
    }
    d->cryptoCommandsEnabled = on;
    if (d->commandWaitingForCryptoCommandsEnabled) {
        QTimer::singleShot(0, d.get(), &Private::startCommandBottomHalf);
    }
}

//
//
// AssuanCommand:
//
//

namespace Kleo
{

class InquiryHandler : public QObject
{
    Q_OBJECT
public:
    explicit InquiryHandler(const char *keyword_, QObject *p = nullptr)
        : QObject(p)
        , keyword(keyword_)
    {
    }

    static gpg_error_t handler(void *cb_data, gpg_error_t rc, unsigned char *buffer, size_t buflen)
    {
        Q_ASSERT(cb_data);
        auto this_ = static_cast<InquiryHandler *>(cb_data);
        Q_EMIT this_->signal(rc, QByteArray::fromRawData(reinterpret_cast<const char *>(buffer), buflen), this_->keyword);
        std::free(buffer);
        delete this_;
        return 0;
    }

private:
    const char *keyword;

Q_SIGNALS:
    void signal(int rc, const QByteArray &data, const QByteArray &keyword);
};

} // namespace Kleo

class AssuanCommand::Private
{
public:
    Private()
        : informativeRecipients(false)
        , informativeSenders(false)
        , bias(GpgME::UnknownProtocol)
        , done(false)
        , nohup(false)
    {
    }

    std::map<std::string, QVariant> options;
    std::vector<std::shared_ptr<Input>> inputs, messages;
    std::vector<std::shared_ptr<Output>> outputs;
    std::vector<QString> files;
    std::vector<KMime::Types::Mailbox> recipients, senders;
    bool informativeRecipients, informativeSenders;
    GpgME::Protocol bias;
    QString sessionTitle;
    unsigned int sessionId;
    QByteArray utf8ErrorKeepAlive;
    AssuanContext ctx;
    bool done;
    bool nohup;
};

AssuanCommand::AssuanCommand()
    : d(new Private)
{
}

AssuanCommand::~AssuanCommand()
{
}

int AssuanCommand::start()
{
    try {
        if (const int err = doStart())
            if (!d->done) {
                done(err);
            }
        return 0;
    } catch (const Exception &e) {
        if (!d->done) {
            done(e.error_code(), e.message());
        }
        return 0;
    } catch (const GpgME::Exception &e) {
        if (!d->done) {
            done(e.error(), QString::fromLocal8Bit(e.message().c_str()));
        }
        return 0;
    } catch (const std::exception &e) {
        if (!d->done) {
            done(makeError(GPG_ERR_INTERNAL), i18n("Caught unexpected exception: %1", QString::fromLocal8Bit(e.what())));
        }
        return 0;
    } catch (...) {
        if (!d->done) {
            done(makeError(GPG_ERR_INTERNAL), i18n("Caught unknown exception - please report this error to the developers."));
        }
        return 0;
    }
}

void AssuanCommand::canceled()
{
    d->done = true;
    doCanceled();
}

// static
int AssuanCommand::makeError(int code)
{
    return makeGnuPGError(code);
}

bool AssuanCommand::hasOption(const char *opt) const
{
    return d->options.count(opt);
}

QVariant AssuanCommand::option(const char *opt) const
{
    const auto it = d->options.find(opt);
    if (it == d->options.end()) {
        return QVariant();
    } else {
        return it->second;
    }
}

const std::map<std::string, QVariant> &AssuanCommand::options() const
{
    return d->options;
}

namespace
{
template<typename U, typename V>
std::vector<U> keys(const std::map<U, V> &map)
{
    std::vector<U> result;
    result.resize(map.size());
    for (typename std::map<U, V>::const_iterator it = map.begin(), end = map.end(); it != end; ++it) {
        result.push_back(it->first);
    }
    return result;
}
}

const std::map<QByteArray, std::shared_ptr<AssuanCommand::Memento>> &AssuanCommand::mementos() const
{
    // oh, hack :(
    Q_ASSERT(assuan_get_pointer(d->ctx.get()));
    const AssuanServerConnection::Private &conn = *static_cast<AssuanServerConnection::Private *>(assuan_get_pointer(d->ctx.get()));
    return conn.mementos;
}

bool AssuanCommand::hasMemento(const QByteArray &tag) const
{
    if (const unsigned int id = sessionId()) {
        return SessionDataHandler::instance()->sessionData(id)->mementos.count(tag) || mementos().count(tag);
    } else {
        return mementos().count(tag);
    }
}

std::shared_ptr<AssuanCommand::Memento> AssuanCommand::memento(const QByteArray &tag) const
{
    if (const unsigned int id = sessionId()) {
        const std::shared_ptr<SessionDataHandler> sdh = SessionDataHandler::instance();
        const std::shared_ptr<SessionData> sd = sdh->sessionData(id);
        const auto it = sd->mementos.find(tag);
        if (it != sd->mementos.end()) {
            return it->second;
        }
    }
    const auto it = mementos().find(tag);
    if (it == mementos().end()) {
        return std::shared_ptr<Memento>();
    } else {
        return it->second;
    }
}

QByteArray AssuanCommand::registerMemento(const std::shared_ptr<Memento> &mem)
{
    const QByteArray tag = QByteArray::number(reinterpret_cast<qulonglong>(mem.get()), 36);
    return registerMemento(tag, mem);
}

QByteArray AssuanCommand::registerMemento(const QByteArray &tag, const std::shared_ptr<Memento> &mem)
{
    // oh, hack :(
    Q_ASSERT(assuan_get_pointer(d->ctx.get()));
    AssuanServerConnection::Private &conn = *static_cast<AssuanServerConnection::Private *>(assuan_get_pointer(d->ctx.get()));

    if (const unsigned int id = sessionId()) {
        SessionDataHandler::instance()->sessionData(id)->mementos[tag] = mem;
    } else {
        conn.mementos[tag] = mem;
    }
    return tag;
}

void AssuanCommand::removeMemento(const QByteArray &tag)
{
    // oh, hack :(
    Q_ASSERT(assuan_get_pointer(d->ctx.get()));
    AssuanServerConnection::Private &conn = *static_cast<AssuanServerConnection::Private *>(assuan_get_pointer(d->ctx.get()));

    conn.mementos.erase(tag);
    if (const unsigned int id = sessionId()) {
        SessionDataHandler::instance()->sessionData(id)->mementos.erase(tag);
    }
}

const std::vector<std::shared_ptr<Input>> &AssuanCommand::inputs() const
{
    return d->inputs;
}

const std::vector<std::shared_ptr<Input>> &AssuanCommand::messages() const
{
    return d->messages;
}

const std::vector<std::shared_ptr<Output>> &AssuanCommand::outputs() const
{
    return d->outputs;
}

QStringList AssuanCommand::fileNames() const
{
    QStringList rv;
    rv.reserve(d->files.size());
    std::copy(d->files.cbegin(), d->files.cend(), std::back_inserter(rv));
    return rv;
}

unsigned int AssuanCommand::numFiles() const
{
    return d->files.size();
}

void AssuanCommand::sendStatus(const char *keyword, const QString &text)
{
    sendStatusEncoded(keyword, text.toUtf8().constData());
}

void AssuanCommand::sendStatusEncoded(const char *keyword, const std::string &text)
{
    if (d->nohup) {
        return;
    }
    if (const int err = assuan_write_status(d->ctx.get(), keyword, text.c_str())) {
        throw Exception(err, i18n("Cannot send \"%1\" status", QString::fromLatin1(keyword)));
    }
}

void AssuanCommand::sendData(const QByteArray &data, bool moreToCome)
{
    if (d->nohup) {
        return;
    }
    if (const gpg_error_t err = assuan_send_data(d->ctx.get(), data.constData(), data.size())) {
        throw Exception(err, i18n("Cannot send data"));
    }
    if (!moreToCome)
        if (const gpg_error_t err = assuan_send_data(d->ctx.get(), nullptr, 0)) { // flush
            throw Exception(err, i18n("Cannot flush data"));
        }
}

int AssuanCommand::inquire(const char *keyword, QObject *receiver, const char *slot, unsigned int maxSize)
{
    Q_ASSERT(keyword);
    Q_ASSERT(receiver);
    Q_ASSERT(slot);

    if (d->nohup) {
        return makeError(GPG_ERR_INV_OP);
    }

    std::unique_ptr<InquiryHandler> ih(new InquiryHandler(keyword, receiver));
    receiver->connect(ih.get(), SIGNAL(signal(int, QByteArray, QByteArray)), slot);
    if (const gpg_error_t err = assuan_inquire_ext(d->ctx.get(), keyword, maxSize, InquiryHandler::handler, ih.get())) {
        return err;
    }
    ih.release();
    return 0;
}

void AssuanCommand::done(const GpgME::Error &err, const QString &details)
{
    if (d->ctx && !d->done && !details.isEmpty()) {
        qCDebug(KLEOPATRA_LOG) << "Error: " << details;
        d->utf8ErrorKeepAlive = details.toUtf8();
        if (!d->nohup) {
            assuan_set_error(d->ctx.get(), err.encodedError(), d->utf8ErrorKeepAlive.constData());
        }
    }
    done(err);
}

void AssuanCommand::done(const GpgME::Error &err)
{
    if (!d->ctx) {
        qCDebug(KLEOPATRA_LOG) << Formatting::errorAsString(err) << ": called with NULL ctx.";
        return;
    }
    if (d->done) {
        qCDebug(KLEOPATRA_LOG) << Formatting::errorAsString(err) << ": called twice!";
        return;
    }

    d->done = true;

    std::for_each(d->messages.begin(), d->messages.end(), std::mem_fn(&Input::finalize));
    std::for_each(d->inputs.begin(), d->inputs.end(), std::mem_fn(&Input::finalize));
    std::for_each(d->outputs.begin(), d->outputs.end(), std::mem_fn(&Output::finalize));
    d->messages.clear();
    d->inputs.clear();
    d->outputs.clear();
    d->files.clear();

    // oh, hack :(
    Q_ASSERT(assuan_get_pointer(d->ctx.get()));
    AssuanServerConnection::Private &conn = *static_cast<AssuanServerConnection::Private *>(assuan_get_pointer(d->ctx.get()));

    if (d->nohup) {
        conn.nohupDone(this);
        return;
    }

    const gpg_error_t rc = assuan_process_done(d->ctx.get(), err.encodedError());
    if (gpg_err_code(rc) != GPG_ERR_NO_ERROR)
        qFatal("AssuanCommand::done: assuan_process_done returned error %d (%s)", static_cast<int>(rc), gpg_strerror(rc));

    d->utf8ErrorKeepAlive.clear();

    conn.commandDone(this);
}

void AssuanCommand::setNohup(bool nohup)
{
    d->nohup = nohup;
}

bool AssuanCommand::isNohup() const
{
    return d->nohup;
}

bool AssuanCommand::isDone() const
{
    return d->done;
}

QString AssuanCommand::sessionTitle() const
{
    return d->sessionTitle;
}

unsigned int AssuanCommand::sessionId() const
{
    return d->sessionId;
}

bool AssuanCommand::informativeSenders() const
{
    return d->informativeSenders;
}

bool AssuanCommand::informativeRecipients() const
{
    return d->informativeRecipients;
}

const std::vector<KMime::Types::Mailbox> &AssuanCommand::recipients() const
{
    return d->recipients;
}

const std::vector<KMime::Types::Mailbox> &AssuanCommand::senders() const
{
    return d->senders;
}

gpg_error_t AssuanCommandFactory::_handle(assuan_context_t ctx, char *line, const char *commandName)
{
    Q_ASSERT(assuan_get_pointer(ctx));
    AssuanServerConnection::Private &conn = *static_cast<AssuanServerConnection::Private *>(assuan_get_pointer(ctx));

    try {
        const auto it = std::lower_bound(conn.factories.begin(), conn.factories.end(), commandName, _detail::ByName<std::less>());
        kleo_assert(it != conn.factories.end());
        kleo_assert(*it);
        kleo_assert(qstricmp((*it)->name(), commandName) == 0);

        const std::shared_ptr<AssuanCommand> cmd = (*it)->create();
        kleo_assert(cmd);

        cmd->d->ctx = conn.ctx;
        cmd->d->options = conn.options;
        cmd->d->inputs.swap(conn.inputs);
        kleo_assert(conn.inputs.empty());
        cmd->d->messages.swap(conn.messages);
        kleo_assert(conn.messages.empty());
        cmd->d->outputs.swap(conn.outputs);
        kleo_assert(conn.outputs.empty());
        cmd->d->files.swap(conn.files);
        kleo_assert(conn.files.empty());
        cmd->d->senders.swap(conn.senders);
        kleo_assert(conn.senders.empty());
        cmd->d->recipients.swap(conn.recipients);
        kleo_assert(conn.recipients.empty());
        cmd->d->informativeRecipients = conn.informativeRecipients;
        cmd->d->informativeSenders = conn.informativeSenders;
        cmd->d->bias = conn.bias;
        cmd->d->sessionTitle = conn.sessionTitle;
        cmd->d->sessionId = conn.sessionId;

        const std::map<std::string, std::string> cmdline_options = parse_commandline(line);
        for (auto it = cmdline_options.begin(), end = cmdline_options.end(); it != end; ++it) {
            cmd->d->options[it->first] = QString::fromUtf8(it->second.c_str());
        }

        bool nohup = false;
        if (cmd->d->options.count("nohup")) {
            if (!cmd->d->options["nohup"].toString().isEmpty()) {
                return assuan_process_done_msg(conn.ctx.get(), gpg_error(GPG_ERR_ASS_PARAMETER), "--nohup takes no argument");
            }
            nohup = true;
            cmd->d->options.erase("nohup");
        }

        conn.currentCommand = cmd;
        conn.currentCommandIsNohup = nohup;

        QTimer::singleShot(0, &conn, &AssuanServerConnection::Private::startCommandBottomHalf);

        return 0;

    } catch (const Exception &e) {
        return assuan_process_done_msg(conn.ctx.get(), e.error_code(), e.message());
    } catch (const std::exception &e) {
        return assuan_process_done_msg(conn.ctx.get(), gpg_error(GPG_ERR_UNEXPECTED), e.what());
    } catch (...) {
        return assuan_process_done_msg(conn.ctx.get(), gpg_error(GPG_ERR_UNEXPECTED), i18n("Caught unknown exception"));
    }
}

int AssuanServerConnection::Private::startCommandBottomHalf()
{
    commandWaitingForCryptoCommandsEnabled = currentCommand && !cryptoCommandsEnabled;

    if (!cryptoCommandsEnabled) {
        return 0;
    }

    const std::shared_ptr<AssuanCommand> cmd = currentCommand;
    if (!cmd) {
        return 0;
    }

    currentCommand.reset();

    const bool nohup = currentCommandIsNohup;
    currentCommandIsNohup = false;

    try {
        if (const int err = cmd->start()) {
            if (cmd->isDone()) {
                return err;
            } else {
                return assuan_process_done(ctx.get(), err);
            }
        }

        if (cmd->isDone()) {
            return 0;
        }

        if (nohup) {
            cmd->setNohup(true);
            nohupedCommands.push_back(cmd);
            return assuan_process_done_msg(ctx.get(), 0, "Command put in the background to continue executing after connection end.");
        } else {
            currentCommand = cmd;
            return 0;
        }

    } catch (const Exception &e) {
        return assuan_process_done_msg(ctx.get(), e.error_code(), e.message());
    } catch (const std::exception &e) {
        return assuan_process_done_msg(ctx.get(), gpg_error(GPG_ERR_UNEXPECTED), e.what());
    } catch (...) {
        return assuan_process_done_msg(ctx.get(), gpg_error(GPG_ERR_UNEXPECTED), i18n("Caught unknown exception"));
    }
}

//
//
// AssuanCommand convenience methods
//
//

/*!
  Checks the \c --mode parameter.

  \returns The parameter as an AssuanCommand::Mode enum value.

  If no \c --mode was given, or it's value wasn't recognized, throws
  an Kleo::Exception.
*/
AssuanCommand::Mode AssuanCommand::checkMode() const
{
    if (!hasOption("mode")) {
        throw Exception(makeError(GPG_ERR_MISSING_VALUE), i18n("Required --mode option missing"));
    }

    const QString modeString = option("mode").toString().toLower();
    if (modeString == QLatin1StringView("filemanager")) {
        return FileManager;
    }
    if (modeString == QLatin1StringView("email")) {
        return EMail;
    }
    throw Exception(makeError(GPG_ERR_INV_ARG), i18n("invalid mode: \"%1\"", modeString));
}

/*!
  Checks the \c --protocol parameter.

  \returns The parameter as a GpgME::Protocol enum value.

  If \c --protocol was given, but has an invalid value, throws an
  Kleo::Exception.

  If no \c --protocol was given, checks the connection bias, if
  available, otherwise, in FileManager mode, returns
  GpgME::UnknownProtocol, but if \a mode == \c EMail, throws an
  Kleo::Exception instead.
*/
GpgME::Protocol AssuanCommand::checkProtocol(Mode mode, int options) const
{
    if (!hasOption("protocol"))
        if (d->bias != GpgME::UnknownProtocol) {
            return d->bias;
        } else if (mode == AssuanCommand::EMail && (options & AllowProtocolMissing) == 0) {
            throw Exception(makeError(GPG_ERR_MISSING_VALUE), i18n("Required --protocol option missing"));
        } else {
            return GpgME::UnknownProtocol;
        }
    else if (mode == AssuanCommand::FileManager) {
        throw Exception(makeError(GPG_ERR_INV_FLAG), i18n("--protocol is not allowed here"));
    }

    const QString protocolString = option("protocol").toString().toLower();
    if (protocolString == QLatin1StringView("openpgp")) {
        return GpgME::OpenPGP;
    }
    if (protocolString == QLatin1StringView("cms")) {
        return GpgME::CMS;
    }
    throw Exception(makeError(GPG_ERR_INV_ARG), i18n("invalid protocol \"%1\"", protocolString));
}

void AssuanCommand::doApplyWindowID(QWidget *widget) const
{
    if (!widget || !hasOption("window-id")) {
        return;
    }
    apply_window_id(widget, option("window-id").toString());
}

WId AssuanCommand::parentWId() const
{
    return wid_from_string(option("window-id").toString());
}

#include "assuanserverconnection.moc"

#include "moc_assuanserverconnection.cpp"
