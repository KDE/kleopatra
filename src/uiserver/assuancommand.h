/* -*- mode: c++; c-basic-offset:4 -*-
    uiserver/assuancommand.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2007 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <utils/types.h>

#include <gpgme++/error.h>
#include <gpgme++/global.h>

#include <gpg-error.h>

#include <KMime/Types>

#include <qwindowdefs.h> // for WId

#include <map>
#include <memory>
#include <string>
#include <vector>

class QVariant;
class QObject;
#include <QStringList>

struct assuan_context_s;

namespace Kleo
{

class Input;
class Output;

class AssuanCommandFactory;

/*!
  \brief Base class for GnuPG UI Server commands

  \note large parts of this are outdated by now!

  <h3>Implementing a new AssuanCommand</h3>

  You do not directly inherit AssuanCommand, unless you want to
  deal with implementing low-level, repetitive things like name()
  in terms of staticName(). Assuming you don't, then you inherit
  your command class from AssuanCommandMixin, passing your class
  as the template argument to AssuanCommandMixin, like this:

  \code
  class MyFooCommand : public AssuanCommandMixin<MyFooCommand> {
  \endcode
  (http://en.wikipedia.org/wiki/Curiously_recurring_template_pattern)

  You then choose a command name, and return that from the static
  method staticName(), which is by convention queried by both
  AssuanCommandMixin<> and GenericAssuanCommandFactory<>:

  \code
      static const char * staticName() { return "MYFOO"; }
  \endcode

  The string should be all-uppercase by convention, but the
  UiServer implementation doesn't enforce this.

  The next step is to implement start(), the starting point of
  command execution:

  <h3>Executing the command</h3>

  \code
      int start( const std::string & line ) {
  \endcode

  This should set everything up and check the parameters in \a
  line and any options this command understands. If there's an
  error, choose one of the gpg-error codes and create a
  gpg_error_t from it using the protected makeError() function:

  \code
          return makeError( GPG_ERR_NOT_IMPLEMENTED );
  \endcode

  But usually, you will want to create a dialog, or call some
  GpgME function from here. In case of errors from GpgME, you
  shouldn't pipe them through makeError(), but return them
  as-is. This will preserve the error source. Error created using
  makeError() will have Kleopatra as their error source, so watch
  out what you're doing :)

  In addition to options and the command line, your command might
  require <em>bulk data</em> input or output. That's what the bulk
  input and output channels are for. You can check whether the
  client handed you an input channel by checking that
  bulkInputDevice() isn't NULL, likewise for bulkOutputDevice().

  If everything is ok, you return 0. This indicates to the client
  that the command has been accepted and is now in progress.

  In this mode (start() returned 0), there are a bunch of options
  for your command to do. Some commands may require additional
  information from the client. The options passed to start() are
  designed to be persistent across commands, and rather limited in
  length (there's a strict line length limit in the assuan
  protocol with no line continuation mechanism). The same is true
  for command line arguments, which, in addition, you have to
  parse yourself. Those usually apply only to this command, and
  not to following ones.

  If you need data that might be larger than the line length
  limit, you can either expect it on the bulkInputDevice(), or, if
  you have the need for more than one such data channel, or the
  data is optional or conditional on some condition that can only
  be determined during command execution, you can \em inquire the
  missing information from the client.

  As an example, a VERIFY command would expect the signed data on
  the bulkInputDevice(). But if the input stream doesn't contain
  an embedded (opaque) signature, indicating a \em detached
  signature, it would go and inquire that data from the
  client. Here's how it works:

  \code
  const int err = inquire( "DETACHED_SIGNATURE",
                           this, SLOT(slotDetachedSignature(int,QByteArray,QByteArray)) );
  if ( err )
      done( err );
  \endcode

  This should be self-explanatory: You give a slot to call when
  the data has arrived. The slot's first argument is an error
  code. The second the data (if any), and the third is just
  repeating what you gave as inquire()'s first argument. As usual,
  you can leave argument off of the end, if you are not interested
  in them.

  You can do as many inquiries as you want, but only one at a
  time.

  You should periodically send status updates to the client. You do
  that by calling sendStatus().

  Once your command has finished executing, call done(). If it's
  with an error code, call done(err) like above. <b>Do not
  forget to call done() when done!</b>. It will close
  bulkInputDevice(), bulkOutputDevice(), and send an OK or ERR
  message back to the client.

  At that point, your command has finished executing, and a new
  one can be accepted, or the connection closed.

  Apropos connection closed. The only way for the client to cancel
  an operation is to shut down the connection. In this case, the
  canceled() function will be called. At that point, the
  connection to the client will have been broken already, and all
  you can do is pack your things and go down gracefully.

  If _you_ detect that the user has canceled (your dialog contains
  a cancel button, doesn't it?), then you should instead call
  done( GPG_ERR_CANCELED ), like for normal operation.

  <h3>Registering the command with UiServer</h3>

  To register a command, you implement a AssuanCommandFactory for
  your AssuanCommand subclass, and register it with the
  UiServer. This can be made considerably easier using
  GenericAssuanCommandFactory:

  \code
  UiServer server;
  server.registerCommandFactory( shared_ptr<AssuanCommandFactory>( new GenericAssuanCommandFactory<MyFooCommand> ) );
  // more registerCommandFactory calls...
  server.start();
  \endcode

*/
class AssuanCommand : public ExecutionContext, public std::enable_shared_from_this<AssuanCommand>
{
    // defined in assuanserverconnection.cpp!
public:
    AssuanCommand();
    ~AssuanCommand() override;

    int start();
    void canceled();

    virtual const char *name() const = 0;

    class Memento
    {
    public:
        virtual ~Memento()
        {
        }
    };

    template<typename T>
    class TypedMemento : public Memento
    {
        T m_t;

    public:
        explicit TypedMemento(const T &t)
            : m_t(t)
        {
        }

        const T &get() const
        {
            return m_t;
        }
        T &get()
        {
            return m_t;
        }
    };

    template<typename T>
    static std::shared_ptr<TypedMemento<T>> make_typed_memento(const T &t)
    {
        return std::shared_ptr<TypedMemento<T>>(new TypedMemento<T>(t));
    }

    static int makeError(int code);

    // convenience methods:
    enum Mode {
        NoMode,
        EMail,
        FileManager
    };
    Mode checkMode() const;

    enum CheckProtocolOption {
        AllowProtocolMissing = 0x01,
    };

    GpgME::Protocol checkProtocol(Mode mode, int options = 0) const;

    void applyWindowID(QWidget *w) const override
    {
        doApplyWindowID(w);
    }
    WId parentWId() const;

    void setNohup(bool on);
    bool isNohup() const;
    bool isDone() const;

    QString sessionTitle() const;
    unsigned int sessionId() const;

    bool informativeRecipients() const;
    bool informativeSenders() const;

    const std::vector<KMime::Types::Mailbox> &recipients() const;
    const std::vector<KMime::Types::Mailbox> &senders() const;

    bool hasMemento(const QByteArray &tag) const;
    std::shared_ptr<Memento> memento(const QByteArray &tag) const;
    template<typename T>
    std::shared_ptr<T> mementoAs(const QByteArray &tag) const
    {
        return std::dynamic_pointer_cast<T>(this->memento(tag));
    }
    QByteArray registerMemento(const std::shared_ptr<Memento> &mem);
    QByteArray registerMemento(const QByteArray &tag, const std::shared_ptr<Memento> &mem);
    void removeMemento(const QByteArray &tag);
    template<typename T>
    T mementoContent(const QByteArray &tag) const
    {
        if (std::shared_ptr<TypedMemento<T>> m = mementoAs<TypedMemento<T>>(tag)) {
            return m->get();
        } else {
            return T();
        }
    }

    bool hasOption(const char *opt) const;
    QVariant option(const char *opt) const;
    const std::map<std::string, QVariant> &options() const;

    const std::vector<std::shared_ptr<Input>> &inputs() const;
    const std::vector<std::shared_ptr<Input>> &messages() const;
    const std::vector<std::shared_ptr<Output>> &outputs() const;

    QStringList fileNames() const;
    unsigned int numFiles() const;

    void sendStatus(const char *keyword, const QString &text);
    void sendStatusEncoded(const char *keyword, const std::string &text);
    void sendData(const QByteArray &data, bool moreToCome = false);

    int inquire(const char *keyword, QObject *receiver, const char *slot, unsigned int maxSize = 0);

    void done(const GpgME::Error &err = GpgME::Error());
    void done(const GpgME::Error &err, const QString &details);
    void done(int err)
    {
        done(GpgME::Error(err));
    }
    void done(int err, const QString &details)
    {
        done(GpgME::Error(err), details);
    }

private:
    virtual void doCanceled() = 0;
    virtual int doStart() = 0;

private:
    void doApplyWindowID(QWidget *w) const;

private:
    const std::map<QByteArray, std::shared_ptr<Memento>> &mementos() const;

private:
    friend class ::Kleo::AssuanCommandFactory;
    class Private;
    const std::unique_ptr<Private> d;
};

class AssuanCommandFactory
{
public:
    virtual ~AssuanCommandFactory()
    {
    }

    virtual std::shared_ptr<AssuanCommand> create() const = 0;
    virtual const char *name() const = 0;

    using _Handler = gpg_error_t (*)(assuan_context_s *, char *);
    virtual _Handler _handler() const = 0;

    static gpg_error_t _handle(assuan_context_s *, char *, const char *);
};

template<typename Command>
class GenericAssuanCommandFactory : public AssuanCommandFactory
{
    AssuanCommandFactory::_Handler _handler() const override
    {
        return &GenericAssuanCommandFactory::_handle;
    }
    static gpg_error_t _handle(assuan_context_s *_ctx, char *_line)
    {
        return AssuanCommandFactory::_handle(_ctx, _line, Command::staticName());
    }
    std::shared_ptr<AssuanCommand> create() const override
    {
        return make();
    }
    const char *name() const override
    {
        return Command::staticName();
    }

public:
    static std::shared_ptr<Command> make()
    {
        return std::shared_ptr<Command>(new Command);
    }
};

template<typename Derived, typename Base = AssuanCommand>
class AssuanCommandMixin : public Base
{
protected:
    /* reimp */ const char *name() const override
    {
        return Derived::staticName();
    }
};

}
