/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QObject>
#include <QString>
#include <QStringList>

#include <memory>

class KUniqueServicePrivate;

/**
 * This class can be used to create a unique service and redirect calls
 * to this service similarly to KDBusService(KDBusService::Unique).
 * @code
 *   YourApplication app(argc, argv);
 *
 *   KUniqueService service;
 *   QObject::connect(&service, &KUniqueService::activateRequested,
 *                    &app, &YourApplication::slotActivateRequested);
 *   QObject::connect(&app, &YourApplication::setExitValue,
 *   &service, [&service](int i) {
 *       service.setExitValue(i);
 *   });
 * @endcode
 * This will redirect calls to running instances over the
 * the slotActivateRequested. When you set the exit
 * value the calling process will afterwards exit with the
 * code provided.
 * If you do not set the exit value the application will not
 * be terminated.
 * @author Andre Heinecke (aheinecke@intevation.org)
 */
class KUniqueService : public QObject
{
    Q_OBJECT
public:
    explicit KUniqueService(QObject *parent = nullptr);
    ~KUniqueService() override;

public Q_SLOTS:
    /**
     * Set the exit @p code the second app should use to terminate.
     * If unset it exits with 0.
     * @param code The exit code.
     */
    void setExitValue(int code);

Q_SIGNALS:
    void activateRequested(const QStringList &arguments, const QString &workingDirectory);

private:
    void emitActivateRequested(const QStringList &arguments, const QString &workingDirectory)
    {
        Q_EMIT activateRequested(arguments, workingDirectory);
    }

    Q_DECLARE_PRIVATE(KUniqueService)
    const std::unique_ptr<KUniqueServicePrivate> d_ptr;
};
