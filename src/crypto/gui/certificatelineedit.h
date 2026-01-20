/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH
    SPDX-FileCopyrightText: 2021, 2022 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <Libkleo/KeyUsage>

#include <QWidget>

#include <memory>

namespace GpgME
{
class Key;
class UserID;
}

namespace Kleo
{
class AbstractKeyListModel;
class KeyFilter;
class KeyGroup;

/** Line edit and completion based Certificate Selection Widget.
 *
 * Shows the status of the selection with a status label and icon.
 *
 * The widget will use a single line HBox Layout. For larger dialog
 * see certificateslectiondialog.
 */
class CertificateLineEdit : public QWidget
{
    Q_OBJECT
public:
    /** Create the certificate selection line.
     *
     * If parent is not NULL the model is not taken
     * over but the parent argument used as the parent of the model.
     *
     * @param model  The keylistmodel to use.
     * @param usage  the desired usage of the certificate
     * @param filter The filters to use. See certificateselectiondialog.
     * @param parent The usual widget parent.
     *
     * \a usage is used to mark certificates that cannot be used for the desired
     * usage with an appropriate icon. This is useful in combination with a suitable
     * key filter.
     * For example, the key filter could filter out any certificates without
     * encryption subkeys and the usage flags would mark certificates with expired
     * encryption subkeys as unusable, so that the users see that there is a
     * certificate, but that it cannot be used.
     */
    explicit CertificateLineEdit(AbstractKeyListModel *model, KeyUsage::Flags usage = KeyUsage::None, KeyFilter *filter = nullptr, QWidget *parent = nullptr);

    ~CertificateLineEdit() override;

    /** Get the selected key */
    GpgME::Key key() const;

    KeyGroup group() const;

    GpgME::UserID userID() const;

    /** The current text */
    QString text() const;

    /** Check if the text is empty */
    bool isEmpty() const;

    /** Returns true, if the user is editing the input. */
    bool isEditingInProgress() const;

    /** Returns true if the field is empty or if a key or group is selected. */
    bool hasAcceptableInput() const;

    /** Set the preselected Key for this widget. */
    void setKey(const GpgME::Key &key);

    /** Set the preselected group for this widget. */
    void setGroup(const KeyGroup &group);

    /** Set the preselected userId for this widget. */
    void setUserID(const GpgME::UserID &userID);

    /** Set the used keyfilter. */
    void setKeyFilter(const std::shared_ptr<KeyFilter> &filter);

    void setAccessibleNameOfLineEdit(const QString &name);

    /*!
     * Sets the error message that is shown for keys that are filtered out and for which
     * no specific reason like expired, revoked or disabled can be determined. By default,
     * the message "This certificate is unusable" is used.
     */
    void setErrorMessageForUnusableKeys(const QString &message);

Q_SIGNALS:
    /** Emitted when the selected key changed. */
    void keyChanged();

    /** Emitted when the entry is no longer empty. */
    void editingStarted();

    /** Emitted when the input is cleared (i.e. becomes empty). */
    void cleared();

    /** Emitted when the certificate selection dialog is requested. */
    void certificateSelectionRequested();

private:
    class Private;
    std::unique_ptr<Private> const d;
};

}
