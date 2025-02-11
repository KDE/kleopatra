/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB

    SPDX-FileCopyrightText: 2016 Bundesamt für Sicherheit in der Informationstechnik
    SPDX-FileContributor: Intevation GmbH

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <QGridLayout>
#include <QString>
#include <vector>

#include <gpgme++/key.h>

class QToolButton;
class QLabel;
class QStackedWidget;

namespace Kleo
{

class KeysComboBox;

class CertificateSelectionLine
{
public:
    /** Number of columns needed in the gridlayout. */
    static const unsigned int NumColumns = 4;

    /** Create a certificateselection line that distinguishes between protocols.
     *
     * Ambiguity means here that there is not a single valid choice or that
     * soemthing is not selected. There are basically two modes here, one is
     * for a protocol specific selection, that is used mainly by GpgOL over assuan.
     * This is the constructor for that mode. The second mode does not care about
     * protocols.
     *
     * @param toFrom: An optional label.
     * @param mailbox: The Mailbox for which the certificate should be selected.
     * @param pgp: List of PGP Certificates.
     * @param pgpAmbig: Whether or not the PGP Cert is ambiguous.
     * @param cms: List of CMS Certificates.
     * @param cmsAmbig: Whether or not the CMS Cert is ambiguous.
     * @param q: Parent widget.
     * @param glay: Layout to add the widgets to.
     */
    CertificateSelectionLine(const QString &toFrom,
                             const QString &mailbox,
                             const std::vector<GpgME::Key> &pgp,
                             bool pgpAmbig,
                             const std::vector<GpgME::Key> &cms,
                             bool cmsAmbig,
                             QWidget *q,
                             QGridLayout &glay);

    void showHide(GpgME::Protocol proto, bool &first, bool showAll, bool op) const;

    bool wasInitiallyAmbiguous(GpgME::Protocol proto) const;

    bool isStillAmbiguous(GpgME::Protocol proto) const;

    QString mailboxText() const;

    void addAndSelectCertificate(const GpgME::Key &key) const;

    GpgME::Key key(GpgME::Protocol proto) const;

    const QToolButton *toolButton() const;

    void kill();

    KeysComboBox *comboBox(GpgME::Protocol proto) const;

private:
    bool pgpAmbiguous : 1;
    bool cmsAmbiguous : 1;

    QLabel *mToFromLB;
    QLabel *mMailboxLB;
    QStackedWidget *mSbox;
    KeysComboBox *mPgpCB;
    KeysComboBox *mCmsCB;
    KeysComboBox *noProtocolCB;
    QToolButton *mToolTB;
};

} // namespace Kleo
