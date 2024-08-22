/*  view/smartcardactions.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include "smartcardactions.h"

#include <commands/createopenpgpkeyfromcardkeyscommand.h>

#include <KActionCollection>
#include <KLocalizedString>

#include <algorithm>

using namespace Kleo::Commands;
using namespace Qt::Literals::StringLiterals;

SmartCardActions::SmartCardActions()
    : mActionCollection{std::make_unique<KActionCollection>(nullptr, u"smartcards"_s)}
{
    mActionCollection->setComponentDisplayName(i18n("Smart Card Management"));

    // window actions
    mActionCollection->addAction(KStandardAction::StandardAction::Close, u"window_close"_s);

    // general actions
    {
        QAction *action = mActionCollection->addAction(KStandardAction::StandardAction::Redisplay, u"reload"_s);
        action->setText(i18nc("@action", "Reload"));
        action->setToolTip(i18nc("@info:tooltip", "Reload smart cards"));
    }

    // card actions
    if (CreateOpenPGPKeyFromCardKeysCommand::isSupported()) {
        addAction(u"card_all_create_openpgp_certificate"_s, //
                  i18nc("@action", "Create OpenPGP Certificate"),
                  i18nc("@info:tooltip", "Create an OpenPGP certificate for the keys stored on the card."));
    }

    // NetKey-specific card actions
    addAction(u"card_netkey_set_nks_pin"_s, //
              i18nc("@action NKS is an identifier for a type of keys on a NetKey card", "Set NKS PIN"));
    addAction(u"card_netkey_set_sigg_pin"_s, //
              i18nc("@action SigG is an identifier for a type of keys on a NetKey card", "Set SigG PIN"));

    // OpenPGP-specific card actions
    addAction(u"card_pgp_generate_keys_and_certificate"_s, //
              i18nc("@action", "Generate New Keys"),
              xi18nc("@info:tooltip",
                     "<para>Generate three new keys on the smart card and create a new OpenPGP "
                     "certificate with those keys. Optionally, the encryption key is generated "
                     "off-card and a backup is created so that you can still access data encrypted "
                     "with this key in case the card is lost or damaged.</para>"
                     "<para><emphasis strong='true'>"
                     "Existing keys on the smart card will be overwritten."
                     "</emphasis></para>"));
    addAction(u"card_pgp_change_pin"_s, //
              i18nc("@action", "Change PIN"),
              i18nc("@info:tooltip",
                    "Change the PIN required for using the keys on the smart card. "
                    "The PIN must contain at least six characters."));
    addAction(u"card_pgp_unblock_card"_s, //
              i18nc("@action", "Unblock Card"),
              i18nc("@info:tooltip", "Unblock the smart card with the PUK (if available) or the Admin PIN."));
    addAction(u"card_pgp_change_admin_pin"_s, //
              i18nc("@action", "Change Admin PIN"),
              i18nc("@info:tooltip", "Change the PIN required for administrative operations."));
    addAction(u"card_pgp_change_puk"_s, //
              i18nc("@action", "Set PUK"),
              i18nc("@info:tooltip",
                    "Set or change the PUK that can be used to unblock the smart card. "
                    "The PUK must contain at least eight characters."));
    addAction(u"card_pgp_change_cardholder"_s, //
              i18nc("@action", "Change Cardholder"),
              i18nc("@info:tooltip", "Change the cardholder's name."),
              QIcon::fromTheme(u"document-edit"_s));

    // PIV-specific card actions
    addAction(u"card_piv_change_pin"_s, //
              i18nc("@action", "Change PIN"),
              i18nc("@info:tooltip", "Change the PIN required for using the keys on the smart card."));
    addAction(u"card_piv_change_puk"_s, //
              i18nc("@action", "Change PUK"),
              i18nc("@info:tooltip",
                    "Change the PIN Unblocking Key (PUK) that can be used to unblock the smart card "
                    "after a wrong PIN has been entered too many times."));
    addAction(u"card_piv_change_admin_key"_s, //
              i18nc("@action", "Change Admin Key"),
              i18nc("@info:tooltip",
                    "Change the PIV Card Application Administration Key that is used by the "
                    "PIV Card Application to authenticate the PIV Card Application Administrator and by the "
                    "administrator (resp. Kleopatra) to authenticate the PIV Card Application."));

    // card slot actions
    addAction(u"card_slot_show_certificate_details"_s, //
              i18nc("@action", "Show Certificate Details"),
              {},
              QIcon::fromTheme(u"dialog-information"_s));
    addAction(u"card_slot_generate_key"_s, //
              i18nc("@action", "Generate New Key"),
              i18nc("@info:tooltip", "If the card slot already contains a key then the new key will irrevocably replace the old key."),
              QIcon::fromTheme(u"view-certificate-add"_s));
    addAction(u"card_slot_write_key"_s, //
              i18nc("@action", "Write Key to Card"),
              i18nc("@info:tooltip", "Write the key pair of a certificate to the card"),
              QIcon::fromTheme(u"view-certificate-export"_s));
    addAction(u"card_slot_write_certificate"_s, //
              i18nc("@action", "Write Certificate to Card"),
              i18nc("@info:tooltip", "Write the certificate corresponding to this key to the card"),
              QIcon::fromTheme(u"view-certificate-export"_s));
    addAction(u"card_slot_read_certificate"_s, //
              i18nc("@action", "Import Certificate from Card"),
              i18nc("@info:tooltip", "Import the certificate stored on the card"),
              QIcon::fromTheme(u"view-certificate-import"_s));
    addAction(u"card_slot_create_csr"_s, //
              i18nc("@action", "Create S/MIME Certification Request"),
              i18nc("@info:tooltip", "Create an S/MIME certificate signing request for this key"),
              QIcon::fromTheme(u"view-certificate-add"_s));
}

SmartCardActions::~SmartCardActions() = default;

void SmartCardActions::addAction(const QString &id, const QString &text, const QString &toolTip, const QIcon &icon)
{
    QAction *action = mActionCollection->addAction(id);
    action->setText(text);
    action->setToolTip(toolTip);
    action->setIcon(icon);
}

std::shared_ptr<const SmartCardActions> SmartCardActions::instance()
{
    return mutableInstance();
}

std::shared_ptr<SmartCardActions> SmartCardActions::mutableInstance()
{
    static std::weak_ptr<SmartCardActions> self;
    if (std::shared_ptr<SmartCardActions> shared = self.lock()) {
        return shared;
    } else {
        const std::shared_ptr<SmartCardActions> s{new SmartCardActions};
        self = s;
        return s;
    }
}

// static
QAction *SmartCardActions::createProxyAction(QAction *action, QObject *parent)
{
    Q_ASSERT(action);
    auto proxyAction = new QAction{parent};
    proxyAction->setObjectName(action->objectName());
    proxyAction->setText(action->text());
    proxyAction->setToolTip(action->toolTip());
    proxyAction->setIcon(action->icon());
    QObject::connect(proxyAction, &QAction::triggered, action, &QAction::trigger);
    return proxyAction;
}

QAction *SmartCardActions::action(const QString &name) const
{
    return mActionCollection->action(name);
}

std::vector<QAction *> SmartCardActions::actions(const std::vector<QString> &names) const
{
    std::vector<QAction *> result;
    result.reserve(names.size());
    std::ranges::transform(names, std::back_inserter(result), [this](const QString &name) {
        return action(name);
    });
    std::erase(result, nullptr);
    return result;
}
