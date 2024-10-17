/*  view/cardkeysview.h

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2024 g10 Code GmbH
    SPDX-FileContributor: Ingo Klöcker <dev@ingo-kloecker.de>

    SPDX-License-Identifier: GPL-2.0-or-later
*/
#pragma once

#include <Libkleo/Predicates>

#include <QHash>
#include <QWidget>

#include <set>
#include <string>
#include <vector>

class CardKeysWidgetItem;
class QAction;
class QToolButton;
class QTreeWidgetItem;

namespace GpgME
{
class Key;
class KeyListResult;
}

namespace Kleo
{
class ProgressOverlay;
class TreeWidget;

namespace SmartCard
{
enum class AppType;
class Card;
struct KeyPairInfo;
}

class CardKeysView : public QWidget
{
    Q_OBJECT
public:
    enum Option {
        // clang-format off
        NoOptions    = 0x0000,
        ShowCreated  = 0x0001, // show "Created" column by default
        DefaultOptions = ShowCreated,
        // clang-format on
    };
    Q_DECLARE_FLAGS(Options, Option)

    explicit CardKeysView(QWidget *parent, Options options = DefaultOptions);
    ~CardKeysView() override;

    void setCard(const std::shared_ptr<const SmartCard::Card> &card);

    std::string currentCardSlot() const;
    GpgME::Key currentCertificate() const;

Q_SIGNALS:
    void currentCardSlotChanged() const;

protected:
    bool eventFilter(QObject *obj, QEvent *event) override;

private:
    void updateKeyList();
    void insertTreeWidgetItem(int slotIndex, const SmartCard::KeyPairInfo &keyInfo, const GpgME::Subkey &subkey, int treeIndex = -1);
    QToolButton *addActionsButton(CardKeysWidgetItem *item, SmartCard::AppType cardType);
    void ensureCertificatesAreValidated();
    void startCertificateValidation(const std::vector<GpgME::Key> &certificates);
    void certificateValidationDone(const GpgME::KeyListResult &result, const std::vector<GpgME::Key> &keys);
    void learnCard();

private:
    Options mOptions;

    std::shared_ptr<const Kleo::SmartCard::Card> mCard;

    std::vector<GpgME::Key> mCertificates; // only S/MIME certificates

    using KeySet = std::set<GpgME::Key, _detail::ByFingerprint<std::less>>;
    KeySet mValidatedCertificates;

    TreeWidget *mTreeWidget = nullptr;
    ProgressOverlay *mTreeViewOverlay = nullptr;
};

Q_DECLARE_OPERATORS_FOR_FLAGS(CardKeysView::Options)

} // namespace Kleo
