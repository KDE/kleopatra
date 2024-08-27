/* -*- mode: c++; c-basic-offset:4 -*-
    dialogs/lookupcertificatesdialog.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "lookupcertificatesdialog.h"

#include <view/textoverlay.h>

#include <kleopatra_debug.h>

#include <Libkleo/Formatting>
#include <Libkleo/GnuPG>
#include <Libkleo/KeyList>
#include <Libkleo/TreeWidget>

#include <KConfigGroup>
#include <KLocalizedString>
#include <KSeparator>
#include <KSharedConfig>
#include <KStandardAction>

#include <QClipboard>
#include <QDialogButtonBox>
#include <QGridLayout>
#include <QGuiApplication>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPushButton>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QTreeView>
#include <QVBoxLayout>

#include <gpgme++/key.h>

using namespace Kleo;
using namespace Kleo::Dialogs;
using namespace GpgME;

Q_DECLARE_METATYPE(KeyWithOrigin);

static const int KeyWithOriginRole = 0x201;

class LookupCertificatesDialog::Private
{
    friend class ::Kleo::Dialogs::LookupCertificatesDialog;
    LookupCertificatesDialog *const q;

public:
    enum Columns {
        Name,
        Email,
        Fingerprint,
        ValidFrom,
        ValidUntil,
        Protocol,
        KeyID,
        Origin,
    };

    explicit Private(LookupCertificatesDialog *qq);
    ~Private();

private:
    void slotSelectionChanged()
    {
        enableDisableWidgets();
    }
    void slotSearchTextChanged()
    {
        enableDisableWidgets();
    }
    void slotSearchClicked()
    {
        Q_EMIT q->searchTextChanged(searchText());
    }
    void slotDetailsClicked()
    {
        if (!q->selectedCertificates().empty()) {
            Q_EMIT q->detailsRequested(q->selectedCertificates().front().key);
        }
    }
    void slotSaveAsClicked()
    {
        std::vector<GpgME::Key> keys;
        for (const auto &[key, origin] : q->selectedCertificates()) {
            keys.push_back(key);
        }
        Q_EMIT q->saveAsRequested(keys);
    }

    void readConfig();
    void writeConfig();
    void enableDisableWidgets();

    QString searchText() const
    {
        return ui.findED->text().trimmed();
    }

    std::vector<KeyWithOrigin> selectedCertificates() const
    {
        const QAbstractItemView *const view = ui.resultTV;
        if (!view) {
            return {};
        }
        const auto sm = view->selectionModel();
        Q_ASSERT(sm);

        std::vector<KeyWithOrigin> keys;
        for (const auto &index : sm->selectedRows()) {
            const auto key = ui.resultTV->itemFromIndex(index)->data(Private::Name, KeyWithOriginRole).value<KeyWithOrigin>();
            Q_ASSERT(!key.key.isNull());
            keys.push_back(key);
        }
        return keys;
    }

    int numSelectedCertificates() const
    {
        return ui.resultTV->selectedItems().size();
    }

    void copySelectedValue()
    {
        auto clipboardData = ui.resultTV->currentIndex().data(Kleo::ClipboardRole).toString();
        if (clipboardData.isEmpty()) {
            clipboardData = ui.resultTV->currentIndex().data().toString();
        }
        QGuiApplication::clipboard()->setText(clipboardData);
    }

    QValidator *queryValidator();
    void updateQueryMode();

private:
    QueryMode queryMode = AnyQuery;
    bool passive;
    QValidator *anyQueryValidator = nullptr;
    QValidator *emailQueryValidator = nullptr;
    bool initial = false;

    struct Ui {
        QLabel *guidanceLabel;
        QLabel *findLB;
        QLineEdit *findED;
        QPushButton *findPB;
        Kleo::TreeWidget *resultTV;
        TextOverlay *overlay;
        QPushButton *selectAllPB;
        QPushButton *deselectAllPB;
        QPushButton *detailsPB;
        QPushButton *saveAsPB;
        QDialogButtonBox *buttonBox;

        void setupUi(LookupCertificatesDialog *dialog)
        {
            auto verticalLayout = new QVBoxLayout{dialog};
            auto gridLayout = new QGridLayout{};

            int row = 0;
            guidanceLabel = new QLabel{dialog};
            gridLayout->addWidget(guidanceLabel, row, 0, 1, 3);

            row++;
            findLB = new QLabel{i18n("Find:"), dialog};
            gridLayout->addWidget(findLB, row, 0, 1, 1);

            findED = new QLineEdit{dialog};
            findLB->setBuddy(findED);
            gridLayout->addWidget(findED, row, 1, 1, 1);

            findPB = new QPushButton{i18n("Search"), dialog};
            findPB->setAutoDefault(false);
            gridLayout->addWidget(findPB, row, 2, 1, 1);

            row++;
            gridLayout->addWidget(new KSeparator{Qt::Horizontal, dialog}, row, 0, 1, 3);

            row++;
            resultTV = new Kleo::TreeWidget(dialog);
            resultTV->setEnabled(true);
            resultTV->setMinimumSize(QSize(400, 0));
            overlay = new TextOverlay{resultTV, dialog};
            overlay->hide();
            gridLayout->addWidget(resultTV, row, 0, 1, 2);

            auto buttonLayout = new QVBoxLayout{};

            selectAllPB = new QPushButton{i18n("Select All"), dialog};
            selectAllPB->setEnabled(false);
            selectAllPB->setAutoDefault(false);
            buttonLayout->addWidget(selectAllPB);

            deselectAllPB = new QPushButton{i18n("Deselect All"), dialog};
            deselectAllPB->setEnabled(false);
            deselectAllPB->setAutoDefault(false);
            buttonLayout->addWidget(deselectAllPB);

            buttonLayout->addStretch();

            detailsPB = new QPushButton{i18n("Details..."), dialog};
            detailsPB->setEnabled(false);
            detailsPB->setAutoDefault(false);
            buttonLayout->addWidget(detailsPB);

            saveAsPB = new QPushButton{i18n("Save As..."), dialog};
            saveAsPB->setEnabled(false);
            saveAsPB->setAutoDefault(false);
            buttonLayout->addWidget(saveAsPB);

            gridLayout->addLayout(buttonLayout, row, 2, 1, 1);

            verticalLayout->addLayout(gridLayout);

            buttonBox = new QDialogButtonBox{dialog};
            buttonBox->setStandardButtons(QDialogButtonBox::Close | QDialogButtonBox::Save);
            verticalLayout->addWidget(buttonBox);

            QObject::connect(findED, SIGNAL(returnPressed()), findPB, SLOT(animateClick()));
            QObject::connect(buttonBox, SIGNAL(accepted()), dialog, SLOT(accept()));
            QObject::connect(buttonBox, SIGNAL(rejected()), dialog, SLOT(reject()));
            QObject::connect(findPB, SIGNAL(clicked()), dialog, SLOT(slotSearchClicked()));
            QObject::connect(detailsPB, SIGNAL(clicked()), dialog, SLOT(slotDetailsClicked()));
            QObject::connect(saveAsPB, SIGNAL(clicked()), dialog, SLOT(slotSaveAsClicked()));
            QObject::connect(findED, SIGNAL(textChanged(QString)), dialog, SLOT(slotSearchTextChanged()));

            QMetaObject::connectSlotsByName(dialog);

            resultTV->setHeaderLabels({
                i18nc("@title:column", "Name"),
                i18nc("@title:column", "Email"),
                i18nc("@title:column", "Fingerprint"),
                i18nc("@title:column", "Valid From"),
                i18nc("@title:column", "Valid Until"),
                i18nc("@title:column", "Protocol"),
                i18nc("@title:column", "Key ID"),
                i18nc("@title:column", "Origin"),
            });

            resultTV->setSelectionMode(QAbstractItemView::ExtendedSelection);

            resultTV->setContextMenuPolicy(Qt::CustomContextMenu);
            connect(resultTV, &QTreeView::customContextMenuRequested, dialog, [this, dialog](const auto &pos) {
                auto menu = new QMenu;
                menu->setAttribute(Qt::WA_DeleteOnClose, true);
                menu->addAction(KStandardAction::copy(
                    dialog,
                    [dialog]() {
                        dialog->d->copySelectedValue();
                    },
                    dialog));
                menu->popup(resultTV->mapToGlobal(pos));
            });
        }

        explicit Ui(LookupCertificatesDialog *q)
        {
            q->setWindowTitle(i18n("Lookup on Server"));
            setupUi(q);

            saveAsPB->hide(); // ### not yet implemented in LookupCertificatesCommand

            findED->setClearButtonEnabled(true);

            importPB()->setText(i18n("Import"));
            importPB()->setEnabled(false);

            connect(resultTV, SIGNAL(doubleClicked(QModelIndex)), q, SLOT(slotDetailsClicked()));

            findED->setFocus();

            connect(selectAllPB, &QPushButton::clicked, resultTV, &QTreeView::selectAll);
            connect(deselectAllPB, &QPushButton::clicked, resultTV, &QTreeView::clearSelection);
        }

        QPushButton *importPB() const
        {
            return buttonBox->button(QDialogButtonBox::Save);
        }
        QPushButton *closePB() const
        {
            return buttonBox->button(QDialogButtonBox::Close);
        }
    } ui;
};

LookupCertificatesDialog::Private::Private(LookupCertificatesDialog *qq)
    : q(qq)
    , passive(false)
    , ui(q)
{
    connect(ui.resultTV->selectionModel(), SIGNAL(selectionChanged(QItemSelection, QItemSelection)), q, SLOT(slotSelectionChanged()));
    updateQueryMode();
}

LookupCertificatesDialog::Private::~Private()
{
}

void LookupCertificatesDialog::Private::readConfig()
{
    KConfigGroup configGroup(KSharedConfig::openStateConfig(), "LookupCertificatesDialog");
    if (!ui.resultTV->restoreColumnLayout(QStringLiteral("LookupCertificatesDialog"))) {
        ui.resultTV->setColumnHidden(Private::KeyID, true);
        initial = true;
        ui.resultTV->resizeToContentsLimited();
    }

    const QSize size = configGroup.readEntry("Size", QSize(600, 400));
    if (size.isValid()) {
        q->resize(size);
    }
}

void LookupCertificatesDialog::Private::writeConfig()
{
    KConfigGroup configGroup(KSharedConfig::openStateConfig(), "LookupCertificatesDialog");
    configGroup.writeEntry("Size", q->size());
    configGroup.sync();
}

static QString guidanceText(LookupCertificatesDialog::QueryMode mode)
{
    switch (mode) {
    default:
        qCWarning(KLEOPATRA_LOG) << __func__ << "Unknown query mode:" << mode;
        [[fallthrough]];
    case LookupCertificatesDialog::AnyQuery:
        return xi18nc("@info", "Enter a search term to search for matching certificates.");
    case LookupCertificatesDialog::EmailQuery:
        return xi18nc("@info", "Enter an email address to search for matching certificates.");
    };
}

QValidator *LookupCertificatesDialog::Private::queryValidator()
{
    switch (queryMode) {
    default:
        qCWarning(KLEOPATRA_LOG) << __func__ << "Unknown query mode:" << queryMode;
        [[fallthrough]];
    case AnyQuery: {
        if (!anyQueryValidator) {
            // allow any query with at least one non-whitespace character
            anyQueryValidator = new QRegularExpressionValidator{QRegularExpression{QStringLiteral(".*\\S+.*")}, q};
        }
        return anyQueryValidator;
    }
    case EmailQuery: {
        if (!emailQueryValidator) {
            // allow anything that looks remotely like an email address, i.e.
            // anything with an '@' surrounded by non-whitespace characters
            const QRegularExpression simpleEmailRegex{QStringLiteral(".*\\S+@\\S+.*")};
            emailQueryValidator = new QRegularExpressionValidator{simpleEmailRegex, q};
        }
        return emailQueryValidator;
    }
    }
}

void LookupCertificatesDialog::Private::updateQueryMode()
{
    ui.guidanceLabel->setText(guidanceText(queryMode));
    ui.findED->setValidator(queryValidator());
}

LookupCertificatesDialog::LookupCertificatesDialog(QWidget *p, Qt::WindowFlags f)
    : QDialog(p, f)
    , d(new Private(this))
{
    d->ui.findPB->setEnabled(false);
    d->readConfig();
}

LookupCertificatesDialog::~LookupCertificatesDialog()
{
    d->writeConfig();
}

void LookupCertificatesDialog::setQueryMode(QueryMode mode)
{
    d->queryMode = mode;
    d->updateQueryMode();
}

LookupCertificatesDialog::QueryMode LookupCertificatesDialog::queryMode() const
{
    return d->queryMode;
}

void LookupCertificatesDialog::setCertificates(const std::vector<KeyWithOrigin> &certs)
{
    d->ui.resultTV->setFocus();
    d->ui.resultTV->clear();

    for (const auto &[cert, origin] : certs) {
        auto item = new QTreeWidgetItem;
        item->setData(Private::Name, Qt::DisplayRole, Formatting::prettyName(cert));
        item->setData(Private::Email, Qt::DisplayRole, Formatting::prettyEMail(cert));
        item->setData(Private::Fingerprint, Qt::DisplayRole, Formatting::prettyID(cert.primaryFingerprint()));
        item->setData(Private::Fingerprint, Qt::AccessibleTextRole, Formatting::accessibleHexID(cert.primaryFingerprint()));
        item->setData(Private::Fingerprint, Kleo::ClipboardRole, QString::fromLatin1(cert.primaryFingerprint()));
        item->setData(Private::ValidFrom, Qt::DisplayRole, Formatting::creationDateString(cert));
        item->setData(Private::ValidFrom, Qt::AccessibleTextRole, Formatting::accessibleCreationDate(cert));
        item->setData(Private::ValidUntil, Qt::DisplayRole, Formatting::expirationDateString(cert));
        item->setData(Private::ValidUntil, Qt::AccessibleTextRole, Formatting::accessibleExpirationDate(cert));
        item->setData(Private::KeyID, Qt::DisplayRole, Formatting::prettyID(cert.keyID()));
        item->setData(Private::KeyID, Qt::AccessibleTextRole, Formatting::accessibleHexID(cert.keyID()));
        item->setData(Private::KeyID, Kleo::ClipboardRole, QString::fromLatin1(cert.keyID()));

        if (cert.protocol() == Protocol::CMS) {
            item->setData(Private::Origin, Qt::DisplayRole, i18n("LDAP"));
        } else if (origin == GpgME::Key::OriginKS) {
            if (keyserver().startsWith(QStringLiteral("ldap:")) || keyserver().startsWith(QStringLiteral("ldaps:"))) {
                item->setData(Private::Origin, Qt::DisplayRole, i18n("LDAP"));
            } else {
                item->setData(Private::Origin, Qt::DisplayRole, i18n("Keyserver"));
            }
        } else {
            item->setData(Private::Origin, Qt::DisplayRole, Formatting::origin(origin));
        }

        item->setData(Private::Protocol, Qt::DisplayRole, Formatting::displayName(cert.protocol()));
        item->setData(Private::Name, KeyWithOriginRole, QVariant::fromValue(KeyWithOrigin{cert, origin}));

        d->ui.resultTV->addTopLevelItem(item);
    }
    if (certs.size() == 1) {
        d->ui.resultTV->setCurrentIndex(d->ui.resultTV->model()->index(0, 0));
    }
    if (d->initial && d->ui.resultTV->model()->rowCount() > 0) {
        d->initial = false;
        d->ui.resultTV->resizeToContentsLimited();
    }
}

std::vector<KeyWithOrigin> LookupCertificatesDialog::selectedCertificates() const
{
    return d->selectedCertificates();
}

void LookupCertificatesDialog::setPassive(bool on)
{
    if (d->passive == on) {
        return;
    }
    d->passive = on;
    d->enableDisableWidgets();
}

bool LookupCertificatesDialog::isPassive() const
{
    return d->passive;
}

void LookupCertificatesDialog::setSearchText(const QString &text)
{
    d->ui.findED->setText(text);
}

QString LookupCertificatesDialog::searchText() const
{
    return d->ui.findED->text();
}

void LookupCertificatesDialog::setOverlayText(const QString &text)
{
    if (text.isEmpty()) {
        d->ui.overlay->hideOverlay();
    } else {
        d->ui.overlay->setText(text);
        d->ui.overlay->showOverlay();
    }
    d->ui.selectAllPB->setEnabled(text.isEmpty());
    d->ui.deselectAllPB->setEnabled(text.isEmpty());
}

QString LookupCertificatesDialog::overlayText() const
{
    return d->ui.overlay->text();
}

void LookupCertificatesDialog::accept()
{
    Q_ASSERT(!selectedCertificates().empty());
    Q_EMIT importRequested(selectedCertificates());
    QDialog::accept();
}

void LookupCertificatesDialog::Private::enableDisableWidgets()
{
    // enable/disable everything except 'close', based on passive:
    const QList<QObject *> list = q->children();
    for (QObject *const o : list) {
        if (QWidget *const w = qobject_cast<QWidget *>(o)) {
            w->setDisabled(passive && w != ui.closePB() && w != ui.buttonBox);
        }
    }

    if (passive) {
        return;
    }

    q->setOverlayText({});

    ui.findPB->setEnabled(ui.findED->hasAcceptableInput());

    const int n = q->selectedCertificates().size();

    ui.detailsPB->setEnabled(n == 1);
    ui.saveAsPB->setEnabled(n == 1);
    ui.importPB()->setEnabled(n != 0);
    ui.importPB()->setDefault(false); // otherwise Import becomes default button if enabled and return triggers both a search and accept()
}

void LookupCertificatesDialog::keyPressEvent(QKeyEvent *event)
{
    if (event == QKeySequence::Copy && d->ui.resultTV->hasFocus()) {
        d->copySelectedValue();
        event->accept();
    }
}

#include "moc_lookupcertificatesdialog.cpp"
