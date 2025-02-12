/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2010 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "verifychecksumsdialog.h"

#ifndef QT_NO_DIRMODEL

#include <Libkleo/SystemInfo>

#include <KLocalizedString>
#include <KMessageBox>

#include "kleopatra_debug.h"
#include <QDialogButtonBox>
#include <QFileSystemModel>
#include <QHBoxLayout>
#include <QHash>
#include <QHeaderView>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QSortFilterProxyModel>
#include <QStringList>
#include <QTreeView>
#include <QVBoxLayout>

using namespace Kleo;
using namespace Kleo::Crypto;
using namespace Kleo::Crypto::Gui;

namespace
{

static Qt::GlobalColor statusColor[] = {
    Qt::color0, // Unknown - nothing
    Qt::green, // OK
    Qt::red, // Failed
    Qt::darkRed, // Error
};
static_assert((sizeof(statusColor) / sizeof(*statusColor)) == VerifyChecksumsDialog::NumStatii, "");

class ColorizedFileSystemModel : public QFileSystemModel
{
    Q_OBJECT
public:
    explicit ColorizedFileSystemModel(QObject *parent = nullptr)
        : QFileSystemModel(parent)
        , statusMap()
    {
    }

    QVariant data(const QModelIndex &mi, int role = Qt::DisplayRole) const override
    {
        if (mi.isValid() && role == Qt::BackgroundRole && !SystemInfo::isHighContrastModeActive()) {
            const QHash<QString, VerifyChecksumsDialog::Status>::const_iterator it = statusMap.find(filePath(mi));
            if (it != statusMap.end())
                if (const Qt::GlobalColor c = statusColor[*it]) {
                    return QColor(c);
                }
        }
        return QFileSystemModel::data(mi, role);
    }

public Q_SLOTS:
    void setStatus(const QString &file, VerifyChecksumsDialog::Status status)
    {
        if (status >= VerifyChecksumsDialog::NumStatii || file.isEmpty()) {
            return;
        }

        // canonicalize filename:
        const QModelIndex mi = index(file);
        const QString canonical = filePath(mi);
        if (canonical.isEmpty()) {
            qCDebug(KLEOPATRA_LOG) << "can't locate file " << file;
            return;
        }

        const QHash<QString, VerifyChecksumsDialog::Status>::iterator it = statusMap.find(canonical);

        if (it != statusMap.end())
            if (*it == status) {
                return; // nothing to do
            } else {
                *it = status;
            }
        else {
            statusMap[canonical] = status;
        }

        emitDataChangedFor(mi);
    }

    void clearStatusInformation()
    {
        using std::swap;

        QHash<QString, VerifyChecksumsDialog::Status> oldStatusMap;
        swap(statusMap, oldStatusMap);

        for (QHash<QString, VerifyChecksumsDialog::Status>::const_iterator it = oldStatusMap.constBegin(), end = oldStatusMap.constEnd(); it != end; ++it) {
            emitDataChangedFor(it.key());
        }
    }

private:
    void emitDataChangedFor(const QString &file)
    {
        emitDataChangedFor(index(file));
    }
    void emitDataChangedFor(const QModelIndex &mi)
    {
        const QModelIndex p = parent(mi);
        Q_EMIT dataChanged(index(mi.row(), 0, p), index(mi.row(), columnCount(p) - 1, p));
    }

private:
    QHash<QString, VerifyChecksumsDialog::Status> statusMap;
};

static int find_layout_item(const QBoxLayout &blay)
{
    for (int i = 0, end = blay.count(); i < end; ++i)
        if (QLayoutItem *item = blay.itemAt(i))
            if (item->layout()) {
                return i;
            }
    return 0;
}

struct BaseWidget {
    QSortFilterProxyModel proxy;
    QLabel label;
    QTreeView view;

    BaseWidget(QFileSystemModel *model, QWidget *parent, QVBoxLayout *vlay)
        : proxy()
        , label(parent)
        , view(parent)
    {
        Q_SET_OBJECT_NAME(proxy);
        Q_SET_OBJECT_NAME(label);
        Q_SET_OBJECT_NAME(view);

        const int row = find_layout_item(*vlay);
        vlay->insertWidget(row, &label);
        vlay->insertWidget(row + 1, &view, 1);

        proxy.setSourceModel(model);

        view.setModel(&proxy);

        QRect r;
        for (int i = 0; i < proxy.columnCount(); ++i) {
            view.resizeColumnToContents(i);
        }

        // define some minimum sizes
        view.header()->resizeSection(0, qMax(view.header()->sectionSize(0), 220));
        view.header()->resizeSection(1, qMax(view.header()->sectionSize(1), 75));
        view.header()->resizeSection(2, qMax(view.header()->sectionSize(2), 75));
        view.header()->resizeSection(3, qMax(view.header()->sectionSize(3), 140));

        for (int i = 0; i < proxy.rowCount(); ++i) {
            r = r.united(view.visualRect(proxy.index(proxy.columnCount() - 1, i)));
        }
        view.setMinimumSize(
            QSize(qBound(r.width() + 4 * view.frameWidth(), 220 + 75 + 75 + 140 + 4 * view.frameWidth(), 1024), // 100 is the default defaultSectionSize
                  qBound(r.height(), 220, 512)));
    }

    void setBase(const QString &base)
    {
        label.setText(base);
        if (auto fsm = qobject_cast<QFileSystemModel *>(proxy.sourceModel())) {
            view.setRootIndex(proxy.mapFromSource(fsm->index(base)));
        } else {
            qCWarning(KLEOPATRA_LOG) << "expect a QFileSystemModel-derived class as proxy.sourceModel(), got ";
            if (!proxy.sourceModel()) {
                qCWarning(KLEOPATRA_LOG) << "a null pointer";
            } else {
                qCWarning(KLEOPATRA_LOG) << proxy.sourceModel()->metaObject()->className();
            }
        }
    }
};

} // anon namespace

class VerifyChecksumsDialog::Private
{
    friend class ::Kleo::Crypto::Gui::VerifyChecksumsDialog;
    VerifyChecksumsDialog *const q;

public:
    explicit Private(VerifyChecksumsDialog *qq)
        : q(qq)
        , bases()
        , errors()
        , model()
        , ui(q)
    {
        qRegisterMetaType<Status>("Kleo::Crypto::Gui::VerifyChecksumsDialog::Status");
    }

private:
    void slotErrorButtonClicked()
    {
        KMessageBox::errorList(q, i18n("The following errors and warnings were recorded:"), errors, i18nc("@title:window", "Checksum Verification Errors"));
    }

private:
    void updateErrors()
    {
        const bool active = ui.isProgressBarActive();
        ui.progressLabel.setVisible(active);
        ui.progressBar.setVisible(active);
        ui.errorLabel.setVisible(!active);
        ui.errorButton.setVisible(!active && !errors.empty());
        if (errors.empty()) {
            ui.errorLabel.setText(i18n("No errors occurred"));
        } else {
            ui.errorLabel.setText(i18np("One error occurred", "%1 errors occurred", errors.size()));
        }
    }

private:
    QStringList bases;
    QStringList errors;
    ColorizedFileSystemModel model;

    struct UI {
        std::vector<BaseWidget *> baseWidgets;
        QLabel progressLabel;
        QProgressBar progressBar;
        QLabel errorLabel;
        QPushButton errorButton;
        QDialogButtonBox buttonBox;
        QVBoxLayout vlay;
        QHBoxLayout hlay[2];

        explicit UI(VerifyChecksumsDialog *q)
            : baseWidgets()
            , progressLabel(i18n("Progress:"), q)
            , progressBar(q)
            , errorLabel(i18n("No errors occurred"), q)
            , errorButton(i18nc("Show Errors", "Show"), q)
            , buttonBox(QDialogButtonBox::Close, Qt::Horizontal, q)
            , vlay(q)
        {
            Q_SET_OBJECT_NAME(progressLabel);
            Q_SET_OBJECT_NAME(progressBar);
            Q_SET_OBJECT_NAME(errorLabel);
            Q_SET_OBJECT_NAME(errorButton);
            Q_SET_OBJECT_NAME(buttonBox);
            Q_SET_OBJECT_NAME(vlay);
            Q_SET_OBJECT_NAME(hlay[0]);
            Q_SET_OBJECT_NAME(hlay[1]);

            errorButton.setAutoDefault(false);

            hlay[0].addWidget(&progressLabel);
            hlay[0].addWidget(&progressBar, 1);

            hlay[1].addWidget(&errorLabel, 1);
            hlay[1].addWidget(&errorButton);

            vlay.addLayout(&hlay[0]);
            vlay.addLayout(&hlay[1]);
            vlay.addWidget(&buttonBox);

            errorLabel.hide();
            errorButton.hide();

            QPushButton *close = closeButton();

            connect(close, &QPushButton::clicked, q, &VerifyChecksumsDialog::canceled);
            connect(close, &QPushButton::clicked, q, &VerifyChecksumsDialog::accept);

            connect(&errorButton, SIGNAL(clicked()), q, SLOT(slotErrorButtonClicked()));
        }

        ~UI()
        {
            qDeleteAll(baseWidgets);
        }

        QPushButton *closeButton() const
        {
            return buttonBox.button(QDialogButtonBox::Close);
        }

        void setBases(const QStringList &bases, QFileSystemModel *model)
        {
            // create new BaseWidgets:
            for (unsigned int i = baseWidgets.size(), end = bases.size(); i < end; ++i) {
                baseWidgets.push_back(new BaseWidget(model, vlay.parentWidget(), &vlay));
            }

            // shed surplus BaseWidgets:
            for (unsigned int i = bases.size(), end = baseWidgets.size(); i < end; ++i) {
                delete baseWidgets.back();
                baseWidgets.pop_back();
            }

            Q_ASSERT(static_cast<unsigned>(bases.size()) == baseWidgets.size());

            // update bases:
            for (unsigned int i = 0; i < baseWidgets.size(); ++i) {
                baseWidgets[i]->setBase(bases[i]);
            }
        }

        void setProgress(int cur, int tot)
        {
            progressBar.setMaximum(tot);
            progressBar.setValue(cur);
        }

        bool isProgressBarActive() const
        {
            const int tot = progressBar.maximum();
            const int cur = progressBar.value();
            return !tot || cur != tot;
        }

    } ui;
};

VerifyChecksumsDialog::VerifyChecksumsDialog(QWidget *parent)
    : QDialog(parent)
    , d(new Private(this))
{
}

VerifyChecksumsDialog::~VerifyChecksumsDialog()
{
}

// slot
void VerifyChecksumsDialog::setBaseDirectories(const QStringList &bases)
{
    if (d->bases == bases) {
        return;
    }
    d->bases = bases;
    d->ui.setBases(bases, &d->model);
}

// slot
void VerifyChecksumsDialog::setErrors(const QStringList &errors)
{
    if (d->errors == errors) {
        return;
    }
    d->errors = errors;
    d->updateErrors();
}

// slot
void VerifyChecksumsDialog::setProgress(int cur, int tot)
{
    d->ui.setProgress(cur, tot);
    d->updateErrors();
}

// slot
void VerifyChecksumsDialog::setStatus(const QString &file, Status status)
{
    d->model.setStatus(file, status);
}

// slot
void VerifyChecksumsDialog::clearStatusInformation()
{
    d->errors.clear();
    d->updateErrors();
    d->model.clearStatusInformation();
}

#include "moc_verifychecksumsdialog.cpp"
#include "verifychecksumsdialog.moc"

#endif // QT_NO_DIRMODEL
