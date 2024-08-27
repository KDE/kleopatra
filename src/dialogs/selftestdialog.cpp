/* -*- mode: c++; c-basic-offset:4 -*-
    dialogs/selftestdialog.cpp

    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "selftestdialog.h"

#include <selftest/selftest.h>
#include <utils/accessibility.h>
#include <utils/scrollarea.h>

#include <Libkleo/SystemInfo>
#include <Libkleo/TreeView>

#include <KColorScheme>
#include <KLocalizedString>

#include <QAbstractTableModel>
#include <QApplication>
#include <QCheckBox>
#include <QDialogButtonBox>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QSortFilterProxyModel>
#include <QSplitter>
#include <QVBoxLayout>

#include "kleopatra_debug.h"

using namespace Kleo;
using namespace Kleo::Dialogs;

namespace
{

class Model : public QAbstractTableModel
{
    Q_OBJECT
public:
    explicit Model(QObject *parent = nullptr)
        : QAbstractTableModel(parent)
        , m_tests()
    {
    }

    enum Column {
        TestName,
        TestResult,

        NumColumns
    };

    const std::shared_ptr<SelfTest> &fromModelIndex(const QModelIndex &idx) const
    {
        const unsigned int row = idx.row();
        if (row < m_tests.size()) {
            return m_tests[row];
        }
        static const std::shared_ptr<SelfTest> null;
        return null;
    }

    int rowCount(const QModelIndex &idx) const override
    {
        return idx.isValid() ? 0 : m_tests.size();
    }
    int columnCount(const QModelIndex &) const override
    {
        return NumColumns;
    }

    QVariant data(const QModelIndex &idx, int role) const override
    {
        const unsigned int row = idx.row();
        if (idx.isValid() && row < m_tests.size())
            switch (role) {
            case Qt::DisplayRole:
            case Qt::ToolTipRole:
                switch (idx.column()) {
                case TestName:
                    return m_tests[row]->name();
                case TestResult:
                    return m_tests[row]->skipped() ? i18n("Skipped") //
                        : m_tests[row]->passed()   ? i18n("Passed")
                                                   : m_tests[row]->shortError();
                }
                break;
            case Qt::BackgroundRole:
                if (!SystemInfo::isHighContrastModeActive()) {
                    KColorScheme scheme(qApp->palette().currentColorGroup());
                    return (m_tests[row]->skipped()      ? scheme.background(KColorScheme::NeutralBackground)
                                : m_tests[row]->passed() ? scheme.background(KColorScheme::PositiveBackground)
                                                         : scheme.background(KColorScheme::NegativeBackground))
                        .color();
                }
            }
        return QVariant();
    }

    QVariant headerData(int section, Qt::Orientation o, int role) const override
    {
        if (o == Qt::Horizontal && section >= 0 && section < NumColumns && role == Qt::DisplayRole)
            switch (section) {
            case TestName:
                return i18n("Test Name");
            case TestResult:
                return i18n("Result");
            }
        return QVariant();
    }

    void clear()
    {
        if (m_tests.empty()) {
            return;
        }
        beginRemoveRows(QModelIndex(), 0, m_tests.size() - 1);
        m_tests.clear();
        endRemoveRows();
    }

    void append(const std::vector<std::shared_ptr<SelfTest>> &tests)
    {
        if (tests.empty()) {
            return;
        }
        beginInsertRows(QModelIndex(), m_tests.size(), m_tests.size() + tests.size());
        m_tests.insert(m_tests.end(), tests.begin(), tests.end());
        endInsertRows();
    }

    void reloadData()
    {
        if (!m_tests.empty()) {
            Q_EMIT dataChanged(index(0, 0), index(m_tests.size() - 1, NumColumns - 1));
        }
    }

    const std::shared_ptr<SelfTest> &at(unsigned int idx) const
    {
        return m_tests.at(idx);
    }

private:
    std::vector<std::shared_ptr<SelfTest>> m_tests;
};

class Proxy : public QSortFilterProxyModel
{
    Q_OBJECT
public:
    explicit Proxy(QObject *parent = nullptr)
        : QSortFilterProxyModel(parent)
        , m_showAll(true)
    {
        setDynamicSortFilter(true);
    }

    bool showAll() const
    {
        return m_showAll;
    }

Q_SIGNALS:
    void showAllChanged(bool);

public Q_SLOTS:
    void setShowAll(bool on)
    {
        if (on == m_showAll) {
            return;
        }
        m_showAll = on;
        invalidateFilter();
        Q_EMIT showAllChanged(on);
    }

private:
    bool filterAcceptsRow(int src_row, const QModelIndex &src_parent) const override
    {
        if (m_showAll) {
            return true;
        }
        if (const Model *const model = qobject_cast<Model *>(sourceModel())) {
            if (!src_parent.isValid() && src_row >= 0 && src_row < model->rowCount(src_parent)) {
                if (const std::shared_ptr<SelfTest> &t = model->at(src_row)) {
                    return !t->passed();
                } else {
                    qCWarning(KLEOPATRA_LOG) << "NULL test??";
                }
            } else {
                if (src_parent.isValid()) {
                    qCWarning(KLEOPATRA_LOG) << "view asks for subitems!";
                } else {
                    qCWarning(KLEOPATRA_LOG) << "index " << src_row << " is out of range [" << 0 << "," << model->rowCount(src_parent) << "]";
                }
            }
        } else {
            qCWarning(KLEOPATRA_LOG) << "expected a ::Model, got ";
            if (!sourceModel()) {
                qCWarning(KLEOPATRA_LOG) << "a null pointer";
            } else {
                qCWarning(KLEOPATRA_LOG) << sourceModel()->metaObject()->className();
            }
        }
        return false;
    }

private:
    bool m_showAll;
};
}

class SelfTestDialog::Private
{
    friend class ::Kleo::Dialogs::SelfTestDialog;
    SelfTestDialog *const q;

public:
    explicit Private(SelfTestDialog *qq)
        : q(qq)
        , model(q)
        , proxy(q)
        , ui(q)
    {
        proxy.setSourceModel(&model);
        ui.resultsTV->setModel(&proxy);

        ui.detailsGB->hide();
        ui.proposedCorrectiveActionGB->hide();

        connect(ui.buttonBox, &QDialogButtonBox::accepted, q, &QDialog::accept);
        connect(ui.buttonBox, &QDialogButtonBox::rejected, q, &QDialog::reject);
        connect(ui.doItPB, &QAbstractButton::clicked, q, [this]() {
            slotDoItClicked();
        });
        connect(ui.rerunPB, &QAbstractButton::clicked, q, &SelfTestDialog::updateRequested);
        connect(ui.resultsTV->selectionModel(), &QItemSelectionModel::selectionChanged, q, [this]() {
            slotSelectionChanged();
        });
        connect(ui.showAllCB, &QAbstractButton::toggled, q, [this](bool checked) {
            proxy.setShowAll(checked);
            if (checked) {
                updateColumnSizes();
            }
            ensureCurrentItemIsVisible();
        });
        proxy.setShowAll(ui.showAllCB->isChecked());

        ui.resultsTV->setFocus();
    }

private:
    void slotSelectionChanged()
    {
        const int row = selectedRowIndex();
        if (row < 0) {
            ui.detailsLB->setText(i18n("(select test first)"));
            ui.detailsGB->hide();
            ui.proposedCorrectiveActionGB->hide();
        } else {
            const std::shared_ptr<SelfTest> &t = model.at(row);
            ui.detailsLB->setText(t->longError());
            ui.detailsGB->setVisible(!t->passed());
            const QString action = t->proposedFix();
            ui.proposedCorrectiveActionGB->setVisible(!t->passed() && !action.isEmpty());
            ui.proposedCorrectiveActionLB->setText(action);
            ui.doItPB->setVisible(!t->passed() && t->canFixAutomatically());
            QMetaObject::invokeMethod(
                q,
                [this]() {
                    ensureCurrentItemIsVisible();
                },
                Qt::QueuedConnection);
        }
    }
    void slotDoItClicked()
    {
        if (const std::shared_ptr<SelfTest> st = model.fromModelIndex(selectedRow()))
            if (st->fix()) {
                model.reloadData();
            }
    }

private:
    void ensureCurrentItemIsVisible()
    {
        ui.resultsTV->scrollTo(ui.resultsTV->currentIndex());
    }
    void updateColumnSizes()
    {
        ui.resultsTV->resizeToContentsLimited();
    }

private:
    QModelIndex selectedRow() const
    {
        const QItemSelectionModel *const ism = ui.resultsTV->selectionModel();
        if (!ism) {
            return QModelIndex();
        }
        const QModelIndexList mil = ism->selectedRows();
        return mil.empty() ? QModelIndex() : proxy.mapToSource(mil.front());
    }
    int selectedRowIndex() const
    {
        return selectedRow().row();
    }

private:
    Model model;
    Proxy proxy;

    struct UI {
        TreeView *resultsTV = nullptr;
        QCheckBox *showAllCB = nullptr;
        QGroupBox *detailsGB = nullptr;
        QLabel *detailsLB = nullptr;
        QGroupBox *proposedCorrectiveActionGB = nullptr;
        QLabel *proposedCorrectiveActionLB = nullptr;
        QPushButton *doItPB = nullptr;
        QCheckBox *runAtStartUpCB;
        QDialogButtonBox *buttonBox;
        QPushButton *rerunPB = nullptr;

        LabelHelper labelHelper;

        explicit UI(SelfTestDialog *qq)
        {
            auto mainLayout = new QVBoxLayout{qq};

            {
                auto label = new QLabel{xi18n("<para>These are the results of the Kleopatra self-test suite. Click on a test for details.</para>"
                                              "<para>Note that all but the first failure might be due to prior tests failing.</para>"),
                                        qq};
                label->setWordWrap(true);
                labelHelper.addLabel(label);

                mainLayout->addWidget(label);
            }

            auto splitter = new QSplitter{qq};
            splitter->setOrientation(Qt::Vertical);

            {
                auto widget = new QWidget{qq};
                auto vbox = new QVBoxLayout{widget};
                vbox->setContentsMargins(0, 0, 0, 0);

                resultsTV = new TreeView{qq};
                resultsTV->setAccessibleName(i18n("test results"));
                QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
                sizePolicy.setHorizontalStretch(0);
                sizePolicy.setVerticalStretch(1);
                sizePolicy.setHeightForWidth(resultsTV->sizePolicy().hasHeightForWidth());
                resultsTV->setSizePolicy(sizePolicy);
                resultsTV->setMinimumHeight(100);
                resultsTV->setRootIsDecorated(false);
                resultsTV->setAllColumnsShowFocus(true);
                vbox->addWidget(resultsTV);

                splitter->addWidget(widget);
            }
            {
                detailsGB = new QGroupBox{i18nc("@title:group", "Details"), qq};
                auto groupBoxLayout = new QVBoxLayout{detailsGB};

                auto scrollArea = new Kleo::ScrollArea{qq};
                scrollArea->setFocusPolicy(Qt::NoFocus);
                scrollArea->setMinimumHeight(100);
                scrollArea->setFrameShape(QFrame::NoFrame);
                scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
                auto scrollAreaLayout = qobject_cast<QBoxLayout *>(scrollArea->widget()->layout());

                detailsLB = new QLabel{qq};
                detailsLB->setTextFormat(Qt::RichText);
                detailsLB->setTextInteractionFlags(Qt::TextSelectableByMouse);
                detailsLB->setWordWrap(true);
                labelHelper.addLabel(detailsLB);

                scrollAreaLayout->addWidget(detailsLB);
                scrollAreaLayout->addStretch();

                groupBoxLayout->addWidget(scrollArea);

                splitter->addWidget(detailsGB);
            }
            {
                proposedCorrectiveActionGB = new QGroupBox{i18nc("@title:group", "Proposed Corrective Action"), qq};
                auto groupBoxLayout = new QVBoxLayout{proposedCorrectiveActionGB};

                auto scrollArea = new Kleo::ScrollArea{qq};
                scrollArea->setFocusPolicy(Qt::NoFocus);
                scrollArea->setMinimumHeight(100);
                scrollArea->setFrameShape(QFrame::NoFrame);
                scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
                auto scrollAreaLayout = qobject_cast<QBoxLayout *>(scrollArea->widget()->layout());

                proposedCorrectiveActionLB = new QLabel{qq};
                proposedCorrectiveActionLB->setTextFormat(Qt::RichText);
                proposedCorrectiveActionLB->setTextInteractionFlags(Qt::TextSelectableByMouse);
                proposedCorrectiveActionLB->setWordWrap(true);
                labelHelper.addLabel(proposedCorrectiveActionLB);

                scrollAreaLayout->addWidget(proposedCorrectiveActionLB);
                scrollAreaLayout->addStretch();

                groupBoxLayout->addWidget(scrollArea);

                {
                    auto hbox = new QHBoxLayout;
                    hbox->addStretch();

                    doItPB = new QPushButton{i18nc("@action:button", "Do It"), qq};
                    doItPB->setEnabled(false);
                    hbox->addWidget(doItPB);

                    groupBoxLayout->addLayout(hbox);
                }

                splitter->addWidget(proposedCorrectiveActionGB);
            }

            mainLayout->addWidget(splitter);

            showAllCB = new QCheckBox{i18nc("@option:check", "Show all test results"), qq};
            showAllCB->setChecked(true);
            mainLayout->addWidget(showAllCB);

            runAtStartUpCB = new QCheckBox{i18nc("@option:check", "Run these tests at startup"), qq};
            runAtStartUpCB->setChecked(true);
            mainLayout->addWidget(runAtStartUpCB);

            buttonBox = new QDialogButtonBox{qq};
            buttonBox->setStandardButtons(QDialogButtonBox::Cancel | QDialogButtonBox::Close | QDialogButtonBox::Ok);
            buttonBox->button(QDialogButtonBox::Ok)->setText(i18nc("@action:button", "Continue"));
            rerunPB = buttonBox->addButton(i18nc("@action:button", "Rerun Tests"), QDialogButtonBox::ActionRole);

            mainLayout->addWidget(buttonBox);
        }
    } ui;
};

SelfTestDialog::SelfTestDialog(QWidget *p, Qt::WindowFlags f)
    : QDialog(p, f)
    , d(new Private(this))
{
    setWindowTitle(i18nc("@title:window", "Self Test"));
    resize(448, 610);

    setAutomaticMode(false);
}

SelfTestDialog::~SelfTestDialog() = default;

void SelfTestDialog::setTests(const std::vector<std::shared_ptr<SelfTest>> &tests)
{
    d->model.clear();
    d->model.append(tests);
    d->updateColumnSizes();
}

void SelfTestDialog::setRunAtStartUp(bool on)
{
    d->ui.runAtStartUpCB->setChecked(on);
}

bool SelfTestDialog::runAtStartUp() const
{
    return d->ui.runAtStartUpCB->isChecked();
}

void SelfTestDialog::setAutomaticMode(bool automatic)
{
    d->ui.showAllCB->setChecked(!automatic);
    d->ui.buttonBox->button(QDialogButtonBox::Ok)->setVisible(automatic);
    d->ui.buttonBox->button(QDialogButtonBox::Cancel)->setVisible(automatic);
    d->ui.buttonBox->button(QDialogButtonBox::Close)->setVisible(!automatic);
}

#include "moc_selftestdialog.cpp"
#include "selftestdialog.moc"
