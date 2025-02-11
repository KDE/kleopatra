/* -*- mode: c++; c-basic-offset:4 -*-
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2008 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#include <config-kleopatra.h>

#include "headerview.h"

#include <algorithm>
#include <numeric>

#include "kleopatra_debug.h"

// #define ENABLE_HEADERVIEW_DEBUG

#ifdef ENABLE_HEADERVIEW_DEBUG
#define hvDebug qDebug
#else
#define hvDebug                                                                                                                                                \
    if (true) {                                                                                                                                                \
    } else                                                                                                                                                     \
        qDebug
#endif

using namespace Kleo;

static std::vector<int> section_sizes(const QHeaderView *view)
{
    Q_ASSERT(view);
    std::vector<int> result;
    result.reserve(view->count());
    for (int i = 0, end = view->count(); i != end; ++i) {
        result.push_back(view->sectionSize(i));
    }
    return result;
}

static void apply_section_sizes(QHeaderView *view, const std::vector<int> &newSizes)
{
    Q_ASSERT(view);
    for (unsigned int i = 0, end = newSizes.size(); i != end; ++i) {
        view->resizeSection(i, newSizes[i]);
    }
}

namespace
{

template<typename T_container>
inline typename T_container::value_type lookup(const T_container &c, unsigned int i, const typename T_container::value_type &defaultValue)
{
    return i < c.size() ? c[i] : defaultValue;
}

}

class HeaderView::Private
{
    friend class ::Kleo::HeaderView;
    HeaderView *const q;

public:
    Private(HeaderView *qq)
        : q(qq)
        , mousePressed(false)
        , sizes()
    {
        connect(q, &QHeaderView::sectionCountChanged, q, [this](int oldCount, int newCount) {
            _klhv_slotSectionCountChanged(oldCount, newCount);
        });
        connect(q, &QHeaderView::sectionResized, q, [this](int idx, int oldSize, int newSize) {
            _klhv_slotSectionResized(idx, oldSize, newSize);
        });
    }

    void _klhv_slotSectionCountChanged(int oldCount, int newCount)
    {
        if (newCount == oldCount) {
            return;
        }
        hvDebug() << oldCount << "->" << newCount;
        if (newCount < oldCount) {
            return;
        }
        ensureNumSections(newCount);
        apply_section_sizes(q, sizes);
    }

    void _klhv_slotSectionResized(int idx, int oldSize, int newSize)
    {
        hvDebug() << idx << ':' << oldSize << "->" << newSize;
        ensureNumSections(idx + 1);
        sizes[idx] = newSize;
    }

    void ensureNumSections(unsigned int num)
    {
        if (num > sizes.size()) {
            sizes.resize(num, q->defaultSectionSize());
        }
    }

    bool mousePressed : 1;
    std::vector<int> sizes;
};

HeaderView::HeaderView(Qt::Orientation o, QWidget *p)
    : QHeaderView(o, p)
    , d(new Private(this))
{
}

HeaderView::~HeaderView()
{
}

void HeaderView::setSectionSizes(const std::vector<int> &sizes)
{
    hvDebug() << sizes;
    d->ensureNumSections(sizes.size());
    d->sizes = sizes;
    apply_section_sizes(this, sizes);
    hvDebug() << "->" << sectionSizes();
}

std::vector<int> HeaderView::sectionSizes() const
{
    return section_sizes(this);
}

#include "moc_headerview.cpp"
