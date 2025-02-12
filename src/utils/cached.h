/*
    This file is part of Kleopatra, the KDE keymanager
    SPDX-FileCopyrightText: 2009 Klarälvdalens Datakonsult AB

    SPDX-License-Identifier: GPL-2.0-or-later
*/

#pragma once

#include <type_traits>

namespace Kleo
{

template<typename T>
class cached
{
    T m_value;
    bool m_dirty;

    using CallType = const typename std::conditional<std::is_standard_layout<T>::value && std::is_trivial<T>::value, T, T &>::type;

public:
    cached()
        : m_value()
        , m_dirty(true)
    {
    }
    /* implicit */ cached(const CallType value)
        : m_value(value)
        , m_dirty(false)
    {
    }

    operator T() const
    {
        return m_value;
    }

    cached &operator=(T value)
    {
        m_value = value;
        m_dirty = false;
        return *this;
    }

    bool dirty() const
    {
        return m_dirty;
    }

    T value() const
    {
        return m_value;
    }

    void set_dirty()
    {
        m_dirty = true;
    }
};

}
