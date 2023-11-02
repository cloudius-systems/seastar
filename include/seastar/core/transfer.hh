/*
 * This file is open source software, licensed to you under the terms
 * of the Apache License, Version 2.0 (the "License").  See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership.  You may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/*
 * Copyright (C) 2014 Cloudius Systems, Ltd.
 */

#pragma once

// Helper functions for copying or moving multiple objects in an exception
// safe manner, then destroying the sources.
//
// To transfer, call transfer_pass1(allocator, &from, &to) on all object pairs,
// (this copies the object from @from to @to).  If no exceptions are encountered,
// call transfer_pass2(allocator, &from, &to).  This destroys the object at the
// origin.  If exceptions were encountered, simply destroy all copied objects.
//
// As an optimization, if the objects are moveable without throwing (noexcept)
// transfer_pass1() simply moves the objects and destroys the source, and
// transfer_pass2() does nothing.

#ifndef SEASTAR_MODULE
#include <memory>
#include <type_traits>
#include <utility>
#include <seastar/util/modules.hh>
#endif

namespace seastar {
SEASTAR_MODULE_EXPORT_BEGIN

template <typename T, typename Alloc>
inline
void
transfer_pass1(Alloc& a, T* from, T* to,
        std::enable_if_t<std::is_nothrow_move_constructible_v<T>>* = nullptr) {
    std::allocator_traits<Alloc>::construct(a, to, std::move(*from));
    std::allocator_traits<Alloc>::destroy(a, from);
}

template <typename T, typename Alloc>
inline
void
transfer_pass2(Alloc&, T*, T*,
        std::enable_if_t<std::is_nothrow_move_constructible_v<T>>* = nullptr) {
}

template <typename T, typename Alloc>
inline
void
transfer_pass1(Alloc& a, T* from, T* to,
        std::enable_if_t<!std::is_nothrow_move_constructible_v<T>>* = nullptr) {
    std::allocator_traits<Alloc>::construct(a, to, *from);
}

template <typename T, typename Alloc>
inline
void
transfer_pass2(Alloc& a, T* from, T*,
        std::enable_if_t<!std::is_nothrow_move_constructible_v<T>>* = nullptr) {
    std::allocator_traits<Alloc>::destroy(a, from);
}
SEASTAR_MODULE_EXPORT_END
}

