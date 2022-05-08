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
 * Copyright (C) 2022-present ScyllaDB Ltd.
 */

#include <deque>

#include <seastar/testing/test_case.hh>
#include <seastar/testing/random.hh>

#include <seastar/util/chunked_deque.hh>

using namespace seastar;

SEASTAR_TEST_CASE(chunked_deque_small) {
    // Check all the methods of chunked_deq but with a trivial type (int) and
    // only a few elements - and in particular a single chunk is enough.
    chunked_deque<int> deq;
    BOOST_REQUIRE_EQUAL(deq.size(), 0u);
    BOOST_REQUIRE_EQUAL(deq.empty(), true);
    deq.push_back(1);
    BOOST_REQUIRE_EQUAL(deq.size(), 1u);
    BOOST_REQUIRE_EQUAL(deq.empty(), false);
    BOOST_REQUIRE_EQUAL(deq.front(), 1);
    BOOST_REQUIRE_EQUAL(deq.back(), 1);
    deq.push_front(2);
    BOOST_REQUIRE_EQUAL(deq.size(), 2u);
    BOOST_REQUIRE_EQUAL(deq.empty(), false);
    BOOST_REQUIRE_EQUAL(deq.front(), 2);
    BOOST_REQUIRE_EQUAL(deq.back(), 1);
    deq.push_back(3);
    BOOST_REQUIRE_EQUAL(deq.size(), 3u);
    BOOST_REQUIRE_EQUAL(deq.empty(), false);
    BOOST_REQUIRE_EQUAL(deq.front(), 2);
    BOOST_REQUIRE_EQUAL(deq.back(), 3);
    deq.pop_front();
    BOOST_REQUIRE_EQUAL(deq.size(), 2u);
    BOOST_REQUIRE_EQUAL(deq.empty(), false);
    BOOST_REQUIRE_EQUAL(deq.front(), 1);
    BOOST_REQUIRE_EQUAL(deq.back(), 3);
    deq.pop_back();
    BOOST_REQUIRE_EQUAL(deq.size(), 1u);
    BOOST_REQUIRE_EQUAL(deq.empty(), false);
    BOOST_REQUIRE_EQUAL(deq.front(), 1);
    BOOST_REQUIRE_EQUAL(deq.back(), 1);
    deq.pop_front();
    BOOST_REQUIRE_EQUAL(deq.size(), 0u);
    BOOST_REQUIRE_EQUAL(deq.empty(), true);
    // The previously allocated chunk should have been freed, and now
    // a new one will need to be allocated:
    deq.push_back(57);
    BOOST_REQUIRE_EQUAL(deq.size(), 1u);
    BOOST_REQUIRE_EQUAL(deq.empty(), false);
    BOOST_REQUIRE_EQUAL(deq.front(), 57);
    BOOST_REQUIRE_EQUAL(deq.back(), 57);
    // check miscelleneous methods (at least they shouldn't crash)
    deq.clear();
    deq.shrink_to_fit();
    deq.reserve_front(1);
    deq.reserve_back(1);
    deq.reserve_front(10);
    deq.reserve_back(10);
    deq.reserve_front(1000);
    deq.reserve_back(1000);
    deq.shrink_to_fit();
    deq.reserve_back(1000);
    deq.reserve_front(1000);

    return make_ready_future<>();
}

SEASTAR_TEST_CASE(chunked_deque_random_push_pop) {
    auto& eng = testing::local_random_engine;
    auto dist = std::uniform_int_distribution<int>();
    size_t count = 10 + dist(eng) % 990;
    std::deque<int> ref;
    chunked_deque<int> deq;

    auto push_front = [&] (int val) {
        deq.push_front(val);
        ref.push_front(val);
    };
    auto push_back = [&] (int val) {
        deq.push_back(val);
        ref.push_back(val);
    };
    auto pop_front = [&] () {
        if (!deq.empty()) {
            deq.pop_front();
            ref.pop_front();
        }
    };
    auto pop_back = [&] () {
        if (!deq.empty()) {
            deq.pop_back();
            ref.pop_back();
        }
    };

    while (count--) {
        switch (dist(eng) % 4) {
        case 0:
            push_front(dist(eng));
            break;
        case 1:
            pop_front();
            break;
        case 2:
            push_back(dist(eng));
            break;
        case 3:
            pop_back();
            break;
        }

        BOOST_REQUIRE_EQUAL(deq.size(), ref.size());
        if (!deq.empty() || ref.empty()) {
            BOOST_REQUIRE_EQUAL(deq.empty(), ref.empty());
        } else {
            BOOST_REQUIRE_EQUAL(deq.front(), ref.front());
            BOOST_REQUIRE_EQUAL(deq.back(), ref.back());
        }
    }

    {
        auto dit = deq.begin();
        auto rit = ref.begin();
        while (dit != deq.end()) {
            BOOST_REQUIRE_EQUAL(*dit++, *rit++);
        }
        BOOST_REQUIRE(rit == ref.end());
        if (!deq.empty()) {
            do {
                BOOST_REQUIRE_EQUAL(*--dit, *--rit);
            } while (dit != deq.begin());
            BOOST_REQUIRE(rit == ref.begin());
        }
    }

    {
        auto dit = deq.cbegin();
        auto rit = ref.cbegin();
        while (dit != deq.cend()) {
            BOOST_REQUIRE_EQUAL(*dit++, *rit++);
        }
        BOOST_REQUIRE(rit == ref.cend());
        if (!deq.empty()) {
            do {
                BOOST_REQUIRE_EQUAL(*--dit, *--rit);
            } while (dit != deq.cbegin());
            BOOST_REQUIRE(rit == ref.cbegin());
        }
    }

    {
        auto dit = deq.rbegin();
        auto rit = ref.rbegin();
        while (dit != deq.rend()) {
            BOOST_REQUIRE_EQUAL(*dit++, *rit++);
        }
        BOOST_REQUIRE(rit == ref.rend());
        if (!deq.empty()) {
            do {
                BOOST_REQUIRE_EQUAL(*--dit, *--rit);
            } while (dit != deq.rbegin());
            BOOST_REQUIRE(rit == ref.rbegin());
        }
    }

    {
        auto dit = deq.crbegin();
        auto rit = ref.crbegin();
        while (dit != deq.crend()) {
            BOOST_REQUIRE_EQUAL(*dit++, *rit++);
        }
        BOOST_REQUIRE(rit == ref.crend());
        if (!deq.empty()) {
            do {
                BOOST_REQUIRE_EQUAL(*--dit, *--rit);
            } while (dit != deq.crbegin());
            BOOST_REQUIRE(rit == ref.crbegin());
        }
    }

    return make_ready_future<>();
}

SEASTAR_TEST_CASE(chunked_deque_constructor) {
    auto& eng = testing::local_random_engine;
    auto dist = std::uniform_int_distribution<int>();

    // Check that chunked_deque appropriately calls the type's constructor
    // and destructor, and doesn't need anything else.
    struct typ {
        int val;
        unsigned* constructed;
        unsigned* destructed;
        typ(int val, unsigned* constructed, unsigned* destructed)
            : val(val), constructed(constructed), destructed(destructed) {
                ++*constructed;
        }
        ~typ() { ++*destructed; }
    };
    unsigned constructed = 0, destructed = 0;
    constexpr unsigned N = 1000;
    chunked_deque<typ> deq;
    for (unsigned i = 0; i < N; i++) {
        BOOST_REQUIRE_EQUAL(deq.size(), i);
        if (dist(eng) & 1) {
            deq.emplace_front(i, &constructed, &destructed);
        } else {
            deq.emplace_back(i, &constructed, &destructed);
        }
    }
    BOOST_REQUIRE_EQUAL(deq.size(), N);
    BOOST_REQUIRE_EQUAL(constructed, N);
    BOOST_REQUIRE_EQUAL(destructed, 0u);
    for (unsigned i = 0 ; i < N; i++) {
        BOOST_REQUIRE_EQUAL(deq.size(), N-i);
        if (dist(eng) & 1) {
            deq.pop_front();
        } else {
            deq.pop_back();
        }
        BOOST_REQUIRE_EQUAL(destructed, i+1);
    }
    BOOST_REQUIRE_EQUAL(deq.size(), 0u);
    BOOST_REQUIRE_EQUAL(deq.empty(), true);
    // Check that destructing a deq also destructs the objects it still
    // contains
    constructed = destructed = 0;
    {
        chunked_deque<typ> deq;
        for (unsigned i = 0; i < N; i++) {
            if (dist(eng) & 1) {
                deq.emplace_front(i, &constructed, &destructed);
            } else {
                deq.emplace_back(i, &constructed, &destructed);
            }
            BOOST_REQUIRE_EQUAL(deq.size(), i+1);
            BOOST_REQUIRE_EQUAL(deq.empty(), false);
            BOOST_REQUIRE_EQUAL(constructed, i+1);
            BOOST_REQUIRE_EQUAL(destructed, 0u);
        }
    }
    BOOST_REQUIRE_EQUAL(constructed, N);
    BOOST_REQUIRE_EQUAL(destructed, N);

    return make_ready_future<>();
}

SEASTAR_TEST_CASE(chunked_deque_construct_fail) {
    // Check that if we fail to construct the item pushed, the queue remains
    // empty.
    class my_exception {};
    struct typ {
        typ() {
            throw my_exception();
        }
    };
    chunked_deque<typ> deq;
    BOOST_REQUIRE_EQUAL(deq.size(), 0u);
    BOOST_REQUIRE_EQUAL(deq.empty(), true);
    try {
        deq.emplace_back();
    } catch(my_exception) {
        // expected, ignore
    }
    try {
        deq.emplace_front();
    } catch(my_exception) {
        // expected, ignore
    }
    BOOST_REQUIRE_EQUAL(deq.size(), 0u);
    BOOST_REQUIRE_EQUAL(deq.empty(), true);

    return make_ready_future<>();
}

SEASTAR_TEST_CASE(chunked_deque_construct_fail2) {
    // A slightly more elaborate test, with a chunk size of 2
    // items, and the third addition failing, so the question is
    // not whether empty() is wrong immediately, but whether after
    // we pop the two items, it will become true or we'll be left
    // with an empty chunk.
    class my_exception {};
    struct typ {
        typ(bool fail) {
            if (fail) {
                throw my_exception();
            }
        }
    };
    chunked_deque<typ, 2> deq;
    BOOST_REQUIRE_EQUAL(deq.size(), 0u);
    BOOST_REQUIRE_EQUAL(deq.empty(), true);

    deq.emplace_back(false);
    deq.emplace_back(false);
    try {
        deq.emplace_back(true);
    } catch(my_exception) {
        // expected, ignore
    }
    BOOST_REQUIRE_EQUAL(deq.size(), 2u);
    BOOST_REQUIRE_EQUAL(deq.empty(), false);
    deq.pop_front();
    BOOST_REQUIRE_EQUAL(deq.size(), 1u);
    BOOST_REQUIRE_EQUAL(deq.empty(), false);
    deq.pop_front();
    BOOST_REQUIRE_EQUAL(deq.size(), 0u);
    BOOST_REQUIRE_EQUAL(deq.empty(), true);

    deq.emplace_front(false);
    deq.emplace_front(false);
    try {
        deq.emplace_front(true);
    } catch(my_exception) {
        // expected, ignore
    }
    BOOST_REQUIRE_EQUAL(deq.size(), 2u);
    BOOST_REQUIRE_EQUAL(deq.empty(), false);
    deq.pop_back();
    BOOST_REQUIRE_EQUAL(deq.size(), 1u);
    BOOST_REQUIRE_EQUAL(deq.empty(), false);
    deq.pop_back();
    BOOST_REQUIRE_EQUAL(deq.size(), 0u);
    BOOST_REQUIRE_EQUAL(deq.empty(), true);

    return make_ready_future<>();
}
