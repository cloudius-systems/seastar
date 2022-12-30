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
 * Copyright (C) 2015 Cloudius Systems, Ltd.
 */

#include <boost/test/tools/old/interface.hpp>
#include <seastar/core/thread.hh>
#include <seastar/core/do_with.hh>
#include <seastar/testing/test_case.hh>
#include <seastar/testing/thread_test_case.hh>
#include <seastar/core/sstring.hh>
#include <seastar/core/condition-variable.hh>
#include <seastar/core/do_with.hh>
#include <seastar/core/loop.hh>
#include <seastar/core/map_reduce.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/shared_mutex.hh>
#include <seastar/core/when_all.hh>
#include <seastar/core/when_any.hh>
#include <seastar/core/with_timeout.hh>
#include <boost/range/irange.hpp>

using namespace seastar;
using namespace std::chrono_literals;
using steady_clock = std::chrono::steady_clock;

SEASTAR_THREAD_TEST_CASE(test_condition_variable_signal_consume) {
    condition_variable cv;

    cv.signal();
    auto f = cv.wait();

    BOOST_REQUIRE_EQUAL(f.available(), true);
    f.get();

    auto f2 = cv.wait();

    BOOST_REQUIRE_EQUAL(f2.available(), false);

    cv.signal();

    with_timeout(steady_clock::now() + 10ms, std::move(f2)).get();

    std::vector<future<>> waiters;
    waiters.emplace_back(cv.wait());
    waiters.emplace_back(cv.wait());
    waiters.emplace_back(cv.wait());

    BOOST_REQUIRE_EQUAL(std::count_if(waiters.begin(), waiters.end(), std::mem_fn(&future<>::available)), 0u);

    cv.signal();

    BOOST_REQUIRE_EQUAL(std::count_if(waiters.begin(), waiters.end(), std::mem_fn(&future<>::available)), 1u);
    // FIFO
    BOOST_REQUIRE_EQUAL(waiters.front().available(), true);

    cv.broadcast();

    BOOST_REQUIRE_EQUAL(std::count_if(waiters.begin(), waiters.end(), std::mem_fn(&future<>::available)), 3u);
}

SEASTAR_THREAD_TEST_CASE(test_condition_variable_pred) {
    condition_variable cv;
    bool ready = false;

    try {
        cv.wait(100ms, [&] { return ready; }).get();
        BOOST_FAIL("should not reach");
    } catch (condition_variable_timed_out&) {
        // ok
    } catch (...) {
        BOOST_FAIL("should not reach");
    }
    // should not affect outcome.
    cv.signal();
    
    try {
        cv.wait(100ms, [&] { return ready; }).get();
        BOOST_FAIL("should not reach");
    } catch (condition_variable_timed_out&) {
        // ok
    } catch (...) {
        BOOST_FAIL("should not reach");
    }

}

SEASTAR_THREAD_TEST_CASE(test_condition_variable_signal_break) {
    condition_variable cv;

    std::vector<future<>> waiters;
    waiters.emplace_back(cv.wait());
    waiters.emplace_back(cv.wait());
    waiters.emplace_back(cv.wait());

    BOOST_REQUIRE_EQUAL(std::count_if(waiters.begin(), waiters.end(), std::mem_fn(&future<>::available)), 0u);

    cv.broken();

    for (auto& f : waiters) {
        try {
            f.get();
        } catch (broken_condition_variable&) {
            // ok
            continue;
        }
        BOOST_FAIL("should not reach");
    }

    try {
        auto f = cv.wait();
        f.get();
        BOOST_FAIL("should not reach");
    } catch (broken_condition_variable&) {
        // ok
    } catch (...) {
        BOOST_FAIL("should not reach");
    }
}

SEASTAR_THREAD_TEST_CASE(test_condition_variable_timeout) {
    condition_variable cv;

    auto f = cv.wait(100ms);
    BOOST_REQUIRE_EQUAL(f.available(), false);

    sleep(200ms).get();
    BOOST_REQUIRE_EQUAL(f.available(), true);

    try {
        f.get();
        BOOST_FAIL("should not reach");
    } catch (condition_variable_timed_out&) {
        // ok
    } catch (...) {
        BOOST_FAIL("should not reach");
    }
}

SEASTAR_THREAD_TEST_CASE(test_condition_variable_pred_wait) {
    condition_variable cv;

    bool ready = false;

    timer<> t;
    t.set_callback([&] { ready = true; cv.signal(); });
    t.arm(100ms);

    cv.wait([&] { return ready; }).get();

    ready = false;

    try {
        cv.wait(10ms, [&] { return ready; }).get();
        BOOST_FAIL("should not reach");
    } catch (timed_out_error&) {
        BOOST_FAIL("should not reach");
    } catch (condition_variable_timed_out&) {
        // ok
    } catch (...) {
        BOOST_FAIL("should not reach");
    }

    ready = true;
    cv.signal();

    cv.wait(10ms, [&] { return ready; }).get();

    for (int i = 0; i < 2; ++i) {
        ready = false;
        t.set_callback([&] { cv.broadcast();});
        t.arm_periodic(10ms);

        try {
            cv.wait(300ms, [&] { return ready; }).get();
            BOOST_FAIL("should not reach");
        } catch (timed_out_error&) {
            BOOST_FAIL("should not reach");
        } catch (condition_variable_timed_out&) {
            // ok
        } catch (...) {
            BOOST_FAIL("should not reach");
        }
        t.cancel();
        cv.signal();
    }

    ready = true;
    cv.signal();

    cv.wait([&] { return ready; }).get();
    // signal state should remain on
    cv.wait().get();
}

SEASTAR_THREAD_TEST_CASE(test_condition_variable_has_waiter) {
    condition_variable cv;

    BOOST_REQUIRE_EQUAL(cv.has_waiters(), false);

    auto f = cv.wait();
    BOOST_REQUIRE_EQUAL(cv.has_waiters(), true);

    cv.signal();
    f.get();
    BOOST_REQUIRE_EQUAL(cv.has_waiters(), false);
}

SEASTAR_THREAD_TEST_CASE(test_condition_variable_abort) {
    condition_variable cv;
    abort_source as;

    std::vector<future<>> waiters;
    waiters.emplace_back(cv.wait());
    waiters.emplace_back(cv.wait(as));
    waiters.emplace_back(cv.wait());

    BOOST_REQUIRE_EQUAL(std::count_if(waiters.begin(), waiters.end(), std::mem_fn(&future<>::available)), 0u);

    as.request_abort();

    BOOST_REQUIRE_EQUAL(waiters[0].available(), false);
    BOOST_REQUIRE_EQUAL(waiters[1].failed(), true);
    BOOST_REQUIRE_EQUAL(waiters[2].available(), false);

    cv.broadcast();

    BOOST_REQUIRE_NO_THROW(waiters[0].get());
    BOOST_REQUIRE_THROW(waiters[1].get(), abort_requested_exception);
    BOOST_REQUIRE_NO_THROW(waiters[2].get());

    condition_variable cv2;
    BOOST_REQUIRE_THROW(cv2.wait(as).get(), abort_requested_exception);
}

SEASTAR_THREAD_TEST_CASE(test_condition_variable_timeout_abort) {
    condition_variable cv;
    auto aoe = abort_on_expiry<lowres_clock>(lowres_clock::now() + 1s);
    abort_source& as = aoe.abort_source();

    auto f = cv.wait(as);
    BOOST_REQUIRE_EQUAL(f.available(), false);

    as.request_abort();
    BOOST_REQUIRE_THROW(f.get(), abort_requested_exception);

    condition_variable cv2;
    BOOST_REQUIRE_THROW(cv2.wait(as).get(), abort_requested_exception);
}

SEASTAR_THREAD_TEST_CASE(test_condition_variable_pred_wait_abort) {
    condition_variable cv;
    abort_source as;

    bool ready = false;

    auto f = cv.wait(as, [&] { return ready; });
    BOOST_REQUIRE_EQUAL(f.available(), false);

    as.request_abort();
    BOOST_REQUIRE_THROW(f.get(), abort_requested_exception);

    condition_variable cv2;
    BOOST_REQUIRE_THROW(cv2.wait(as, [&] { return ready; }).get(), abort_requested_exception);
}

#ifdef SEASTAR_COROUTINES_ENABLED

SEASTAR_TEST_CASE(test_condition_variable_signal_consume_coroutine) {
    condition_variable cv;

    cv.signal();
    co_await with_timeout(steady_clock::now() + 10ms, [&]() -> future<> {
        co_await cv.when();
    }());

    try {
        co_await with_timeout(steady_clock::now() + 10ms, [&]() -> future<> {
            co_await cv.when();
        }());
        BOOST_FAIL("should not reach");
    } catch (condition_variable_timed_out&) {
        BOOST_FAIL("should not reach");
    } catch (timed_out_error&) {
        // ok
    } catch (...) {
        BOOST_FAIL("should not reach");
    }

    try {
        co_await with_timeout(steady_clock::now() + 10s, [&]() -> future<> {
            co_await cv.when(100ms);
        }());
        BOOST_FAIL("should not reach");
    } catch (timed_out_error&) {
        BOOST_FAIL("should not reach");
    } catch (condition_variable_timed_out&) {
        // ok
    } catch (...) {
        BOOST_FAIL("should not reach");
    }

}

SEASTAR_TEST_CASE(test_condition_variable_pred_when) {
    condition_variable cv;

    bool ready = false;

    timer<> t;
    t.set_callback([&] { ready = true; cv.signal(); });
    t.arm(100ms);

    co_await cv.when([&] { return ready; });

    ready = false;

    try {
        co_await cv.when(10ms, [&] { return ready; });
        BOOST_FAIL("should not reach");
    } catch (timed_out_error&) {
        BOOST_FAIL("should not reach");
    } catch (condition_variable_timed_out&) {
        // ok
    } catch (...) {
        BOOST_FAIL("should not reach");
    }

    ready = true;
    cv.signal();

    co_await cv.when(10ms, [&] { return ready; });

    for (int i = 0; i < 2; ++i) {
        ready = false;
        t.set_callback([&] { cv.broadcast();});
        t.arm_periodic(10ms);

        try {
            co_await cv.when(300ms, [&] { return ready; });
            BOOST_FAIL("should not reach");
        } catch (timed_out_error&) {
            BOOST_FAIL("should not reach");
        } catch (condition_variable_timed_out&) {
            // ok
        } catch (...) {
            BOOST_FAIL("should not reach");
        }
        t.cancel();
        cv.signal();
    }

    ready = true;
    cv.signal();

    co_await cv.when([&] { return ready; });
    // signal state should remain on
    co_await cv.when();
}



SEASTAR_TEST_CASE(test_condition_variable_when_signal) {
    condition_variable cv;

    bool ready = false;

    timer<> t;
    t.set_callback([&] { cv.signal(); ready = true; });
    t.arm(100ms);

    co_await cv.when();
    // ensure we did not resume before timer ran fully
    BOOST_REQUIRE_EQUAL(ready, true);
}

SEASTAR_TEST_CASE(test_condition_variable_when_timeout) {
    condition_variable cv;

    bool ready = false;

    // create "background" fiber
    auto f = [&]() -> future<> {
        try {
            co_await cv.when(100ms, [&] { return ready; });
        } catch (timed_out_error&) {
            BOOST_FAIL("should not reach");
        } catch (condition_variable_timed_out&) {
            BOOST_FAIL("should not reach");
        } catch (...) {
            BOOST_FAIL("should not reach");
        }
    }();

    // ensure we wake up waiter before timeuot
    ready = true;
    cv.signal();

    // now busy-spin until the timer should be expired
    while (cv.has_waiters()) {
    }

    // he should not have run yet...
    BOOST_REQUIRE_EQUAL(f.available(), false);
    // now, if the code is broken, the timer will run once we switch out,
    // and cause the wait to time out, even though it did not. -> assert

    co_await std::move(f);
}

SEASTAR_TEST_CASE(test_condition_variable_abort_when) {
    condition_variable cv;
    abort_source as;

    timer<> default_timer;
    default_timer.set_callback([&] {
        BOOST_TEST_MESSAGE("default timer expired");
        cv.broken();
    });
    default_timer.arm(100ms);

    timer<> abort_timer;
    abort_timer.set_callback([&] { as.request_abort(); });
    abort_timer.arm(10ms);

    BOOST_REQUIRE_THROW(co_await cv.when(as), abort_requested_exception);

    condition_variable cv2;
    default_timer.cancel();
    default_timer.set_callback([&] {
        BOOST_TEST_MESSAGE("default timer expired");
        cv2.broken();
    });
    default_timer.arm(100ms);

    BOOST_REQUIRE_THROW(co_await cv2.when(as), abort_requested_exception);
}

SEASTAR_TEST_CASE(test_condition_variable_abort_when_timeout) {
    condition_variable cv;
    auto aoe = abort_on_expiry<lowres_clock>(lowres_clock::now() + 1s);
    abort_source& as = aoe.abort_source();

    auto tmr = timer<lowres_clock>([&as] {
        as.request_abort_ex(std::runtime_error("expired"));
    });
    tmr.arm(10ms);

    BOOST_REQUIRE_THROW(co_await cv.when(as), std::runtime_error);

    condition_variable cv2;
    BOOST_REQUIRE_THROW(co_await cv2.when(as), std::runtime_error);
}

SEASTAR_TEST_CASE(test_condition_variable_abort_when_pred) {
    condition_variable cv;
    abort_source as;

    timer<> default_timer;
    default_timer.set_callback([&] { cv.broken(); });
    default_timer.arm(100ms);

    timer<> abort_timer;
    abort_timer.set_callback([&] { as.request_abort(); });
    abort_timer.arm(10ms);

    bool ready = false;
    BOOST_REQUIRE_THROW(co_await cv.when(as, [&] { return ready; }), abort_requested_exception);

    condition_variable cv2;
    BOOST_REQUIRE_THROW(co_await cv2.when(as, [&] { return ready; }), abort_requested_exception);
}

#endif
