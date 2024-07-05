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
 * Copyright 2024 ScyllaDB
 */

#ifdef SEASTAR_MODULE
module;
#endif

#include <seastar/core/internal/throttle.hh>

namespace seastar {

shared_throttle::shared_throttle(config cfg, unsigned nr_queues)
        : _token_bucket(fixed_point_factor,
                        std::max<capacity_t>(fixed_point_factor * token_bucket_t::rate_cast(cfg.rate_limit_duration).count(), tokens_capacity(cfg.limit_min_tokens)),
                        tokens_capacity(cfg.min_tokens)
                       )
        , _per_tick_threshold(_token_bucket.limit() / nr_queues)
{
    if (tokens_capacity(cfg.min_tokens) > _token_bucket.threshold()) {
        throw std::runtime_error("Fair-group replenisher limit is lower than threshold");
    }
}

auto shared_throttle::grab_capacity(capacity_t cap) noexcept -> capacity_t {
    assert(cap <= _token_bucket.limit());
    return _token_bucket.grab(cap);
}

void shared_throttle::replenish_capacity(clock_type::time_point now) noexcept {
    _token_bucket.replenish(now);
}

void shared_throttle::maybe_replenish_capacity(clock_type::time_point& local_ts) noexcept {
    auto now = clock_type::now();
    auto extra = _token_bucket.accumulated_in(now - local_ts);

    if (extra >= _token_bucket.threshold()) {
        local_ts = now;
        replenish_capacity(now);
    }
}

auto shared_throttle::capacity_deficiency(capacity_t from) const noexcept -> capacity_t {
    return _token_bucket.deficiency(from);
}


} // seastar namespace
