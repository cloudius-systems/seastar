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

#include <fmt/core.h>
#if FMT_VERSION >= 60000
#include <fmt/chrono.h>
#elif FMT_VERSION >= 50000
#include <fmt/time.h>
#endif

#include <seastar/util/log.hh>
#include <seastar/core/smp.hh>
#include <seastar/util/log-cli.hh>

#include <seastar/core/array_map.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/future.hh>
#include <seastar/core/print.hh>

#include <boost/any.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/range/adaptor/map.hpp>
#include <cxxabi.h>
#include <syslog.h>

#include <iostream>
#include <map>
#include <regex>
#include <string>
#include <system_error>
#include <chrono>

#include "core/program_options.hh"

using namespace std::chrono_literals;

namespace seastar {

namespace internal {

void log_buf::free_buffer() noexcept {
    if (_own_buf) {
        delete[] _begin;
    }
}

void log_buf::realloc_buffer() {
    const auto old_size = size();
    const auto new_size = old_size * 2;

    auto new_buf = new char[new_size];
    std::memcpy(new_buf, _begin, old_size);
    free_buffer();

    _begin = new_buf;
    _current = _begin + old_size;
    _end = _begin + new_size;
    _own_buf = true;
}

log_buf::log_buf()
    : _begin(new char[512])
    , _end(_begin + 512)
    , _current(_begin)
    , _own_buf(true)
{
}

log_buf::log_buf(char* external_buf, size_t size) noexcept
    : _begin(external_buf)
    , _end(_begin + size)
    , _current(_begin)
    , _own_buf(false)
{
}

log_buf::~log_buf() {
    free_buffer();
}

} // namespace internal

thread_local uint64_t logging_failures = 0;

void validate(boost::any& v,
              const std::vector<std::string>& values,
              logger_timestamp_style* target_type, int) {
    using namespace boost::program_options;
    validators::check_first_occurrence(v);
    auto s = validators::get_single_string(values);
    if (s == "none") {
        v = logger_timestamp_style::none;
        return;
    } else if (s == "boot") {
        v = logger_timestamp_style::boot;
        return;
    } else if (s == "real") {
        v = logger_timestamp_style::real;
        return;
    }
    throw validation_error(validation_error::invalid_option_value);
}

std::ostream& operator<<(std::ostream& os, logger_timestamp_style lts) {
    switch (lts) {
    case logger_timestamp_style::none: return os << "none";
    case logger_timestamp_style::boot: return os << "boot";
    case logger_timestamp_style::real: return os << "real";
    default: abort();
    }
    return os;
}

void validate(boost::any& v,
              const std::vector<std::string>& values,
              logger_ostream_type* target_type, int) {
    using namespace boost::program_options;
    validators::check_first_occurrence(v);
    auto s = validators::get_single_string(values);
    if (s == "none") {
        v = logger_ostream_type::none;
        return;
    } else if (s == "stdout") {
        v = logger_ostream_type::stdout;
        return;
    } else if (s == "stderr") {
        v = logger_ostream_type::stderr;
        return;
    }
    throw validation_error(validation_error::invalid_option_value);
}

std::ostream& operator<<(std::ostream& os, logger_ostream_type lot) {
    switch (lot) {
    case logger_ostream_type::none: return os << "none";
    case logger_ostream_type::stdout: return os << "stdout";
    case logger_ostream_type::stderr: return os << "stderr";
    default: abort();
    }
    return os;
}

static internal::log_buf::inserter_iterator print_no_timestamp(internal::log_buf::inserter_iterator it) {
    return it;
}

static internal::log_buf::inserter_iterator print_boot_timestamp(internal::log_buf::inserter_iterator it) {
    auto n = std::chrono::steady_clock::now().time_since_epoch() / 1us;
    return fmt::format_to(it, "{:10d}.{:06d}", n / 1000000, n % 1000000);
}

static internal::log_buf::inserter_iterator print_real_timestamp(internal::log_buf::inserter_iterator it) {
    struct a_second {
        time_t t;
        std::string s;
    };
    static thread_local a_second this_second;
    using clock = std::chrono::system_clock;
    auto n = clock::now();
    auto t = clock::to_time_t(n);
    if (this_second.t != t) {
        this_second.s = fmt::format("{:%Y-%m-%d %T}", fmt::localtime(t));
        this_second.t = t;
    }
    auto ms = (n - clock::from_time_t(t)) / 1ms;
    return fmt::format_to(it, "{},{:03d}", this_second.s, ms);
}

static internal::log_buf::inserter_iterator (*print_timestamp)(internal::log_buf::inserter_iterator) = print_no_timestamp;

const std::map<log_level, sstring> log_level_names = {
        { log_level::trace, "trace" },
        { log_level::debug, "debug" },
        { log_level::info, "info" },
        { log_level::warn, "warn" },
        { log_level::error, "error" },
};

std::ostream& operator<<(std::ostream& out, log_level level) {
    return out << log_level_names.at(level);
}

std::istream& operator>>(std::istream& in, log_level& level) {
    sstring s;
    in >> s;
    if (!in) {
        return in;
    }
    for (auto&& x : log_level_names) {
        if (s == x.second) {
            level = x.first;
            return in;
        }
    }
    in.setstate(std::ios::failbit);
    return in;
}

std::ostream* logger::_out = &std::cerr;
std::atomic<bool> logger::_ostream = { true };
std::atomic<bool> logger::_syslog = { false };

logger::logger(sstring name) : _name(std::move(name)) {
    global_logger_registry().register_logger(this);
}

logger::logger(logger&& x) : _name(std::move(x._name)), _level(x._level.load(std::memory_order_relaxed)) {
    global_logger_registry().moved(&x, this);
}

logger::~logger() {
    global_logger_registry().unregister_logger(this);
}

static thread_local std::array<char, 8192> static_log_buf;

bool logger::rate_limit::check() {
    const auto now = clock::now();
    if (now < _next) {
        ++_dropped_messages;
        return false;
    }
    _next = now + _interval;
    return true;
}

logger::rate_limit::rate_limit(std::chrono::milliseconds interval)
    : _interval(interval), _next(clock::now())
{ }

void
logger::do_log(log_level level, log_writer& writer) {
    bool is_ostream_enabled = _ostream.load(std::memory_order_relaxed);
    bool is_syslog_enabled = _syslog.load(std::memory_order_relaxed);
    if(!is_ostream_enabled && !is_syslog_enabled) {
      return;
    }
    static array_map<sstring, 20> level_map = {
            { int(log_level::debug), "DEBUG" },
            { int(log_level::info),  "INFO "  },
            { int(log_level::trace), "TRACE" },
            { int(log_level::warn),  "WARN "  },
            { int(log_level::error), "ERROR" },
    };
    auto print_once = [&] (internal::log_buf::inserter_iterator it) {
      if (local_engine) {
          it = fmt::format_to(it, " [shard {}]", this_shard_id());
      }
      it = fmt::format_to(it, " {} - ", _name);
      return writer(it);
    };

    if (is_ostream_enabled) {
        internal::log_buf buf(static_log_buf.data(), static_log_buf.size());
        auto it = buf.back_insert_begin();
        it = fmt::format_to(it, "{} ", level_map[int(level)]);
        it = print_timestamp(it);
        it = print_once(it);
        *it++ = '\n';
        *_out << buf.view();
        _out->flush();
    }
    if (is_syslog_enabled) {
        internal::log_buf buf(static_log_buf.data(), static_log_buf.size());
        auto it = buf.back_insert_begin();
        it = print_once(it);
        *it = '\0';
        static array_map<int, 20> level_map = {
                { int(log_level::debug), LOG_DEBUG },
                { int(log_level::info), LOG_INFO },
                { int(log_level::trace), LOG_DEBUG },  // no LOG_TRACE
                { int(log_level::warn), LOG_WARNING },
                { int(log_level::error), LOG_ERR },
        };
        // NOTE: syslog() can block, which will stall the reactor thread.
        //       this should be rare (will have to fill the pipe buffer
        //       before syslogd can clear it) but can happen.  If it does,
        //       we'll have to implement some internal buffering (which
        //       still means the problem can happen, just less frequently).
        // syslog() interprets % characters, so send msg as a parameter
        syslog(level_map[int(level)], "%s", buf.data());
    }
}

void logger::failed_to_log(std::exception_ptr ex, format_info fmt) noexcept
{
    try {
        lambda_log_writer writer([ex = std::move(ex), fmt = std::move(fmt)] (internal::log_buf::inserter_iterator it) {
            it = fmt::format_to(it, "{}:{} @{}: failed to log message", fmt.loc.file_name(), fmt.loc.line(), fmt.loc.function_name());
            if (!fmt.format.empty()) {
                it = fmt::format_to(it, ": fmt='{}'", fmt.format);
            }
            return fmt::format_to(it, ": {}", ex);
        });
        do_log(log_level::error, writer);
    } catch (...) {
        ++logging_failures;
    }
}

void
logger::set_ostream(std::ostream& out) noexcept {
    _out = &out;
}

void
logger::set_ostream_enabled(bool enabled) noexcept {
    _ostream.store(enabled, std::memory_order_relaxed);
}

void
logger::set_stdout_enabled(bool enabled) noexcept {
    _ostream.store(enabled, std::memory_order_relaxed);
}

void
logger::set_syslog_enabled(bool enabled) noexcept {
    _syslog.store(enabled, std::memory_order_relaxed);
}

bool logger::is_shard_zero() noexcept {
    return this_shard_id() == 0;
}

void
logger_registry::set_all_loggers_level(log_level level) {
    std::lock_guard<std::mutex> g(_mutex);
    for (auto&& l : _loggers | boost::adaptors::map_values) {
        l->set_level(level);
    }
}

log_level
logger_registry::get_logger_level(sstring name) const {
    std::lock_guard<std::mutex> g(_mutex);
    return _loggers.at(name)->level();
}

void
logger_registry::set_logger_level(sstring name, log_level level) {
    std::lock_guard<std::mutex> g(_mutex);
    _loggers.at(name)->set_level(level);
}

std::vector<sstring>
logger_registry::get_all_logger_names() {
    std::lock_guard<std::mutex> g(_mutex);
    auto ret = _loggers | boost::adaptors::map_keys;
    return std::vector<sstring>(ret.begin(), ret.end());
}

void
logger_registry::register_logger(logger* l) {
    std::lock_guard<std::mutex> g(_mutex);
    if (_loggers.find(l->name()) != _loggers.end()) {
        throw std::runtime_error(format("Logger '{}' registered twice", l->name()));
    }
    _loggers[l->name()] = l;
}

void
logger_registry::unregister_logger(logger* l) {
    std::lock_guard<std::mutex> g(_mutex);
    _loggers.erase(l->name());
}

void
logger_registry::moved(logger* from, logger* to) {
    std::lock_guard<std::mutex> g(_mutex);
    _loggers[from->name()] = to;
}

void apply_logging_settings(const logging_settings& s) {
    global_logger_registry().set_all_loggers_level(s.default_level);

    for (const auto& pair : s.logger_levels) {
        try {
            global_logger_registry().set_logger_level(pair.first, pair.second);
        } catch (const std::out_of_range&) {
            throw std::runtime_error(
                        seastar::format("Unknown logger '{}'. Use --help-loggers to list available loggers.",
                                        pair.first));
        }
    }

    logger_ostream_type logger_ostream = s.stdout_enabled ? s.logger_ostream : logger_ostream_type::none;
    switch (logger_ostream) {
    case logger_ostream_type::none:
        logger::set_ostream_enabled(false);
        break;
    case logger_ostream_type::stdout:
        logger::set_ostream(std::cout);
        logger::set_ostream_enabled(true);
        break;
    case logger_ostream_type::stderr:
        logger::set_ostream(std::cerr);
        logger::set_ostream_enabled(true);
        break;
    }
    logger::set_syslog_enabled(s.syslog_enabled);

    switch (s.stdout_timestamp_style) {
    case logger_timestamp_style::none:
        print_timestamp = print_no_timestamp;
        break;
    case logger_timestamp_style::boot:
        print_timestamp = print_boot_timestamp;
        break;
    case logger_timestamp_style::real:
        print_timestamp = print_real_timestamp;
        break;
    default:
        break;
    }
}

sstring pretty_type_name(const std::type_info& ti) {
    int status;
    std::unique_ptr<char[], void (*)(void*)> result(
            abi::__cxa_demangle(ti.name(), 0, 0, &status), std::free);
    return result.get() ? result.get() : ti.name();
}

logger_registry& global_logger_registry() {
    static logger_registry g_registry;
    return g_registry;
}

sstring level_name(log_level level) {
    return  log_level_names.at(level);
}

namespace log_cli {

namespace bpo = boost::program_options;

log_level parse_log_level(const sstring& s) {
    try {
        return boost::lexical_cast<log_level>(s.c_str());
    } catch (const boost::bad_lexical_cast&) {
        throw std::runtime_error(format("Unknown log level '{}'", s));
    }
}

void parse_map_associations(const std::string& v, std::function<void(std::string, std::string)> consume_key_value) {
    static const std::regex colon(":");

    std::sregex_token_iterator s(v.begin(), v.end(), colon, -1);
    const std::sregex_token_iterator e;
    while (s != e) {
        const sstring p = std::string(*s++);

        const auto i = p.find('=');
        if (i == sstring::npos) {
            throw bpo::invalid_option_value(p);
        }

        auto k = p.substr(0, i);
        auto v = p.substr(i + 1, p.size());
        consume_key_value(std::move(k), std::move(v));
    };
}

bpo::options_description get_options_description() {
    program_options::options_description_building_visitor descriptor;
    options(nullptr).describe(descriptor);
    return std::move(descriptor).get_options_description();
}

options::options(program_options::option_group* parent_group)
    : program_options::option_group(parent_group, "Logging options")
    , default_log_level(*this, "default-log-level",
             log_level::info,
             "Default log level for log messages. Valid values are trace, debug, info, warn, error."
             )
    , logger_log_level(*this, "logger-log-level",
             {{}},
             "Map of logger name to log level. The format is \"NAME0=LEVEL0[:NAME1=LEVEL1:...]\". "
             "Valid logger names can be queried with --help-loggers. "
             "Valid values for levels are trace, debug, info, warn, error. "
             "This option can be specified multiple times."
            )
    , logger_stdout_timestamps(*this, "logger-stdout-timestamps", logger_timestamp_style::real,
                    "Select timestamp style for stdout logs: none|boot|real")
    , log_to_stdout(*this, "log-to-stdout", true, "Send log output to output stream, as selected by --logger-ostream-type")
    , logger_ostream_type(*this, "logger-ostream-type", logger_ostream_type::stderr,
            "Send log output to: none|stdout|stderr")
    , log_to_syslog(*this, "log-to-syslog", false, "Send log output to syslog.")
{
}

void print_available_loggers(std::ostream& os) {
    auto names = global_logger_registry().get_all_logger_names();
    // For quick searching by humans.
    std::sort(names.begin(), names.end());

    os << "Available loggers:\n";

    for (auto&& name : names) {
        os << "    " << name << '\n';
    }
}

logging_settings extract_settings(const boost::program_options::variables_map& vars) {
    options opts(nullptr);
    program_options::variables_map_extracting_visitor visitor(vars);
    opts.mutate(visitor);
    return extract_settings(opts);
}

logging_settings extract_settings(const options& opts) {
    return logging_settings{
        opts.logger_log_level.get_value(),
        opts.default_log_level.get_value(),
        opts.log_to_stdout.get_value(),
        opts.log_to_syslog.get_value(),
        opts.logger_stdout_timestamps.get_value(),
        opts.logger_ostream_type.get_value(),
    };
}

}

}
namespace boost {
template<>
seastar::log_level lexical_cast(const std::string& source) {
    std::istringstream in(source);
    seastar::log_level level;
    if (!(in >> level)) {
        throw boost::bad_lexical_cast();
    }
    return level;
}

}

namespace std {
std::ostream& operator<<(std::ostream& out, const std::exception_ptr& eptr) {
    if (!eptr) {
        out << "<no exception>";
        return out;
    }
    try {
        std::rethrow_exception(eptr);
    } catch(...) {
        auto tp = abi::__cxa_current_exception_type();
        if (tp) {
            out << seastar::pretty_type_name(*tp);
        } else {
            // This case shouldn't happen...
            out << "<unknown exception>";
        }
        // Print more information on some familiar exception types
        try {
            throw;
        } catch (const seastar::nested_exception& ne) {
            out << fmt::format(": {} (while cleaning up after {})", ne.inner, ne.outer);
        } catch (const std::system_error& e) {
            out << " (error " << e.code() << ", " << e.what() << ")";
        } catch (const std::exception& e) {
            out << " (" << e.what() << ")";
        } catch (...) {
            // no extra info
        }

        try {
            throw;
        } catch (const std::nested_exception& ne) {
            out << ": " << ne.nested_ptr();
        } catch (...) {
            // do nothing
        }
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const std::exception& e) {
    return out << seastar::pretty_type_name(typeid(e)) << " (" << e.what() << ")";
}

std::ostream& operator<<(std::ostream& out, const std::system_error& e) {
    return out << seastar::pretty_type_name(typeid(e)) << " (error " << e.code() << ", " << e.what() << ")";
}

}
