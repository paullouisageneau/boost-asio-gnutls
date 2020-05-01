//
// gnutls/stream.hpp
// ~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2020 Paul-Louis Ageneau (paul-louis at ageneau dot org)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_ASIO_GNUTLS_STREAM_HPP
#define BOOST_ASIO_GNUTLS_STREAM_HPP

#include "context.hpp"
#include "stream_base.hpp"

#include <boost/asio.hpp>

#ifndef BOOST_NO_EXCEPTIONS
#include <boost/system/system_error.hpp>
#endif

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include <cstddef>
#include <list>
#include <sstream>
#include <string>
#include <utility>

namespace boost {
namespace asio {
namespace gnutls {

template <typename NextLayer> class stream : public stream_base
{
public:
    using next_layer_type = NextLayer;
    using lowest_layer_type = typename next_layer_type::lowest_layer_type;
    using executor_type = typename next_layer_type::executor_type;
    using io_context = boost::asio::io_context;

    template <typename Arg>
    stream(Arg&& arg, context& ctx)
        : stream_base(ctx)
        , m_next_layer(std::make_shared<next_layer_type>(std::forward<Arg>(arg)))
        , m_tls_version(ctx.m_impl->tls_version())
    {
        set_impl(ctx.m_impl->is_server() ? server : client);
    }

    stream(stream&& other)
        : stream_base(std::move(other))
        , m_tls_version(std::move(other.m_tls_version))
        , m_next_layer(std::move(other.m_next_layer))
        , m_impl(std::move(other.m_impl))
    {
        m_impl->parent = this;
    }

    stream(stream const& other) = delete;
    ~stream()
    {
        if (m_impl) m_impl->parent = nullptr;
    }

    executor_type get_executor() { return m_next_layer->get_executor(); }
    io_context& get_io_context() { return m_next_layer->lowest_layer().get_io_context(); }
    const lowest_layer_type& lowest_layer() const { return m_next_layer->lowest_layer(); }
    lowest_layer_type& lowest_layer() { return m_next_layer->lowest_layer(); }
    const next_layer_type& next_layer() const { return *m_next_layer; }
    next_layer_type& next_layer() { return *m_next_layer; }

    native_handle_type native_handle() { return m_impl->session; }

    template <typename HandshakeHandler>
    void async_handshake(handshake_type type, HandshakeHandler handler)
    {
        if (m_impl->handshake_handler || m_impl->is_handshake_done)
        {
            post(get_executor(),
                 std::bind(std::move(handler), boost::asio::error::operation_not_supported));
            return;
        }

        error_code ec;
        m_next_layer->non_blocking(true, ec);
        if (ec)
        {
            post(get_executor(), std::bind(std::move(handler), ec));
            return;
        }

        set_impl(type);
        m_impl->handshake_handler = std::move(handler);
        m_impl->handle_handshake();
    }

    template <typename ConstBufferSequence, typename BufferedHandshakeHandler>
    void async_handshake(handshake_type type,
                         const ConstBufferSequence& buffers,
                         BufferedHandshakeHandler handler)
    {
        async_handshake(type, std::bind(handler, std::placeholders::_1, std::size_t(0)));
    }

    template <typename MutableBufferSequence, typename ReadHandler>
    void async_read_some(const MutableBufferSequence& buffers, ReadHandler handler)
    {
        if (m_impl->read_handler)
        {
            post(get_executor(),
                 std::bind(std::move(handler),
                           boost::asio::error::operation_not_supported,
                           std::size_t(0)));
            return;
        }
        std::size_t bytes_added = 0;
        for (auto b = buffer_sequence_begin(buffers), end(buffer_sequence_end(buffers)); b != end;
             ++b)
        {
            if (b->size() == 0) continue;
            m_impl->read_buffers.push_back(*b);
            bytes_added += b->size();
        }

        if (bytes_added == 0)
        {
            // if we're reading 0 bytes, post handler immediately
            post(get_executor(), std::bind<void>(std::move(handler), error_code(), std::size_t(0)));
            return;
        }

        m_impl->read_handler = std::move(handler);
        m_impl->async_schedule();
    }

    template <typename ConstBufferSequence, typename WriteHandler>
    void async_write_some(const ConstBufferSequence& buffers, WriteHandler handler)
    {
        if (m_impl->write_handler)
        {
            post(get_executor(),
                 std::bind(std::move(handler),
                           boost::asio::error::operation_not_supported,
                           std::size_t(0)));
            return;
        }

        size_t bytes_added = 0;
        for (auto b = buffer_sequence_begin(buffers), end(buffer_sequence_end(buffers)); b != end;
             ++b)
        {
            if (b->size() == 0) continue;
            m_impl->write_buffers.push_back(*b);
            bytes_added += b->size();
        }

        if (bytes_added == 0)
        {
            // if we're writing 0 bytes, post handler immediately
            post(get_executor(), std::bind<void>(std::move(handler), error_code(), std::size_t(0)));
            return;
        }

        m_impl->write_handler = std::move(handler);
        m_impl->bytes_written = 0;
        m_impl->async_schedule();
    }

    template <typename ShutdownHandler> void async_shutdown(ShutdownHandler handler)
    {
        if (m_impl->shutdown_handler || !m_impl->is_handshake_done)
        {
            post(get_executor(),
                 std::bind(std::move(handler), boost::asio::error::operation_not_supported));
            return;
        }

        m_impl->shutdown_handler = std::move(handler);
        m_impl->handle_shutdown();
    }

    void handshake(handshake_type type)
    {
        error_code ec;
        handshake(type, ec);
        if (ec) boost::throw_exception(boost::system::system_error(ec));
    }

    error_code handshake(handshake_type type, error_code& ec)
    {
        m_next_layer->non_blocking(false, ec);
        if (ec) return ec;

        set_impl(type);
        int ret;
        do {
            ret = gnutls_handshake(m_impl->session);
        } while (ret != GNUTLS_E_SUCCESS && !gnutls_error_is_fatal(ret));

        m_next_layer->non_blocking(true, ec);
        if (ec) return ec;

        if (ret != GNUTLS_E_SUCCESS) return ec = error_code(ret, error::get_ssl_category());
        m_impl->is_handshake_done = true;
        return ec;
    }

#ifndef BOOST_NO_EXCEPTIONS
    template <typename ConstBufferSequence>
    void handshake(handshake_type type, const ConstBufferSequence& buffers)
    {
        error_code ec;
        handshake(type, ec);
        if (ec) boost::throw_exception(boost::system::system_error(ec));
    }
#endif

    template <typename ConstBufferSequence>
    error_code handshake(handshake_type type, const ConstBufferSequence& buffers, error_code& ec)
    {
        handshake(type, ec);
        return ec;
    }

#ifndef BOOST_NO_EXCEPTIONS
    void shutdown()
    {
        error_code ec;
        shutdown(ec);
        if (ec) boost::throw_exception(boost::system::system_error(ec));
    }
#endif

    error_code shutdown(error_code& ec)
    {
        m_next_layer->non_blocking(false, ec);
        if (ec) return ec;

        int ret;
        do {
            ret = gnutls_bye(m_impl->session, GNUTLS_SHUT_RDWR);
        } while (ret != GNUTLS_E_SUCCESS && !gnutls_error_is_fatal(ret));

        m_next_layer->non_blocking(true, ec);
        ec.clear();

        if (ret != GNUTLS_E_SUCCESS) return ec = error_code(ret, error::get_ssl_category());
        m_impl->is_handshake_done = false;
        return ec;
    }

#ifndef BOOST_NO_EXCEPTIONS
    template <typename MutableBufferSequence> size_t read_some(const MutableBufferSequence& buffers)
    {
        error_code ec;
        auto bytes_read = read_some(buffers, ec);
        if (ec) boost::throw_exception(boost::system::system_error(ec));
        return bytes_read;
    }
#endif

    template <typename MutableBufferSequence>
    size_t read_some(const MutableBufferSequence& buffers, error_code& ec)
    {
        if (m_impl->read_handler || !m_impl->is_handshake_done)
        {
            ec = boost::asio::error::operation_not_supported;
            return 0;
        }

        std::copy(buffer_sequence_begin(buffers),
                  buffer_sequence_end(buffers),
                  std::back_inserter(m_impl->read_buffers));

        std::size_t bytes_read = m_impl->recv_some(ec);
        m_impl->read_buffers.clear();
        return bytes_read;
    }

#ifndef BOOST_NO_EXCEPTIONS
    template <typename ConstBufferSequence>
    std::size_t write_some(const ConstBufferSequence& buffers)
    {
        error_code ec;
        auto bytes_sent = m_impl->write_some(buffers, ec);
        if (ec) boost::throw_exception(boost::system::system_error(ec));
        return bytes_sent;
    }
#endif

    template <typename ConstBufferSequence>
    std::size_t write_some(const ConstBufferSequence& buffers, error_code& ec)
    {
        if (m_impl->write_handler || !m_impl->is_handshake_done)
        {
            ec = boost::asio::error::operation_not_supported;
            return 0;
        }

        std::copy(buffer_sequence_begin(buffers),
                  buffer_sequence_end(buffers),
                  std::back_inserter(m_impl->write_buffers));

        std::size_t bytes_written = m_impl->send_some(ec);
        m_impl->write_buffers.clear();
        return bytes_written;
    }

    // ---------- SNI extension ----------

#ifndef BOOST_NO_EXCEPTIONS
    void set_host_name(std::string const& name)
    {
        error_code ec;
        set_host_name(name, ec);
        if (ec) boost::throw_exception(boost::system::system_error(ec));
    }
#endif

    error_code set_host_name(std::string const& name, error_code& ec)
    {
        int ret =
            gnutls_server_name_set(m_impl->session, GNUTLS_NAME_DNS, name.c_str(), name.size());
        return ec = ret == GNUTLS_E_SUCCESS ? error_code()
                                            : error_code(ret, error::get_ssl_category());
    }

    // -----------------------------------

private:
    enum class direction
    {
        none,
        read,
        write
    };

    void set_impl(handshake_type type)
    {
        if (!m_impl || m_impl->type != type)
            if (auto old = std::exchange(m_impl, std::make_shared<impl>(this, type)))
                old->parent = nullptr;
    }

    std::shared_ptr<next_layer_type> m_next_layer;

    const unsigned int m_tls_version; // X*10 + Y => TLS X.Y, 0*10 + Z => SSL Z

    struct impl : public std::enable_shared_from_this<impl>
    {
        impl(stream* p, handshake_type t)
            : type(t)
            , next_layer_weak(p->m_next_layer)
            , executor(p->m_next_layer->get_executor())
            , parent(p)
        {
            int ret = gnutls_init(
                &session, (type == client ? GNUTLS_CLIENT : GNUTLS_SERVER) | GNUTLS_NONBLOCK);
            if (ret != GNUTLS_E_SUCCESS)
                throw std::runtime_error("gnutls_init failed: " +
                                         std::string(gnutls_strerror(ret)));

            gnutls_session_set_ptr(session, this);
            gnutls_handshake_set_post_client_hello_function(session, post_client_hello_func);

            gnutls_transport_set_ptr(session, this);
            gnutls_transport_set_push_function(session, push_func);
            gnutls_transport_set_pull_function(session, pull_func);

            auto context_impl = parent->m_context_impl;
            auto const opts = context_impl->opts;
            auto const tls_version = parent->m_tls_version;

            std::ostringstream priority;
            if (tls_version > 0 && tls_version < 10 && !(opts & context::no_sslv3))
                priority << "+VERS-SSL3.0:%COMPAT";

            if (tls_version >= 10)
                priority << "-VERS-TLS-ALL:+VERS-TLS" << (tls_version / 10) << '.'
                         << (tls_version % 10);

            if (!priority.str().empty())
            {
                char const* err_pos = nullptr;
                ret = gnutls_set_default_priority_append(
                    session, priority.str().c_str(), &err_pos, 0);
                if (ret != GNUTLS_E_SUCCESS)
                    throw std::runtime_error("gnutls_set_default_priority_append for \"" +
                                             priority.str() +
                                             "\" failed: " + std::string(gnutls_strerror(ret)));
            }
            else
            {
                ret = gnutls_set_default_priority(session);
                if (ret != GNUTLS_E_SUCCESS)
                    throw std::runtime_error("gnutls_priority_set_direct failed: " +
                                             std::string(gnutls_strerror(ret)));
            }

            gnutls_certificate_set_verify_function(context_impl->cred, verify_func);
            ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, context_impl->cred);
            if (ret != GNUTLS_E_SUCCESS)
                throw std::runtime_error("gnutls_credentials_set failed: " +
                                         std::string(gnutls_strerror(ret)));
        }

        ~impl() { gnutls_deinit(session); }

        std::string get_servername() const
        {
            char buf[256];
            size_t len = sizeof(buf);
            unsigned int type = GNUTLS_NAME_DNS;
            int ret = gnutls_server_name_get(session, buf, &len, &type, 0);
            return ret == GNUTLS_E_SUCCESS ? std::string(buf, len) : "";
        }

        bool want_read() const { return want_direction == direction::read || read_handler; }
        bool want_write() const { return want_direction == direction::write || write_handler; }

        void async_schedule()
        {
            using namespace std::placeholders;

            auto next_layer = next_layer_weak.lock();
            if (!next_layer) return;

            // Start a read operation if GnuTLS wants one
            if (want_read() && !std::exchange(is_reading, true))
            {
                if (gnutls_record_check_pending(session) > 0 && read_handler)
                    handle_read();
                else
                    next_layer->async_wait(
                        next_layer_type::wait_read,
                        std::bind(&impl::handle_read, this->shared_from_this(), _1));
            }

            // Start a write operation if GnuTLS wants one
            if (want_write() && !std::exchange(is_writing, true))
            {
                next_layer->async_wait(
                    next_layer_type::wait_write,
                    std::bind(&impl::handle_write, this->shared_from_this(), _1));
            }
        }

        void handle_read(error_code ec = {})
        {
            is_reading = false;
            if (read_handler)
            {
                if (!ec) bytes_read += recv_some(ec);

                if (ec == boost::asio::error::would_block) return async_schedule();

                read_buffers.clear();
                auto handler = std::exchange(read_handler, nullptr);
                handler(ec, std::exchange(bytes_read, std::size_t(0)));
            }

            if (handshake_handler) return handle_handshake(ec);
            if (shutdown_handler) return handle_shutdown(ec);
        }

        void handle_write(error_code ec = {})
        {
            is_writing = false;
            if (write_handler)
            {
                if (!ec) bytes_written += send_some(ec);

                if (ec == boost::asio::error::would_block) return async_schedule();

                write_buffers.clear();
                auto handler = std::exchange(write_handler, nullptr);
                handler(ec, std::exchange(bytes_written, std::size_t(0)));
            }

            if (handshake_handler) return handle_handshake(ec);
            if (shutdown_handler) return handle_shutdown(ec);
        }

        void handle_handshake(error_code ec = {})
        {
            if (!ec)
            {
                int ret = gnutls_handshake(session);
                if (ret == GNUTLS_E_AGAIN)
                {
                    want_direction = gnutls_record_get_direction(session) == 0 ? direction::read
                                                                               : direction::write;
                    return async_schedule();
                }

                want_direction = direction::none;
                if (ret == GNUTLS_E_SUCCESS)
                    is_handshake_done = true;
                else
                    ec = error_code(ret, error::get_ssl_category());
            }

            auto handler = std::exchange(handshake_handler, nullptr);
            handler(ec);
        }

        void handle_shutdown(error_code ec = {})
        {
            if (!ec)
            {
                int ret = gnutls_bye(session, GNUTLS_SHUT_RDWR);
                if (ret == GNUTLS_E_AGAIN)
                {
                    want_direction = gnutls_record_get_direction(session) == 0 ? direction::read
                                                                               : direction::write;
                    return async_schedule();
                }

                want_direction = direction::none;
                if (ret == GNUTLS_E_SUCCESS)
                    is_handshake_done = false;
                else
                    ec = error_code(ret, error::get_ssl_category());
            }

            auto handler = std::exchange(shutdown_handler, nullptr);
            handler(ec);
        }

        std::size_t recv_some(error_code& ec)
        {
            std::size_t bytes_read = 0;
            while (!read_buffers.empty())
            {
                auto& front = read_buffers.front();
                int ret = gnutls_record_recv(session, front.data(), front.size());
                if (ret < 0)
                {
                    if (ret == GNUTLS_E_AGAIN)
                        ec = boost::asio::error::would_block;
                    else if (gnutls_error_is_fatal(ret))
                        ec = error_code(ret, error::get_ssl_category());
                    else
                        continue;

                    break;
                }

                if (front.size() > 0 && ret == 0)
                {
                    ec = boost::asio::error::eof;
                    break;
                }

                front += ret;
                bytes_read += ret;
                if (front.size() == 0) read_buffers.pop_front();

                if (gnutls_record_check_pending(session) == 0) break;
            }

            if (bytes_read > 0) ec.clear();

            return bytes_read;
        }

        std::size_t send_some(error_code& ec)
        {
            gnutls_record_cork(session);
            while (!write_buffers.empty())
            {
                auto& front = write_buffers.front();
                int ret = gnutls_record_send(session, front.data(), front.size());
                if (ret < 0) break;

                front += ret;
                if (front.size() == 0) write_buffers.pop_front();
            }

            std::size_t bytes_written = 0;
            do {
                int ret = gnutls_record_uncork(session, 0);
                if (ret < 0)
                {
                    if (ret == GNUTLS_E_AGAIN)
                        ec = boost::asio::error::would_block;
                    else if (gnutls_error_is_fatal(ret))
                        ec = error_code(ret, error::get_ssl_category());
                    else
                        continue;

                    break;
                }

                bytes_written += ret;
            } while (gnutls_record_check_corked(session) > 0);

            if (bytes_written > 0) ec.clear();

            return bytes_written;
        }

        static ssize_t pull_func(void* ptr, void* buffer, std::size_t size)
        {
            auto* im = static_cast<impl*>(ptr);
            auto next_layer = im->next_layer_weak.lock();
            if (!next_layer)
            {
                gnutls_transport_set_errno(im->session, ECONNRESET);
                return -1;
            }

            error_code ec;
            std::size_t bytes_read = next_layer->read_some(boost::asio::buffer(buffer, size), ec);
            if (ec && ec != boost::asio::error::eof)
            {
                gnutls_transport_set_errno(
                    im->session, ec == boost::asio::error::would_block ? EAGAIN : ECONNRESET);
                return -1;
            }

            gnutls_transport_set_errno(im->session, 0);
            return ssize_t(bytes_read);
        }

        static ssize_t push_func(void* ptr, const void* data, std::size_t len)
        {
            auto* im = static_cast<impl*>(ptr);
            auto next_layer = im->next_layer_weak.lock();
            if (!next_layer)
            {
                gnutls_transport_set_errno(im->session, ECONNRESET);
                return -1;
            }

            error_code ec;
            std::size_t bytes_written =
                next_layer->write_some(boost::asio::const_buffer(data, len), ec);
            if (ec)
            {
                gnutls_transport_set_errno(
                    im->session, ec == boost::asio::error::would_block ? EAGAIN : ECONNRESET);
                return -1;
            }

            gnutls_transport_set_errno(im->session, 0);
            return ssize_t(bytes_written);
        }

        static int verify_func(gnutls_session_t session)
        {
            auto* im = static_cast<impl*>(gnutls_session_get_ptr(session));
            if (!im->parent) return GNUTLS_E_INVALID_SESSION;
            auto context_impl = im->parent->m_context_impl;

            if (!(context_impl->verify & context::verify_peer))
                return GNUTLS_E_SUCCESS; // no verification requested

            if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509)
                return GNUTLS_E_NO_CERTIFICATE_FOUND;

            unsigned int count = 0;
            gnutls_datum_t const* array = gnutls_certificate_get_peers(session, &count);
            if (!array || count == 0) return GNUTLS_E_NO_CERTIFICATE_FOUND;

            gnutls_x509_crt_t cert;
            gnutls_x509_crt_init(&cert);
            int ret = gnutls_x509_crt_import(cert, &array[0], GNUTLS_X509_FMT_DER);
            if (ret != GNUTLS_E_SUCCESS)
            {
                gnutls_x509_crt_deinit(cert);
                return ret;
            }

            bool verified = false;
            unsigned int status = 0;
            ret = gnutls_certificate_verify_peers2(session, &status);
            if (ret == GNUTLS_E_SUCCESS && !(status & GNUTLS_CERT_INVALID)) verified = true;

            if (context_impl->verify_callback)
            {
                verify_context ctx(cert);
                verified = context_impl->verify_callback(verified, ctx);
            }

            gnutls_x509_crt_deinit(cert);
            return verified ? GNUTLS_E_SUCCESS : GNUTLS_E_CERTIFICATE_ERROR;
        }

        static int post_client_hello_func(gnutls_session_t session)
        {
            auto* im = static_cast<impl*>(gnutls_session_get_ptr(session));
            if (!im->parent) return GNUTLS_E_INVALID_SESSION;
            auto context_impl = im->parent->m_context_impl;

            auto& callback = context_impl->servername_callback;
            if (!callback) return GNUTLS_E_SUCCESS;

            if (!callback(*im->parent, im->get_servername())) return GNUTLS_E_UNRECOGNIZED_NAME;

            // context may have been switched
            context_impl = im->parent->m_context_impl;

            // set credentials now
            gnutls_certificate_set_verify_function(context_impl->cred, verify_func);
            int ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, context_impl->cred);
            if (ret != GNUTLS_E_SUCCESS) return ret;

            // set certificate request
            auto const verify = context_impl->verify;
            gnutls_certificate_request_t req = GNUTLS_CERT_IGNORE;
            if (verify & context::verify_peer)
            {
                if (verify & context::verify_fail_if_no_peer_cert)
                    req = GNUTLS_CERT_REQUIRE;
                else
                    req = GNUTLS_CERT_REQUEST;
            }
            gnutls_certificate_server_set_request(session, req);

            return GNUTLS_E_SUCCESS;
        }

        const handshake_type type;
        const std::weak_ptr<next_layer_type> next_layer_weak;
        const executor_type executor;
        stream* parent;

        gnutls_session_t session;

        direction want_direction = direction::none;
        bool is_handshake_done = false;
        bool is_reading = false;
        bool is_writing = false;

        std::function<void(error_code const&)> handshake_handler;
        std::function<void(error_code const&)> shutdown_handler;
        std::function<void(error_code const&, std::size_t)> read_handler;
        std::function<void(error_code const&, std::size_t)> write_handler;

        std::list<boost::asio::mutable_buffer> read_buffers;
        std::list<boost::asio::const_buffer> write_buffers;

        std::size_t bytes_read = 0;
        std::size_t bytes_written = 0;
    };

    std::shared_ptr<impl> m_impl;
};

} // namespace gnutls
} // namespace asio
} // namespace boost

#endif
