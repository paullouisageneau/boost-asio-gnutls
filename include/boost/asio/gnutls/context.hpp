//
// gnutls/context.hpp
// ~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2020 Paul-Louis Ageneau (paul-louis at ageneau dot org)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_ASIO_GNUTLS_CONTEXT_HPP
#define BOOST_ASIO_GNUTLS_CONTEXT_HPP

#include "context_base.hpp"
#include "error.hpp"
#include "verify_context.hpp"

#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>

#ifndef BOOST_NO_EXCEPTIONS
#include <boost/system/system_error.hpp>
#endif

#include <gnutls/gnutls.h>

#include <exception>
#include <functional>
#include <memory>
#include <string>
#include <utility>

namespace boost {
namespace asio {
namespace gnutls {

class stream_base;
template <typename next_layer_type> class stream;

using const_buffer = boost::asio::const_buffer;

class context : public context_base
{
public:
    explicit context(method m)
        : m_impl(std::make_shared<impl>(this, m))
    {}
    context(context&& other) { *this = std::move(other); }
    context(const context& other) = delete;
    ~context()
    {
        if (m_impl) m_impl->parent = nullptr;
    }

    context& operator=(context&& other)
    {
        m_impl = std::move(other.m_impl);
        m_impl->parent = this;
        return *this;
    }

    native_handle_type native_handle() { return m_impl->cred; }

#ifndef BOOST_NO_EXCEPTIONS
    void set_options(options opts)
    {
        error_code ec;
        set_options(opts, ec);
        if (ec) boost::throw_exception(boost::system::system_error(ec));
    }
#endif

    error_code set_options(options opts, error_code& ec)
    {
        m_impl->opts = opts;
        return ec;
    }

#ifndef BOOST_NO_EXCEPTIONS
    void clear_options()
    {
        error_code ec;
        clear_options(ec);
        if (ec) boost::throw_exception(boost::system::system_error(ec));
    }
#endif

    void clear_options(error_code& ec) { m_impl->opts = 0; }

#ifndef BOOST_NO_EXCEPTIONS
    void set_default_verify_paths()
    {
        error_code ec;
        set_default_verify_paths(ec);
        if (ec) boost::throw_exception(boost::system::system_error(ec));
    }
#endif

    error_code set_default_verify_paths(error_code& ec)
    {
        int ret = gnutls_certificate_set_x509_system_trust(m_impl->cred);
        if (ret != GNUTLS_E_SUCCESS) ec = error_code(ret, error::get_ssl_category());
        return ec;
    }

#ifndef BOOST_NO_EXCEPTIONS
    void set_verify_mode(verify_mode v)
    {
        error_code ec;
        set_verify_mode(v, ec);
        if (ec) boost::throw_exception(boost::system::system_error(ec));
    }
#endif

    error_code set_verify_mode(verify_mode v, error_code& ec)
    {
        m_impl->verify = v;
        return ec;
    }

#ifndef BOOST_NO_EXCEPTIONS
    template <typename VerifyCallback> void set_verify_callback(VerifyCallback callback)
    {
        error_code ec;
        set_verify_callback(callback, ec);
        if (ec) boost::throw_exception(boost::system::system_error(ec));
    }
#endif

    template <typename VerifyCallback>
    error_code set_verify_callback(VerifyCallback callback, error_code& ec)
    {
        m_impl->verify_callback = callback;
        return ec;
    }

#ifndef BOOST_NO_EXCEPTIONS
    void use_passphrase(std::string const& pass)
    {
        error_code ec;
        use_passphrase(pass, ec);
        if (ec) boost::throw_exception(boost::system::system_error(ec));
    }
#endif

    error_code use_passphrase(std::string const& pass, error_code& ec)
    {
        m_impl->passphrase = pass;
        return ec;
    }

#ifndef BOOST_NO_EXCEPTIONS
    void use_certificate_file(std::string const& filename, file_format format)
    {
        error_code ec;
        use_certificate_file(filename, format, ec);
        if (ec) boost::throw_exception(boost::system::system_error(ec));
    }
#endif

    error_code use_certificate_file(std::string const& filename, file_format, error_code& ec)
    {
        m_impl->certificate_file = filename;
        return ec;
    }

#ifndef BOOST_NO_EXCEPTIONS
    void use_private_key_file(std::string const& filename, file_format format)
    {
        error_code ec;
        use_private_key_file(filename, format, ec);
        if (ec) boost::throw_exception(boost::system::system_error(ec));
    }
#endif

    error_code use_private_key_file(std::string const& filename, file_format format, error_code& ec)
    {
        if (m_impl->certificate_file.empty())
            return ec = boost::asio::error::operation_not_supported;

        m_impl->private_key_file = filename;
        int ret = gnutls_certificate_set_x509_key_file2(m_impl->cred,
                                                        m_impl->certificate_file.c_str(),
                                                        m_impl->private_key_file.c_str(),
                                                        format == pem ? GNUTLS_X509_FMT_PEM
                                                                      : GNUTLS_X509_FMT_DER,
                                                        m_impl->passphrase.c_str(),
                                                        0);
        if (ret != GNUTLS_E_SUCCESS) ec = error_code(ret, error::get_ssl_category());
        return ec;
    }

#ifndef BOOST_NO_EXCEPTIONS
    void use_tmp_dh_file(std::string const& filename)
    {
        error_code ec;
        use_tmp_dh_file(filename, ec);
        if (ec) boost::throw_exception(boost::system::system_error(ec));
    }
#endif

    error_code use_tmp_dh_file(std::string const&, error_code& ec)
    {
        // Unnecessary and discouraged on GnuTLS 3.6.0 or later.
        // Since 3.6.0, DH parameters are negotiated following RFC7919.
        return ec;
    }

#ifndef BOOST_NO_EXCEPTIONS
    void use_certificate(const_buffer const& certificate, file_format format)
    {
        error_code ec;
        use_certificate(certificate, format, ec);
        if (ec) boost::throw_exception(boost::system::system_error(ec));
    }
#endif

    error_code use_certificate(const_buffer const& certificate, file_format, error_code& ec)
    {
        m_impl->certificate.assign(static_cast<char const*>(certificate.data()),
                                   certificate.size());
        return ec;
    }

#ifndef BOOST_NO_EXCEPTIONS
    void use_private_key(const_buffer const& private_key, file_format format)
    {
        error_code ec;
        use_private_key(private_key, format, ec);
        if (ec) boost::throw_exception(boost::system::system_error(ec));
    }
#endif

    error_code use_private_key(const_buffer const& private_key, file_format format, error_code& ec)
    {
        if (m_impl->certificate.empty()) return ec = boost::asio::error::operation_not_supported;

        m_impl->private_key.assign(reinterpret_cast<char const*>(private_key.data()),
                                   private_key.size());

        gnutls_datum_t cert;
        cert.data = reinterpret_cast<unsigned char*>(
            const_cast<char*>(m_impl->certificate.c_str())); // must be null terminated
        cert.size = m_impl->certificate.size();

        gnutls_datum_t key;
        key.data = reinterpret_cast<unsigned char*>(
            const_cast<char*>(m_impl->private_key.c_str())); // must be null terminated
        key.size = m_impl->private_key.size();

        int ret = gnutls_certificate_set_x509_key_mem2(m_impl->cred,
                                                       &cert,
                                                       &key,
                                                       format == pem ? GNUTLS_X509_FMT_PEM
                                                                     : GNUTLS_X509_FMT_DER,
                                                       m_impl->passphrase.c_str(),
                                                       0);
        if (ret != GNUTLS_E_SUCCESS) ec = error_code(ret, error::get_ssl_category());
        return ec;
    }

#ifndef BOOST_NO_EXCEPTIONS
    void use_tmp_dh(const_buffer const& dh)
    {
        error_code ec;
        use_tmp_dh(dh, ec);
        if (ec) boost::throw_exception(boost::system::system_error(ec));
    }
#endif

    error_code use_tmp_dh(const_buffer const&, error_code& ec)
    {
        // Unnecessary and discouraged on GnuTLS 3.6.0 or later.
        // Since 3.6.0, DH parameters are negotiated following RFC7919.
        return ec;
    }

    // ---------- SNI extension ----------

    error_code set_servername_callback(std::function<bool(stream_base& s, std::string name)> cb,
                                       error_code& ec)
    {
        m_impl->servername_callback = std::move(cb);
        return ec;
    }

    // -------- Other extensions ---------

    error_code set_verify_trust(const_buffer const& certificate, file_format format, error_code& ec)
    {
        std::string cert(static_cast<char const*>(certificate.data()), certificate.size());

        gnutls_datum_t ca;
        ca.data = reinterpret_cast<unsigned char*>(
            const_cast<char*>(cert.c_str())); // must be null terminated
        ca.size = cert.size();

        // Warning: returns the number of certificates processed or a negative
        // error code on error
        int ret = gnutls_certificate_set_x509_trust_mem(
            m_impl->cred, &ca, format == pem ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER);
        if (ret < 0) ec = error_code(ret, error::get_ssl_category());
        return ec;
    }

    // -----------------------------------

private:
    struct impl
    {
        impl(context* p_, method m_)
            : m(m_)
            , parent(p_)
        {
            int ret = gnutls_certificate_allocate_credentials(&cred);
            if (ret != GNUTLS_E_SUCCESS)
                throw std::runtime_error("gnutls_certificate_allocate_credentials failed: " +
                                         std::string(gnutls_strerror(ret)));

            gnutls_certificate_set_known_dh_params(cred, GNUTLS_SEC_PARAM_MEDIUM);
        }
        ~impl() { gnutls_certificate_free_credentials(cred); }

        bool is_server() const { return (static_cast<unsigned int>(m) & 0x2) != 0; }
        unsigned int tls_version() const { return static_cast<unsigned int>(m) >> 16; }

        bool verify_dn(gnutls_x509_crt_t cert);

        const method m;
        context* parent;

        gnutls_certificate_credentials_t cred;
        verify_mode verify = 0;
        options opts = 0;

        std::string certificate_file, private_key_file;
        std::string certificate, private_key;
        std::string passphrase;

        std::function<bool(bool preverified, verify_context& ctx)> verify_callback;
        std::function<bool(stream_base& s, std::string name)> servername_callback;
    };

    std::shared_ptr<impl> m_impl;

    friend class stream_base;
    template <typename next_layer_type> friend class stream;
};

} // namespace gnutls
} // namespace asio
} // namespace boost

#endif
