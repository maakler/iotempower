#include "config.h"

#ifdef MQTT_TLS_BACKEND_WOLFSSL

#include "iotempower-wolfssl-mqtt-client.h"
#include <Arduino.h>

#if defined(ESP32)
#include <WiFi.h>
#else
#include <ESP8266WiFi.h>
#endif

#include <wolfssl.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>

class IoTempowerWolfsslTransport : public espMqttClientInternals::Transport {
    public:
        IoTempowerWolfsslTransport();
        ~IoTempowerWolfsslTransport();

        void setCACert(const char* ca_cert);

        bool connect(IPAddress ip, uint16_t port) override;
        bool connect(const char* host, uint16_t port) override;
        size_t write(const uint8_t* buf, size_t size) override;
        int read(uint8_t* buf, size_t size) override;
        void stop() override;
        bool connected() override;
        bool disconnected() override;

        int rawWrite(const uint8_t* buf, size_t size);
        int rawRead(uint8_t* buf, size_t size);

    private:
        bool connectTcp(const char* host, uint16_t port);
        bool startTls(const char* host);
        void cleanupTls();

        WiFiClient _client;
        WOLFSSL_CTX* _ctx;
        WOLFSSL* _ssl;
        const char* _ca_cert;
        bool _tls_connected;
};

static int iotempower_wolfssl_send(WOLFSSL* ssl, char* data, int size, void* ctx) {
    (void)ssl;
    if (!ctx || !data || size <= 0) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    return static_cast<IoTempowerWolfsslTransport*>(ctx)->rawWrite(
        reinterpret_cast<const uint8_t*>(data),
        static_cast<size_t>(size));
}

static int iotempower_wolfssl_recv(WOLFSSL* ssl, char* data, int size, void* ctx) {
    (void)ssl;
    if (!ctx || !data || size <= 0) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    return static_cast<IoTempowerWolfsslTransport*>(ctx)->rawRead(
        reinterpret_cast<uint8_t*>(data),
        static_cast<size_t>(size));
}

IoTempowerWolfsslTransport::IoTempowerWolfsslTransport()
    : _ctx(NULL),
      _ssl(NULL),
      _ca_cert(NULL),
      _tls_connected(false) {
}

IoTempowerWolfsslTransport::~IoTempowerWolfsslTransport() {
    stop();
}

void IoTempowerWolfsslTransport::setCACert(const char* ca_cert) {
    _ca_cert = ca_cert;
}

bool IoTempowerWolfsslTransport::connect(IPAddress ip, uint16_t port) {
    char ip_buffer[16];
    snprintf(ip_buffer, sizeof(ip_buffer), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    return connect(ip_buffer, port);
}

bool IoTempowerWolfsslTransport::connect(const char* host, uint16_t port) {
    stop();
    if (!host || !*host || !_ca_cert || !*_ca_cert) {
        return false;
    }
    if (!connectTcp(host, port)) {
        return false;
    }
    if (!startTls(host)) {
        stop();
        return false;
    }
    return true;
}

bool IoTempowerWolfsslTransport::connectTcp(const char* host, uint16_t port) {
    if (!_client.connect(host, port)) {
        return false;
    }
#if defined(ESP8266)
    _client.setNoDelay(true);
#endif
    return true;
}

bool IoTempowerWolfsslTransport::startTls(const char* host) {
    if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
        return false;
    }

    WOLFSSL_METHOD* method = wolfSSLv23_client_method();
    if (!method) {
        return false;
    }

    _ctx = wolfSSL_CTX_new(method);
    if (!_ctx) {
        return false;
    }

    wolfSSL_CTX_set_verify(_ctx, SSL_VERIFY_PEER, NULL);
    wolfSSL_SetIOSend(_ctx, iotempower_wolfssl_send);
    wolfSSL_SetIORecv(_ctx, iotempower_wolfssl_recv);

    if (wolfSSL_CTX_load_verify_buffer(
            _ctx,
            reinterpret_cast<const unsigned char*>(_ca_cert),
            static_cast<long>(strlen(_ca_cert)),
            SSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        return false;
    }

    _ssl = wolfSSL_new(_ctx);
    if (!_ssl) {
        return false;
    }

    wolfSSL_SetIOReadCtx(_ssl, this);
    wolfSSL_SetIOWriteCtx(_ssl, this);
    wolfSSL_check_domain_name(_ssl, host);

#ifdef HAVE_SNI
    wolfSSL_UseSNI(_ssl, WOLFSSL_SNI_HOST_NAME, host, static_cast<unsigned short>(strlen(host)));
#endif

    unsigned long deadline = millis() + 15000;
    while (millis() < deadline) {
        int ret = wolfSSL_connect(_ssl);
        if (ret == WOLFSSL_SUCCESS) {
            _tls_connected = true;
            return true;
        }

        int err = wolfSSL_get_error(_ssl, ret);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            return false;
        }
        delay(1);
    }

    return false;
}

size_t IoTempowerWolfsslTransport::write(const uint8_t* buf, size_t size) {
    if (!_ssl || !_tls_connected || !buf || size == 0) {
        return 0;
    }

    int ret = wolfSSL_write(_ssl, buf, static_cast<int>(size));
    if (ret <= 0) {
        int err = wolfSSL_get_error(_ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return 0;
        }
        stop();
        return 0;
    }
    return static_cast<size_t>(ret);
}

int IoTempowerWolfsslTransport::read(uint8_t* buf, size_t size) {
    if (!_ssl || !_tls_connected || !buf || size == 0) {
        return 0;
    }

    int ret = wolfSSL_read(_ssl, buf, static_cast<int>(size));
    if (ret < 0) {
        int err = wolfSSL_get_error(_ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return 0;
        }
        stop();
        return 0;
    }
    return ret;
}

void IoTempowerWolfsslTransport::stop() {
    cleanupTls();
    _client.stop();
}

bool IoTempowerWolfsslTransport::connected() {
    return _tls_connected && _client.connected();
}

bool IoTempowerWolfsslTransport::disconnected() {
    return !connected();
}

int IoTempowerWolfsslTransport::rawWrite(const uint8_t* buf, size_t size) {
    size_t written = _client.write(buf, size);
    if (written == 0) {
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    }
    return static_cast<int>(written);
}

int IoTempowerWolfsslTransport::rawRead(uint8_t* buf, size_t size) {
    if (!_client.connected()) {
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }
    if (!_client.available()) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    int ret = _client.read(buf, size);
    if (ret <= 0) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    return ret;
}

void IoTempowerWolfsslTransport::cleanupTls() {
    _tls_connected = false;
    if (_ssl) {
        wolfSSL_shutdown(_ssl);
        wolfSSL_free(_ssl);
        _ssl = NULL;
    }
    if (_ctx) {
        wolfSSL_CTX_free(_ctx);
        _ctx = NULL;
    }
}

#if defined(ESP32)
IoTempowerWolfsslMqttClient::IoTempowerWolfsslMqttClient(
    espMqttClientTypes::UseInternalTask useInternalTask)
    : MqttClientSetup(useInternalTask),
      _client(new IoTempowerWolfsslTransport()) {
    _transport = _client;
}

IoTempowerWolfsslMqttClient::IoTempowerWolfsslMqttClient(uint8_t priority, uint8_t core)
    : MqttClientSetup(espMqttClientTypes::UseInternalTask::YES, priority, core),
      _client(new IoTempowerWolfsslTransport()) {
    _transport = _client;
}
#else
IoTempowerWolfsslMqttClient::IoTempowerWolfsslMqttClient()
    : MqttClientSetup(espMqttClientTypes::UseInternalTask::NO),
      _client(new IoTempowerWolfsslTransport()) {
    _transport = _client;
}
#endif

IoTempowerWolfsslMqttClient::~IoTempowerWolfsslMqttClient() {
    delete _client;
}

IoTempowerWolfsslMqttClient& IoTempowerWolfsslMqttClient::setCACert(const char* ca_cert) {
    _client->setCACert(ca_cert);
    return *this;
}

IoTempowerWolfsslMqttClient& IoTempowerWolfsslMqttClient::setBufferSizes(int rx, int tx) {
    (void)rx;
    (void)tx;
    return *this;
}

#endif
