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
        void setCACertDer(const unsigned char* ca_cert, unsigned int ca_cert_len);
        void setPreSharedKey(
            const char* identity,
            const unsigned char* key,
            unsigned int key_len);

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
        const unsigned char* _ca_cert;
        long _ca_cert_len;
        int _ca_cert_type;
        const char* _psk_identity;
        const unsigned char* _psk_key;
        unsigned int _psk_key_len;
        bool _psk_enabled;
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

static bool iotempower_wolfssl_initialized = false;
static const char* iotempower_wolfssl_psk_identity = NULL;
static const unsigned char* iotempower_wolfssl_psk_key = NULL;
static unsigned int iotempower_wolfssl_psk_key_len = 0;

static unsigned int iotempower_wolfssl_psk_client_cb(
        WOLFSSL* ssl,
        const char* hint,
        char* identity,
        unsigned int identity_max_len,
        unsigned char* key,
        unsigned int key_max_len) {
    (void)ssl;
    (void)hint;
    if (!identity || !key || !iotempower_wolfssl_psk_identity ||
            !iotempower_wolfssl_psk_key || iotempower_wolfssl_psk_key_len == 0) {
        return 0;
    }

    size_t identity_len = strlen(iotempower_wolfssl_psk_identity);
    if (identity_len + 1 > identity_max_len ||
            iotempower_wolfssl_psk_key_len > key_max_len) {
        return 0;
    }

    memcpy(identity, iotempower_wolfssl_psk_identity, identity_len);
    identity[identity_len] = '\0';
    memcpy(key, iotempower_wolfssl_psk_key, iotempower_wolfssl_psk_key_len);
    return iotempower_wolfssl_psk_key_len;
}

IoTempowerWolfsslTransport::IoTempowerWolfsslTransport()
    : _ctx(NULL),
      _ssl(NULL),
      _ca_cert(NULL),
      _ca_cert_len(0),
      _ca_cert_type(SSL_FILETYPE_PEM),
      _psk_identity(NULL),
      _psk_key(NULL),
      _psk_key_len(0),
      _psk_enabled(false),
      _tls_connected(false) {
}

IoTempowerWolfsslTransport::~IoTempowerWolfsslTransport() {
    stop();
}

void IoTempowerWolfsslTransport::setCACert(const char* ca_cert) {
    _ca_cert = reinterpret_cast<const unsigned char*>(ca_cert);
    _ca_cert_len = ca_cert ? static_cast<long>(strlen(ca_cert)) : 0;
    _ca_cert_type = SSL_FILETYPE_PEM;
    _psk_enabled = false;
}

void IoTempowerWolfsslTransport::setCACertDer(
        const unsigned char* ca_cert,
        unsigned int ca_cert_len) {
    _ca_cert = ca_cert;
    _ca_cert_len = static_cast<long>(ca_cert_len);
    _ca_cert_type = SSL_FILETYPE_ASN1;
    _psk_enabled = false;
}

void IoTempowerWolfsslTransport::setPreSharedKey(
        const char* identity,
        const unsigned char* key,
        unsigned int key_len) {
    _psk_identity = identity;
    _psk_key = key;
    _psk_key_len = key_len;
    _psk_enabled = identity && *identity && key && key_len > 0;
    if (_psk_enabled) {
        iotempower_wolfssl_psk_identity = identity;
        iotempower_wolfssl_psk_key = key;
        iotempower_wolfssl_psk_key_len = key_len;
    }
}

bool IoTempowerWolfsslTransport::connect(IPAddress ip, uint16_t port) {
    char ip_buffer[16];
    snprintf(ip_buffer, sizeof(ip_buffer), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    return connect(ip_buffer, port);
}

bool IoTempowerWolfsslTransport::connect(const char* host, uint16_t port) {
    stop();
    if (!host || !*host || (!_psk_enabled && (!_ca_cert || _ca_cert_len <= 0))) {
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
    if (!iotempower_wolfssl_initialized) {
        if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
            Serial.printf("wolfSSL init failed, heap=%u\n", ESP.getFreeHeap());
            return false;
        }
        iotempower_wolfssl_initialized = true;
    }

    WOLFSSL_METHOD* method = wolfTLSv1_2_client_method();
    if (!method) {
        Serial.printf("wolfSSL TLS 1.2 method unavailable, heap=%u\n", ESP.getFreeHeap());
        return false;
    }

    _ctx = wolfSSL_CTX_new(method);
    if (!_ctx) {
        Serial.printf("wolfSSL context allocation failed, heap=%u\n", ESP.getFreeHeap());
        return false;
    }

#ifdef MQTT_TLS_MODE_PSK
    if (wolfSSL_CTX_set_cipher_list(_ctx, "PSK-AES128-GCM-SHA256") != WOLFSSL_SUCCESS) {
        Serial.printf("wolfSSL PSK cipher unavailable, heap=%u\n", ESP.getFreeHeap());
        return false;
    }
#else
    if (wolfSSL_CTX_set_cipher_list(_ctx, "ECDHE-ECDSA-AES128-GCM-SHA256") != WOLFSSL_SUCCESS) {
        Serial.printf("wolfSSL ECDSA cipher unavailable, heap=%u\n", ESP.getFreeHeap());
        return false;
    }
#endif

#ifdef HAVE_MAX_FRAGMENT
    wolfSSL_CTX_UseMaxFragment(_ctx, WOLFSSL_MFL_2_10);
#endif

#if defined(HAVE_SUPPORTED_CURVES) && !defined(MQTT_TLS_MODE_PSK)
    if (wolfSSL_CTX_UseSupportedCurve(_ctx, WOLFSSL_ECC_SECP256R1) != WOLFSSL_SUCCESS) {
        Serial.printf("wolfSSL supported-curve setup failed, heap=%u\n", ESP.getFreeHeap());
        return false;
    }
#endif

#ifndef MQTT_TLS_MODE_PSK
    wolfSSL_CTX_set_verify(_ctx, SSL_VERIFY_PEER, NULL);
#endif
    wolfSSL_SetIOSend(_ctx, iotempower_wolfssl_send);
    wolfSSL_SetIORecv(_ctx, iotempower_wolfssl_recv);

#ifdef MQTT_TLS_MODE_PSK
    wolfSSL_CTX_set_psk_client_callback(_ctx, iotempower_wolfssl_psk_client_cb);
#else
    if (wolfSSL_CTX_load_verify_buffer(
            _ctx,
            _ca_cert,
            _ca_cert_len,
            _ca_cert_type) != WOLFSSL_SUCCESS) {
        Serial.printf("wolfSSL CA load failed, heap=%u\n", ESP.getFreeHeap());
        return false;
    }
#endif

    _ssl = wolfSSL_new(_ctx);
    if (!_ssl) {
        Serial.printf("wolfSSL session allocation failed, heap=%u\n", ESP.getFreeHeap());
        return false;
    }

    wolfSSL_SetIOReadCtx(_ssl, this);
    wolfSSL_SetIOWriteCtx(_ssl, this);
#ifdef MQTT_TLS_MODE_PSK
    wolfSSL_set_psk_client_callback(_ssl, iotempower_wolfssl_psk_client_cb);
#endif
#ifndef MQTT_TLS_MODE_PSK
    wolfSSL_check_domain_name(_ssl, host);
#endif

#if defined(HAVE_SNI) && !defined(MQTT_TLS_MODE_PSK)
    wolfSSL_UseSNI(_ssl, WOLFSSL_SNI_HOST_NAME, host, static_cast<unsigned short>(strlen(host)));
#endif

    unsigned long deadline = millis() + 15000;
    while (millis() < deadline) {
        int ret = wolfSSL_connect(_ssl);
        if (ret == WOLFSSL_SUCCESS) {
            Serial.printf("wolfSSL connected, heap=%u\n", ESP.getFreeHeap());
            _tls_connected = true;
            return true;
        }

        int err = wolfSSL_get_error(_ssl, ret);
        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
            Serial.printf("wolfSSL_connect failed ret=%d err=%d heap=%u\n",
                ret, err, ESP.getFreeHeap());
            return false;
        }
        delay(1);
    }

    Serial.printf("wolfSSL_connect timed out, heap=%u\n", ESP.getFreeHeap());
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
    bool was_connected = _tls_connected;
    _tls_connected = false;
    if (_ssl) {
        if (was_connected) {
            wolfSSL_shutdown(_ssl);
        }
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

IoTempowerWolfsslMqttClient& IoTempowerWolfsslMqttClient::setCACertDer(
        const unsigned char* ca_cert,
        unsigned int ca_cert_len) {
    _client->setCACertDer(ca_cert, ca_cert_len);
    return *this;
}

IoTempowerWolfsslMqttClient& IoTempowerWolfsslMqttClient::setPreSharedKey(
        const char* identity,
        const unsigned char* key,
        unsigned int key_len) {
    _client->setPreSharedKey(identity, key, key_len);
    return *this;
}

IoTempowerWolfsslMqttClient& IoTempowerWolfsslMqttClient::setBufferSizes(int rx, int tx) {
    (void)rx;
    (void)tx;
    return *this;
}

#endif
