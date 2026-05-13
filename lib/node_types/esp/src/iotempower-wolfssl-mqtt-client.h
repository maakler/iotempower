#ifndef _IOTEMPOWER_WOLFSSL_MQTT_CLIENT_H_
#define _IOTEMPOWER_WOLFSSL_MQTT_CLIENT_H_

#include <espMqttClient.h>

class IoTempowerWolfsslTransport;

class IoTempowerWolfsslMqttClient : public MqttClientSetup<IoTempowerWolfsslMqttClient> {
    public:
        ~IoTempowerWolfsslMqttClient();

#if defined(ESP32)
        explicit IoTempowerWolfsslMqttClient(espMqttClientTypes::UseInternalTask useInternalTask);
        explicit IoTempowerWolfsslMqttClient(uint8_t priority = 1, uint8_t core = 1);
#else
        IoTempowerWolfsslMqttClient();
#endif

        IoTempowerWolfsslMqttClient& setCACert(const char* ca_cert);
        IoTempowerWolfsslMqttClient& setCACertDer(
            const unsigned char* ca_cert,
            unsigned int ca_cert_len);
        IoTempowerWolfsslMqttClient& setPreSharedKey(
            const char* identity,
            const unsigned char* key,
            unsigned int key_len);
        IoTempowerWolfsslMqttClient& setBufferSizes(int rx, int tx);

    private:
        IoTempowerWolfsslTransport* _client;
};

#endif
