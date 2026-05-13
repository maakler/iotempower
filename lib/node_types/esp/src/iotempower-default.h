// global/static iotempower configuration values

#ifndef _IOTEMPOWER_DEFAULT_H_
#define _IOTEMPOWER_DEFAULT_H_

//#define IOTEMPOWER_RECONFIG_MAGIC "uiotpassreset"
#ifndef IOTEMPOWER_AP_RECONFIG_NAME
#define IOTEMPOWER_AP_RECONFIG_NAME "uiot-node"
#endif
#ifndef IOTEMPOWER_AP_RECONFIG_PASSWORD
#define IOTEMPOWER_AP_RECONFIG_PASSWORD "iotempire"
#endif
#ifndef IOTEMPOWER
#define IOTEMPOWER "iotempower"
#endif
#ifndef IOTEMPOWER_FLASH_DEFAULT_PASSWORD
#define IOTEMPOWER_FLASH_DEFAULT_PASSWORD IOTEMPOWER
#endif
#ifndef IOTEMPOWER_MAX_DEVICES
#define IOTEMPOWER_MAX_DEVICES 32
#endif
#ifndef IOTEMPOWER_MAX_SUBDEVICES
#define IOTEMPOWER_MAX_SUBDEVICES 16
#endif
#ifndef IOTEMPOWER_MAX_STRLEN
#define IOTEMPOWER_MAX_STRLEN 127
#endif
// max length of a network buffer
#ifndef IOTEMPOWER_MAX_BUFLEN
#define IOTEMPOWER_MAX_BUFLEN 1024
#endif
#ifndef MIN_PUBLISH_TIME_MS
#define MIN_PUBLISH_TIME_MS 20  // posting every 20ms allowed -> only 50messages per second (else network stacks seems to run full)- TODO: check if this is too conservative or too much
#endif
#ifndef LOG_LINE_MAX_LEN
#define LOG_LINE_MAX_LEN 128
#endif
#ifndef IOTEMPOWER_MAX_LED_STRIPS
#define IOTEMPOWER_MAX_LED_STRIPS 8
#endif
#ifndef IOTEMPOWER_MAX_ANIMATOR_COMMANDS
#define IOTEMPOWER_MAX_ANIMATOR_COMMANDS 16
#endif
#ifndef IOTEMPOWER_MAX_TRIGGER
#define IOTEMPOWER_MAX_TRIGGER 4294967295L
#endif
#ifndef IOTEMPOWER_DO_LATER_MAP_SIZE
#define IOTEMPOWER_DO_LATER_MAP_SIZE 64
#endif
#ifndef IOTEMPOWER_MAX_DO_LATER_INTERVAL
#define IOTEMPOWER_MAX_DO_LATER_INTERVAL (3600000L*24L) // 24 hours max delay, close to half overrun (72h)
#endif
#endif // _IOTEMPOWER_DEFAULT_H_
