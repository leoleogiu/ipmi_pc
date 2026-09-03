#ifndef IPMI_DEFS_H
#define IPMI_DEFS_H

#include <stdint.h>

// --- Configurazione Rete Allarmi ---
#define SNMP_TRAP_TARGET_IP "127.0.0.1"  // Indirizzo IP del destinatario delle notifiche SNMP
#define SNMP_TRAP_PORT      162

// --- Versione e Variabili globali ---
#define IPMI_SIM_VERSION "3.3.0"
extern int ipmi_debug;

// PASSWORD BMC (per sessione IPMI)
extern const char *BMC_PASSWORD; // Password BMC predefinita

// --- NetFunction Codes ---
#define IPMI_NETFN_CHASSIS       0x00
#define IPMI_NETFN_BRIDGE        0x02
#define IPMI_NETFN_SENSOR_EVENT  0x04
#define IPMI_NETFN_APP           0x06
#define IPMI_NETFN_STORAGE       0x0A
#define IPMI_NETFN_OEM           0x30  // NetFn Custom OEM per GPIO e funzioni proprietarie

// --- IPMI Commands: CHASSIS (NetFn 0x00) ---
#define IPMI_CMD_GET_CHASSIS_STATUS     0x01
#define IPMI_CMD_CHASSIS_CONTROL        0x02

// --- IPMI Commands: SENSOR / EVENT (NetFn 0x04) ---
#define IPMI_CMD_SET_SENSOR_THRESHOLD   0x26
#define IPMI_CMD_GET_SENSOR_THRESHOLD   0x27
#define IPMI_CMD_SET_SENSOR_EVENT_ENABLE 0x28
#define IPMI_CMD_GET_SENSOR_EVENT_ENABLE 0x29
#define IPMI_CMD_SET_SENSOR_HYSTERESIS  0x2A
#define IPMI_CMD_GET_SENSOR_HYSTERESIS  0x2B
#define IPMI_CMD_GET_SENSOR_READING     0x2D

// --- IPMI Commands: APP (NetFn 0x06) ---
#define IPMI_CMD_GET_DEVICE_ID          0x01
#define IPMI_CMD_GET_CHANNEL_AUTH_CAP   0x38
#define IPMI_CMD_GET_SESSION_CHALLENGE  0x39
#define IPMI_CMD_ACTIVATE_SESSION       0x3A
#define IPMI_CMD_SET_SESSION_PRIV_LEVEL 0x3B 
#define IPMI_CMD_CLOSE_SESSION          0x3C 

// --- IPMI Commands: STORAGE / SEL (NetFn 0x0A) ---
#define IPMI_CMD_GET_FRU_INFO           0x10
#define IPMI_CMD_READ_FRU_DATA          0x11
#define IPMI_CMD_GET_SDR_INFO           0x20
#define IPMI_CMD_RESERVE_SDR_REPO       0x22
#define IPMI_CMD_GET_SDR                0x23
#define IPMI_CMD_GET_SEL_INFO           0x40
#define IPMI_CMD_RESERVE_SEL            0x42
#define IPMI_CMD_GET_SEL_ENTRY          0x43
#define IPMI_CMD_ADD_SEL_ENTRY          0x44
#define IPMI_CMD_DELETE_SEL_ENTRY       0x46
#define IPMI_CMD_CLEAR_SEL              0x47

// --- IPMI Commands: OEM GPIO (NetFn 0x30) ---
#define IPMI_CMD_OEM_SET_GPIO           0x10  // Imposta lo stato di un pin GPIO
#define IPMI_CMD_OEM_GET_GPIO           0x11  // Legge lo stato di un pin GPIO

// --- Completion Codes ---
#define IPMI_CC_OK                      0x00
#define IPMI_CC_INVALID_CMD             0xC1
#define IPMI_CC_INVALID_RESERVATION     0xC5 // Reservation canceled or invalid reservation ID
#define IPMI_CC_OUT_OF_SPACE            0xC6 // Command response exceeds size limit / SEL Repository Full
#define IPMI_CC_REQ_DATA_LEN_INVALID    0xC7 // Request data length invalid
#define IPMI_CC_REQ_DATA_NOT_PRESENT    0xCB // Requested Sensor, data, or record not present
#define IPMI_CC_PARAM_OUT_OF_RANGE      0xCC // Parameter out of range

#define IPMI_CC_INSUFFICIENT_PRIVILEGE  0xD4 // Insufficient privilege level

/* Codici aggiuntivi per gestione sessioni e autenticazione */
#define IPMI_CC_INVALID_AUTH_TYPE       0x81  /* Invalid authentication type */
#define IPMI_CC_INVALID_SESSION_ID      0x82  /* Invalid session ID */
#define IPMI_CC_INVALID_PRIV_LEVEL      0x84  /* Invalid privilege level */
#define IPMI_CC_INVALID_AUTH_CODE       0x85  /* Invalid authentication code */

// STRUTTURA SEL ENTRY (16 byte standard IPMI)
typedef struct {
    uint16_t record_id;
    uint8_t  record_type;
    uint32_t timestamp;
    uint16_t gen_id;
    uint8_t  evm_rev;
    uint8_t  sensor_type;
    uint8_t  sensor_num;
    uint8_t  event_type;
    uint8_t  event_data[3];
} __attribute__((packed)) sel_entry_t;

uint16_t ipmi_process_packet(const uint8_t *in, uint16_t in_len, uint8_t *out);
void ipmi_sensor_monitoring_tick(void);
void ipmi_sensors_init(void);

#endif