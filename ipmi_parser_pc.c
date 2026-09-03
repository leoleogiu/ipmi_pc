// ipmi_parser_pc.c
#include "ipmi_defs.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdbool.h>

int ipmi_debug = 0;

#define IPMI_LOG(fmt, ...) do { if (ipmi_debug) printf(fmt, ##__VA_ARGS__); } while(0)

static uint8_t g_chassis_power_on = 1;
static uint8_t g_gpio_pins[32] = {0};

static uint8_t g_session_auth_type = 0x00; // Default: Nessuna autenticazione o stato iniziale

// Gestione Repository SEL (System Event Log)
#define MAX_SEL_ENTRIES 32
static sel_entry_t g_sel_log[MAX_SEL_ENTRIES];
static uint16_t g_sel_count = 0;
static uint16_t g_sel_next_id = 0x0001;
static uint16_t g_sel_reservation_id = 0x0000;

static uint32_t g_active_session_id          = 0x00000000;
static uint8_t  g_current_session_priv_level = 0x04; // 0x04 = ADMIN, 0x02 = USER
static uint8_t  g_max_session_priv_level     = 0x04;

const char *BMC_PASSWORD = "admin"; // Password BMC predefinita

static uint8_t ipmi_checksum(const uint8_t *data, uint16_t len) {
    uint8_t sum = 0;
    for (uint16_t i = 0; i < len; i++) sum += data[i];
    return (uint8_t)(-sum);
}

// Funzione ausiliaria per invio pacchetto Trap SNMP UDP
void send_snmp_pet_trap(uint8_t sensor_id, uint8_t reading, uint8_t threshold)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    struct sockaddr_in trap_addr;
    memset(&trap_addr, 0, sizeof(trap_addr));
    trap_addr.sin_family      = AF_INET;
    trap_addr.sin_port        = htons(162);
    trap_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    uint8_t packet[256];
    uint8_t idx = 0;

    /* Header ASN.1 Sequence */
    packet[idx++] = 0x30;
    uint8_t len_pos = idx++;

    /* Version: SNMP v1 (0x00) */
    packet[idx++] = 0x02; packet[idx++] = 0x01; packet[idx++] = 0x00;

    /* Community: "public" */
    packet[idx++] = 0x04; packet[idx++] = 0x06;
    memcpy(&packet[idx], "public", 6);
    idx += 6;

    /* PDU Type: Trap-v1 (0xA4) */
    packet[idx++] = 0xA4;
    uint8_t pdu_len_pos = idx++;

    /* Enterprise OID: 1.3.6.1.4.1.3183 (IPMI Standard) */
    packet[idx++] = 0x06; packet[idx++] = 0x08;
    packet[idx++] = 0x2B; packet[idx++] = 0x06;
    packet[idx++] = 0x01; packet[idx++] = 0x04;
    packet[idx++] = 0x01; packet[idx++] = 0x98;
    packet[idx++] = 0x6F; packet[idx++] = 0x00;

    /* Agent IP Address: 0.0.0.0 */
    packet[idx++] = 0x40; packet[idx++] = 0x04;
    packet[idx++] = 0x00; packet[idx++] = 0x00;
    packet[idx++] = 0x00; packet[idx++] = 0x00;

    /* Generic Trap: 6 (enterpriseSpecific) */
    packet[idx++] = 0x02; packet[idx++] = 0x01; packet[idx++] = 0x06;

    /* Specific Trap: ID Sensore */
    packet[idx++] = 0x02; packet[idx++] = 0x01; packet[idx++] = sensor_id;

    /* Time Stamp: 0 */
    packet[idx++] = 0x43; packet[idx++] = 0x01; packet[idx++] = 0x00;

    /* Varbind List */
    packet[idx++] = 0x30;
    uint8_t varbind_list_len_pos = idx++;

    /* Varbind 1: Reading */
    packet[idx++] = 0x30; packet[idx++] = 0x0A;
    packet[idx++] = 0x06; packet[idx++] = 0x05;
    packet[idx++] = 0x2B; packet[idx++] = 0x06; packet[idx++] = 0x01; packet[idx++] = 0x01; packet[idx++] = 0x01;
    packet[idx++] = 0x02; packet[idx++] = 0x01;
    packet[idx++] = reading;

    /* Varbind 2: Threshold */
    packet[idx++] = 0x30; packet[idx++] = 0x0A;
    packet[idx++] = 0x06; packet[idx++] = 0x05;
    packet[idx++] = 0x2B; packet[idx++] = 0x06; packet[idx++] = 0x01; packet[idx++] = 0x01; packet[idx++] = 0x02;
    packet[idx++] = 0x02; packet[idx++] = 0x01;
    packet[idx++] = threshold;

    /* Calcolo lunghezze BER dinamiche */
    packet[varbind_list_len_pos] = idx - varbind_list_len_pos - 1;
    packet[pdu_len_pos]          = idx - pdu_len_pos - 1;
    packet[len_pos]              = idx - len_pos - 1;

    sendto(sock, packet, idx, 0, (struct sockaddr *)&trap_addr, sizeof(trap_addr));
    close(sock);
}

static const uint8_t g_fru_data[64] = {
    0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFE,
    0x01, 0x06, 0x00, 0xC0, 0xC6, 0xF0,
    0xC7, 'S','T','M','i','c','r','o',
    0xCB, 'S','T','M','3','2','F','4','-','B','M','C',
    0xCB, 'S','N','-','2','0','2','6','-','0','0','1',
    0xC5, 'S','T','M','3','2',
    0xC0, 0xC1, 0x00, 0x54,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t g_sdr_temp[] = {
    0x34, 0x00, 0x51, 0x01, 0x33, // Record ID: 0x0034 | SDR v1.5 | Full Sensor | Length: 51 byte
    0x20, 0x00, 0x01, 0x07, 0x01, 0x7F, 0x68,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x38, 0x38, 0x80, 0x01, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x19, 0x32, 0x00, 0x7F, 0x80,
    0x50, 0x46, 0x3C,             // Thresholds: 80°C (0x50), 70°C (0x46), 60°C (0x3C)
    0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00,
    0xC8, 'M','C','U',' ','T','e','m','p'
};

//NOK
static const uint8_t g_sdr_volt[] = { 
    0x10, 0x00, 0x51, 0x01, 0x33, // Header SDR (5 byte)
    0x20, 0x00, 0x02, 0x07, 0x01, 0x7F, 0x68, 0x02, 0x01, // Config (9 byte)
    
    // --- BLOCCO MASCHERE CORRETTO (6 byte) ---
    0x3F, 0x00, // Offset 0x0E-0x0F: Assertion Mask (Abilita allarmi Lower e Upper)
    0x3F, 0x00, // Offset 0x10-0x11: Deassertion Mask
    0x3F, 0x3F, // Offset 0x12-0x13: Read Mask (Cambiato da 0x38, 0x38 a 0x3F, 0x3F per togliere i "na")
    
    0x00, 0x04, 0x00, 0x00, // Modificato in 0x00 (Unsigned) per correggere la lettura negativa
    0x14, 0x00, 0x00, 0x00, 0x00, 0xD0, 0x00, // Matrice matematica intatta (M=20, B=0, R-Exp=-3)
    
    0xA5,                               // Lettura Nominale: 3.30V (0xA5)
    0xC8, 0x00, 0xFF, 0x00,             
    
    // --- SOGLIE CORRETTE PER SITUAZIONE OK/NOK ---
    0xB4, 0xAF, 0xAA,                   // Upper: 3.60V (0xB4) | 3.50V (0xAF) | 3.40V (0xAA)
    0x9B, 0xA0, 0xA3,                   // LNR=3.10V, LC=3.20V, LNC=3.26V CORRETTO
    
    0x02, 0x02, 0x00, 0x00, 0x00, 0xC8, 
    '3', '.', '3', 'V', ' ', 'V', 'C', 'C' // ID Sensore
};

// --- STRUTTURA ED ARCHITETTURA MULTI-SENSORE ---
typedef struct ipmi_sensor ipmi_sensor_t;

// Definizione del tipo puntatore a funzione per la lettura sensore
typedef uint8_t (*sensor_read_fn_t)(ipmi_sensor_t *s);

struct ipmi_sensor {
    uint8_t  sensor_num;     // Numero/ID Sensore IPMI (es. 0x01, 0x02)
    uint8_t  sensor_type;    // Tipo Sensore (0x01 = Temp, 0x02 = Voltage, ecc.)
    uint8_t  raw_reading;    // Lettura istantanea grezza in RAM
    uint8_t  th_lnr;         // Lower Non-Recoverable
    uint8_t  th_lc;          // Lower Critical
    uint8_t  th_lnc;         // Lower Non-Critical
    uint8_t  th_unc;         // Upper Non-Critical
    uint8_t  th_uc;          // Upper Critical
    uint8_t  th_unr;         // Upper Non-Recoverable
    uint8_t  pos_hysteresis; // Positive Hysteresis (Go-High)
    uint8_t  neg_hysteresis; // Negative Hysteresis (Go-Low)
    uint8_t  event_enable;   // Controllo scansione/eventi (default 0xC0)
    uint8_t  prev_status;    // Ultimo stato calcolato per monitoraggio tick
    // Callback per la lettura hardware/simulata
    sensor_read_fn_t read_func;    
    const uint8_t *sdr_data; // Puntatore al record SDR statico
    uint16_t sdr_size;       // Dimensione del record SDR
};

// Esempio: Lettura canale ADC / Bus I2C per la tensione 3.3V
uint8_t read_voltage_3v3_channel(ipmi_sensor_t *s) {
    // In un sistema reale: i2c_read(BUS_1, ADDR_ADC, REG_VOLT);
    // Qui restituiresti il valore RAW converting da mV/ADC
    if (s) {
        // Lettura hardware OK: Bit 6 = 0 (Reading Valid), Bit 7 = 0 (Scanning Active)
        s->event_enable &= ~(1 << 6); 
    }
    return 165; // 3.30 V
}

// Esempio: Lettura sensore di temperatura CPU
uint8_t read_temp_cpu_sensor(ipmi_sensor_t *s) {
    // Es. lettura da /sys/class/hwmon/hwmon0/temp1_input
    if (s) {
        // Lettura hardware OK: Bit 6 = 0 (Reading Valid), Bit 7 = 0 (Scanning Active)
        s->event_enable &= ~(1 << 6); 
    }
    return 45; // 45 °C
}

// Vettore Globale Sensori del BMC
static ipmi_sensor_t g_sensors[] = {
    { 0x01, 0x01, 38,  0,   0,   0,   0x3C, 0x46, 0x50, 0x02, 0x02, 0x00, 0, .read_func = read_temp_cpu_sensor, g_sdr_temp, sizeof(g_sdr_temp) },
    { 0x02, 0x02, 165, 0x9B, 0xA0, 0xA3, 0xAA, 0xAF, 0xB4, 0x02, 0x02, 0x00, .read_func = read_voltage_3v3_channel, g_sdr_volt, sizeof(g_sdr_volt) }
};

#define NUM_SENSORS (sizeof(g_sensors) / sizeof(g_sensors[0]))

// Funzione Helper per ricerca sensore
static ipmi_sensor_t* get_sensor(uint8_t sensor_num) {
    for (size_t i = 0; i < NUM_SENSORS; i++) {
        if (g_sensors[i].sensor_num == sensor_num) return &g_sensors[i];
    }
    return NULL;
}

// Inizializzazione automatica delle soglie di default estraendole dai record SDR Full Sensor
void ipmi_sensors_init(void) {
    for (size_t i = 0; i < NUM_SENSORS; i++) {
        ipmi_sensor_t *s = &g_sensors[i];
        if (s->sdr_data != NULL && s->sdr_size >= 42) {
            s->th_unr = s->sdr_data[36]; // Upper Non-Recoverable
            s->th_uc  = s->sdr_data[37]; // Upper Critical
            s->th_unc = s->sdr_data[38]; // Upper Non-Critical
            s->th_lnr = s->sdr_data[39]; // Lower Non-Recoverable
            s->th_lc  = s->sdr_data[40]; // Lower Critical
            s->th_lnc = s->sdr_data[41]; // Lower Non-Critical
        }
        if (s->sdr_data != NULL && s->sdr_size >= 44) {
            s->pos_hysteresis = s->sdr_data[42]; // Positive Hysteresis
            s->neg_hysteresis = s->sdr_data[43]; // Negative Hysteresis
        }
    }
}

static uint16_t ipmi_add_sel_entry_internal(uint8_t sensor_type, uint8_t sensor_num, uint8_t event_type, uint8_t ed1, uint8_t ed2, uint8_t ed3) {
    if (g_sel_count >= MAX_SEL_ENTRIES) return 0xFFFF;
    sel_entry_t *entry = &g_sel_log[g_sel_count];
    entry->record_id   = g_sel_next_id++;
    entry->record_type = 0x02; // Standard System Event Record (IPMI)
    entry->timestamp   = 0x00000000;
    entry->gen_id      = 0x0020; // BMC Generator ID
    entry->evm_rev     = 0x04;   // IPMI Event Message Format (v1.5/v2.0)
    entry->sensor_type = sensor_type;
    entry->sensor_num  = sensor_num;
    entry->event_type  = event_type;
    entry->event_data[0] = ed1;
    entry->event_data[1] = ed2;
    entry->event_data[2] = ed3;
    g_sel_count++;
    return entry->record_id;
}

void ipmi_sensor_monitoring_tick(void) {
    for (size_t i = 0; i < NUM_SENSORS; i++) {
        ipmi_sensor_t *s = &g_sensors[i];
        uint8_t curr_status = 0;

        // 1. Se lo scanning è disabilitato (Bit 7 = 0), ignora il sensore
        if (!(s->event_enable & (1 << 7))) {
            continue;
        }

        // 2. Acquisizione hardware della lettura raw
        if (s->read_func != NULL) {
            s->raw_reading = s->read_func(s);
        }

        // 3. Se la lettura è non valida (Bit 5 = 1), ignora la valutazione delle soglie
        if (s->event_enable & (1 << 5)) {
            continue;
        }

        // 4. Valutazione dello stato delle soglie con Isteresi
        
        // --- SOGLIE LOWER (LNC: bit 0, LC: bit 1, LNR: bit 2) ---
        if (s->prev_status & (1 << 0)) {
            uint16_t clear_th = (uint16_t)s->th_lnc + s->pos_hysteresis;
            if (clear_th > 255) clear_th = 255;
            if (s->raw_reading <= clear_th) curr_status |= (1 << 0);
        } else {
            if (s->raw_reading <= s->th_lnc) curr_status |= (1 << 0);
        }

        if (s->prev_status & (1 << 1)) {
            uint16_t clear_th = (uint16_t)s->th_lc + s->pos_hysteresis;
            if (clear_th > 255) clear_th = 255;
            if (s->raw_reading <= clear_th) curr_status |= (1 << 1);
        } else {
            if (s->raw_reading <= s->th_lc) curr_status |= (1 << 1);
        }

        if (s->prev_status & (1 << 2)) {
            uint16_t clear_th = (uint16_t)s->th_lnr + s->pos_hysteresis;
            if (clear_th > 255) clear_th = 255;
            if (s->raw_reading <= clear_th) curr_status |= (1 << 2);
        } else {
            if (s->raw_reading <= s->th_lnr) curr_status |= (1 << 2);
        }

        // --- SOGLIE UPPER (UNC: bit 3, UC: bit 4, UNR: bit 5) ---
        if (s->prev_status & (1 << 3)) {
            uint8_t clear_th = (s->th_unc > s->neg_hysteresis) ? (s->th_unc - s->neg_hysteresis) : 0;
            if (s->raw_reading >= clear_th) curr_status |= (1 << 3);
        } else {
            if (s->raw_reading >= s->th_unc) curr_status |= (1 << 3);
        }

        if (s->prev_status & (1 << 4)) {
            uint8_t clear_th = (s->th_uc > s->neg_hysteresis) ? (s->th_uc - s->neg_hysteresis) : 0;
            if (s->raw_reading >= clear_th) curr_status |= (1 << 4);
        } else {
            if (s->raw_reading >= s->th_uc) curr_status |= (1 << 4);
        }

        if (!(s->prev_status & (1 << 5))) {
            uint8_t clear_th = (s->th_unr > s->neg_hysteresis) ? (s->th_unr - s->neg_hysteresis) : 0;
            if (s->raw_reading >= clear_th) curr_status |= (1 << 5);
        } else {
            if (s->raw_reading >= s->th_unr) curr_status |= (1 << 5);
        }

        // 5. Gestione cambio di stato ed emissione eventi
        if (curr_status != s->prev_status) {
            uint8_t newly_asserted   = curr_status & ~s->prev_status;
            uint8_t newly_deasserted = s->prev_status & ~curr_status;

            IPMI_LOG("[MONITORING] Cambio stato sensore 0x%02X | Status: 0x%02X (Ass: 0x%02X, Deass: 0x%02X)\n", 
                     s->sensor_num, curr_status, newly_asserted, newly_deasserted);

            // Genera eventi SEL e Trap SNMP SOLO SE il Bit 6 è 0 (Event Messages Enabled)
            if (s->event_enable & (1 << 6)) {
                // --- ALLARMI ATTIVATI (ASSERTIONS - Event Type 0x01) ---
                if (newly_asserted & (1 << 5)) { // UNR
                    ipmi_add_sel_entry_internal(s->sensor_type, s->sensor_num, 0x01, 0x0B, s->raw_reading, s->th_unr);
                    send_snmp_pet_trap(s->sensor_num, s->raw_reading, s->th_unr);
                }
                if (newly_asserted & (1 << 4)) { // UC
                    ipmi_add_sel_entry_internal(s->sensor_type, s->sensor_num, 0x01, 0x09, s->raw_reading, s->th_uc);
                    send_snmp_pet_trap(s->sensor_num, s->raw_reading, s->th_uc);
                }
                if (newly_asserted & (1 << 3)) { // UNC
                    ipmi_add_sel_entry_internal(s->sensor_type, s->sensor_num, 0x01, 0x07, s->raw_reading, s->th_unc);
                    send_snmp_pet_trap(s->sensor_num, s->raw_reading, s->th_unc);
                }
                if (newly_asserted & (1 << 2)) { // LNR
                    ipmi_add_sel_entry_internal(s->sensor_type, s->sensor_num, 0x01, 0x04, s->raw_reading, s->th_lnr);
                    send_snmp_pet_trap(s->sensor_num, s->raw_reading, s->th_lnr);
                }
                if (newly_asserted & (1 << 1)) { // LC
                    ipmi_add_sel_entry_internal(s->sensor_type, s->sensor_num, 0x01, 0x02, s->raw_reading, s->th_lc);
                    send_snmp_pet_trap(s->sensor_num, s->raw_reading, s->th_lc);
                }
                if (newly_asserted & (1 << 0)) { // LNC
                    ipmi_add_sel_entry_internal(s->sensor_type, s->sensor_num, 0x01, 0x00, s->raw_reading, s->th_lnc);
                    send_snmp_pet_trap(s->sensor_num, s->raw_reading, s->th_lnc);
                }

                // --- RIENTRO ALLARMI (DE-ASSERTIONS - Event Type 0x81) ---
                if (newly_deasserted & (1 << 5)) { // UNR
                    ipmi_add_sel_entry_internal(s->sensor_type, s->sensor_num, 0x81, 0x0A, s->raw_reading, s->th_unr);
                }
                if (newly_deasserted & (1 << 4)) { // UC
                    ipmi_add_sel_entry_internal(s->sensor_type, s->sensor_num, 0x81, 0x08, s->raw_reading, s->th_uc);
                }
                if (newly_deasserted & (1 << 3)) { // UNC
                    ipmi_add_sel_entry_internal(s->sensor_type, s->sensor_num, 0x81, 0x06, s->raw_reading, s->th_unc);
                }
                if (newly_deasserted & (1 << 2)) { // LNR
                    ipmi_add_sel_entry_internal(s->sensor_type, s->sensor_num, 0x81, 0x05, s->raw_reading, s->th_lnr);
                }
                if (newly_deasserted & (1 << 1)) { // LC
                    ipmi_add_sel_entry_internal(s->sensor_type, s->sensor_num, 0x81, 0x03, s->raw_reading, s->th_lc);
                }
                if (newly_deasserted & (1 << 0)) { // LNC
                    ipmi_add_sel_entry_internal(s->sensor_type, s->sensor_num, 0x81, 0x01, s->raw_reading, s->th_lnc);
                }
            }

            // Aggiorna SEMPRE lo stato precedente
            s->prev_status = curr_status;
        }
    }
}

uint16_t ipmi_process_packet(const uint8_t *in, uint16_t in_len, uint8_t *out) {
    if (in_len < 4 || in[0] != 0x06) return 0;

    uint8_t rmcp_class = in[3];

    // --- Messaggi ASF (Ping / Pong) ---
    if (rmcp_class == 0x06 && in_len >= 12) {
        if (in[8] == 0x80) {
            uint8_t tag = in[9];
            out[0] = 0x06; out[1] = 0x00; out[2] = 0xFF; out[3] = 0x06;
            out[4] = in[4]; out[5] = in[5]; out[6] = in[6]; out[7] = in[7];
            out[8] = 0x40; out[9] = tag; out[10] = 0x00; out[11] = 0x10;
            out[12] = in[4]; out[13] = in[5]; out[14] = in[6]; out[15] = in[7];
            out[16] = 0x00; out[17] = 0x00; out[18] = 0x00; out[19] = 0x00;
            out[20] = 0x81; out[21] = 0x00;
            memset(&out[22], 0, 6);
            return 28;
        }
        return 0;
    }

    // --- PACCHETTI IPMI (Class 0x07) ---
    if (rmcp_class != 0x07 || in_len < 5) return 0;

    uint8_t auth_type = in[4];
    uint8_t auth_code_len = 0;
    if (auth_type == 0x04 || auth_type == 0x01 || auth_type == 0x02) {
        auth_code_len = 16;
    }

    if (in_len < (21 + auth_code_len)) return 0;

    uint8_t hdr_len = 14 + auth_code_len;
    uint8_t msg_len = in[hdr_len - 1];

    if ((hdr_len + msg_len) > in_len) return 0;

    uint32_t seq_num    = in[5]  | (in[6]  << 8) | (in[7]  << 16) | (in[8]  << 24);
    uint32_t session_id = in[9]  | (in[10] << 8) | (in[11] << 16) | (in[12] << 24);
    
    uint8_t  rs_addr    = in[14 + auth_code_len];
    uint8_t  netfn_lun  = in[15 + auth_code_len];
    uint8_t  rq_addr    = in[17 + auth_code_len];
    uint8_t  rq_seq_lun = in[18 + auth_code_len];
    uint8_t  cmd        = in[19 + auth_code_len];
    uint8_t  netfn      = netfn_lun >> 2;
    
    const uint8_t *req_data = &in[20 + auth_code_len];
    uint16_t req_data_len   = (msg_len >= 7) ? (msg_len - 7) : 0;

    // --- VALIDAZIONE SESSION ID & SICUREZZA ---
    bool is_zero_session_cmd = (netfn == IPMI_NETFN_APP) && (
        cmd == IPMI_CMD_GET_CHANNEL_AUTH_CAP ||
        cmd == IPMI_CMD_GET_SESSION_CHALLENGE
    );
    bool is_activate_cmd = (netfn == IPMI_NETFN_APP && cmd == IPMI_CMD_ACTIVATE_SESSION);

    if (netfn == IPMI_NETFN_APP && cmd == IPMI_CMD_GET_DEVICE_ID) {
        if (session_id != 0 && session_id != g_active_session_id) {
            IPMI_LOG("[SEC] Get Device ID rifiutato: Session ID non valido 0x%08X\r\n", (unsigned int)session_id);
            return 0;
        }
    } else if (is_zero_session_cmd) {
        if (session_id != 0x00000000) {
            IPMI_LOG("[SEC] Pre-session cmd con Session ID non nullo: 0x%08X\r\n", (unsigned int)session_id);
            return 0;
        }
    } else if (is_activate_cmd) {
        if (session_id == 0) {
            IPMI_LOG("[SEC] Activate Session richiede un Session ID non nullo\r\n");
            return 0;
        }
    } else {
        if (g_active_session_id == 0 || session_id != g_active_session_id) {
            IPMI_LOG("[SEC] Richiesta rifiutata: Session ID non valido 0x%08X\r\n", (unsigned int)session_id);
            return 0;
        }
    }

    IPMI_LOG("-> IPMI REQ: NetFn=0x%02X, Cmd=0x%02X (Seq=0x%08X, Data Len=%d, SessionID=0x%08X)\n", 
           netfn, cmd, seq_num, req_data_len, session_id);

    // Preparazione Header Risposta IPMI
    out[0] = 0x06; out[1] = 0x00; out[2] = 0xFF; out[3] = 0x07;
    out[4] = auth_type;
    out[5] = in[5]; out[6] = in[6]; out[7] = in[7]; out[8] = in[8];
    out[9] = in[9]; out[10] = in[10]; out[11] = in[11]; out[12] = in[12];

    if (auth_code_len > 0) {
        memset(&out[13], 0, auth_code_len);
    }

    uint8_t base = 14 + auth_code_len;
    out[base + 0] = rq_addr;
    out[base + 1] = ((netfn + 1) << 2) | (netfn_lun & 0x03);
    out[base + 2] = ipmi_checksum(&out[base + 0], 2);
    out[base + 3] = rs_addr;
    out[base + 4] = rq_seq_lun;
    out[base + 5] = cmd;

    uint8_t *resp_data = &out[base + 6];
    uint16_t data_len = 0;

    // --- NetFn CHASSIS (0x00) ---
    if (netfn == IPMI_NETFN_CHASSIS) {
        switch (cmd) {
            case IPMI_CMD_GET_CHASSIS_STATUS:
                resp_data[0] = IPMI_CC_OK;
                resp_data[1] = g_chassis_power_on ? 0x01 : 0x00;
                resp_data[2] = 0x00; resp_data[3] = 0x00;
                data_len = 4;
                break;

            case IPMI_CMD_CHASSIS_CONTROL: {
                if (req_data_len < 1) {
                    resp_data[0] = IPMI_CC_REQ_DATA_LEN_INVALID; data_len = 1; break;
                }
                if (g_current_session_priv_level < 0x04) {
                    resp_data[0] = IPMI_CC_INSUFFICIENT_PRIVILEGE; data_len = 1; break;
                }
                uint8_t ctrl = req_data[0] & 0x0F;
                resp_data[0] = IPMI_CC_OK;
                if (ctrl == 0x00) { 
                    g_chassis_power_on = 0; g_gpio_pins[17] = 0; 
                    IPMI_LOG("[CHASSIS] POWER OFF -> GPIO 17 = 0\n"); 
                }
                else if (ctrl == 0x01) { 
                    g_chassis_power_on = 1; g_gpio_pins[17] = 1; 
                    IPMI_LOG("[CHASSIS] POWER ON -> GPIO 17 = 1\n"); 
                }
                else if (ctrl == 0x02 || ctrl == 0x03) { 
                    g_chassis_power_on = 1; g_gpio_pins[17] = 1;
                    IPMI_LOG("[CHASSIS] RESET\n"); 
                }
                data_len = 1;
                break;
            }
            default: resp_data[0] = IPMI_CC_INVALID_CMD; data_len = 1;
        }
    }
    // --- NetFn SENSOR / EVENT (0x04) ---
    else if (netfn == IPMI_NETFN_SENSOR_EVENT) {
        switch (cmd) {
            case IPMI_CMD_SET_SENSOR_THRESHOLD: {
                if (req_data_len < 8) {
                    resp_data[0] = IPMI_CC_REQ_DATA_LEN_INVALID; data_len = 1; break;
                }
                if (g_current_session_priv_level < 0x03) {
                    resp_data[0] = IPMI_CC_INSUFFICIENT_PRIVILEGE; data_len = 1; break;
                }

                ipmi_sensor_t *s = get_sensor(req_data[0]);
                if (!s) {
                    resp_data[0] = IPMI_CC_REQ_DATA_NOT_PRESENT; data_len = 1; break;
                }

                uint8_t mask = req_data[1];
                if (mask & (1 << 0)) s->th_lnc = req_data[2];
                if (mask & (1 << 1)) s->th_lc  = req_data[3];
                if (mask & (1 << 2)) s->th_lnr = req_data[4];
                if (mask & (1 << 3)) s->th_unc = req_data[5];
                if (mask & (1 << 4)) s->th_uc  = req_data[6];
                if (mask & (1 << 5)) s->th_unr = req_data[7];

                resp_data[0] = IPMI_CC_OK; data_len = 1;
                break;
            }

            case IPMI_CMD_GET_SENSOR_THRESHOLD: {
                if (req_data_len < 1) {
                    resp_data[0] = IPMI_CC_REQ_DATA_LEN_INVALID; data_len = 1; break;
                }
                ipmi_sensor_t *s = get_sensor(req_data[0]);
                if (!s) {
                    resp_data[0] = IPMI_CC_REQ_DATA_NOT_PRESENT; data_len = 1; break;
                }

                resp_data[0] = IPMI_CC_OK;
                resp_data[1] = 0x3F; // Maschera totale di abilitazione (Lower e Upper)
                resp_data[2] = s->th_lnc;
                resp_data[3] = s->th_lc;
                resp_data[4] = s->th_lnr;
                resp_data[5] = s->th_unc;
                resp_data[6] = s->th_uc;
                resp_data[7] = s->th_unr;
                data_len = 8;
                break;
            }

            case IPMI_CMD_SET_SENSOR_EVENT_ENABLE: {
                if (req_data_len < 2) {
                    resp_data[0] = IPMI_CC_REQ_DATA_LEN_INVALID; data_len = 1; break;
                }                
                ipmi_sensor_t *s = get_sensor(req_data[0]);
                if (s) {
                    s->event_enable = req_data[1];
                    resp_data[0] = IPMI_CC_OK;
                } else {
                    resp_data[0] = IPMI_CC_REQ_DATA_NOT_PRESENT;
                }
                data_len = 1;
                break;
            }

            case IPMI_CMD_GET_SENSOR_EVENT_ENABLE: {
                if (req_data_len < 1) {
                    resp_data[0] = IPMI_CC_REQ_DATA_LEN_INVALID; data_len = 1; break;
                }
                ipmi_sensor_t *s = get_sensor(req_data[0]);
                if (s) {
                    resp_data[0] = IPMI_CC_OK;
                    resp_data[1] = s->event_enable;
                    memset(&resp_data[2], 0, 4);
                    data_len = 6;
                } else {
                    resp_data[0] = IPMI_CC_REQ_DATA_NOT_PRESENT; data_len = 1;
                }
                break;
            }

            case IPMI_CMD_SET_SENSOR_HYSTERESIS: {
                if (req_data_len < 3) {
                    resp_data[0] = IPMI_CC_REQ_DATA_LEN_INVALID; data_len = 1; break;
                }
                if (g_current_session_priv_level < 0x03) {
                    resp_data[0] = IPMI_CC_INSUFFICIENT_PRIVILEGE; data_len = 1; break;
                }
                ipmi_sensor_t *s = get_sensor(req_data[0]);
                if (!s) {
                    resp_data[0] = IPMI_CC_REQ_DATA_NOT_PRESENT; data_len = 1; break;
                }
                s->pos_hysteresis = req_data[2];
                if (req_data_len >= 4) {
                    s->neg_hysteresis = req_data[3];
                } else {
                    s->neg_hysteresis = req_data[2];
                }
                resp_data[0] = IPMI_CC_OK;
                data_len = 1;
                break;
            }

            case IPMI_CMD_GET_SENSOR_HYSTERESIS: {
                if (req_data_len < 1) {
                    resp_data[0] = IPMI_CC_REQ_DATA_LEN_INVALID; data_len = 1; break;
                }
                ipmi_sensor_t *s = get_sensor(req_data[0]);
                if (s) {
                    resp_data[0] = IPMI_CC_OK;
                    resp_data[1] = s->pos_hysteresis;
                    resp_data[2] = s->neg_hysteresis;
                    data_len = 3;
                } else {
                    resp_data[0] = IPMI_CC_REQ_DATA_NOT_PRESENT; data_len = 1;
                }
                break;
            }

            case IPMI_CMD_GET_SENSOR_READING: {
                if (req_data_len < 1) {
                    resp_data[0] = IPMI_CC_REQ_DATA_LEN_INVALID; data_len = 1; break;
                }
                ipmi_sensor_t *s = get_sensor(req_data[0]);
                if (s) {
                    uint8_t status_flags = 0x00;

                    // Calcola le soglie solo se la lettura è valida (Bit 6 = 0) e lo scanning è attivo (Bit 7 = 0)
                    if ((s->event_enable & (1 << 6)) == 0 && (s->event_enable & (1 << 7)) == 0) {
                        status_flags = s->prev_status;
                    }

                    resp_data[0] = IPMI_CC_OK;
                    resp_data[1] = s->raw_reading; 
                    resp_data[2] = s->event_enable; //0x40; 
                    resp_data[3] = status_flags; 
                    resp_data[4] = 0x00;
                    data_len = 5;
                } else {
                    resp_data[0] = IPMI_CC_REQ_DATA_NOT_PRESENT; data_len = 1;
                }
                break;
            }
            default: resp_data[0] = IPMI_CC_INVALID_CMD; data_len = 1;
        }
    }
    // --- NetFn APP (0x06) ---
    else if (netfn == IPMI_NETFN_APP) {
        switch (cmd) {
            case IPMI_CMD_GET_DEVICE_ID:
                resp_data[0] = IPMI_CC_OK;
                resp_data[1] = 0x20; resp_data[2] = 0x00; resp_data[3] = 0x01; 
                resp_data[4] = 0x00; resp_data[5] = 0x51; resp_data[6] = 0x89;
                resp_data[7] = 0x65; resp_data[8] = 0xD9; resp_data[9] = 0x00;
                resp_data[10] = 0x01; resp_data[11] = 0x00;
                memset(&resp_data[12], 0, 4); 
                data_len = 16;
                break;

            case IPMI_CMD_GET_CHANNEL_AUTH_CAP:
                if (req_data_len < 1) {
                    resp_data[0] = IPMI_CC_REQ_DATA_LEN_INVALID; data_len = 1; break;
                }
                resp_data[0] = IPMI_CC_OK;
                resp_data[1] = req_data[0] & 0x0F;
                resp_data[2] = 0x11;
                resp_data[3] = 0x18;
                memset(&resp_data[4], 0, 5);
                data_len = 9;
                break;

            case IPMI_CMD_GET_SESSION_CHALLENGE:
                if (req_data_len < 1) {
                    resp_data[0] = IPMI_CC_REQ_DATA_LEN_INVALID; data_len = 1; break;
                }
                g_session_auth_type = req_data[0];
                resp_data[0] = IPMI_CC_OK;
                resp_data[1] = 0x78; resp_data[2] = 0x56;
                resp_data[3] = 0x34; resp_data[4] = 0x12;
                memset(&resp_data[5], 0, 16);
                data_len = 21;
                break;

            case IPMI_CMD_ACTIVATE_SESSION: {
                static uint32_t session_counter = 0x10000000;
                
                uint8_t req_auth_type  = (req_data_len >= 1) ? req_data[0] : 0x00;
                uint8_t req_priv_level = (req_data_len >= 2) ? (req_data[1] & 0x0F) : 0x04;
               
                if (req_auth_type != g_session_auth_type) {
                    IPMI_LOG("[SEC ERROR] Activate Session: Auth Type mismatch!\n");
                    resp_data[0] = IPMI_CC_INVALID_AUTH_TYPE;
                    data_len = 1;
                    break;
                }
                
                if (auth_type == 0x04) {
                    if (req_auth_type != 0x04) {
                        resp_data[0] = IPMI_CC_INVALID_AUTH_TYPE; data_len = 1; break;
                    }                    
                    char pass_buf[17] = {0};
                    if (auth_code_len == 16) {
                        memcpy(pass_buf, &in[13], 16);
                        pass_buf[16] = '\0';
                        for (int i = 0; i < 16; i++) {
                            if (pass_buf[i] == ' ' || pass_buf[i] == '\r' || pass_buf[i] == '\n' || pass_buf[i] == '\0') {
                                pass_buf[i] = '\0'; break;
                            }
                        }
                    }
                    if (auth_code_len != 16 || strcmp(pass_buf, BMC_PASSWORD) != 0) {
                        IPMI_LOG("[SECURITY ERROR] Activate Session: Password errata!\n");
                        resp_data[0] = IPMI_CC_INVALID_AUTH_CODE; data_len = 1; break;
                    }
                    g_max_session_priv_level = 0x04;
                } else if (auth_type == 0x00) {
                    req_auth_type = 0x00;
                    if (req_priv_level > 0x02) req_priv_level = 0x02;
                    g_max_session_priv_level = 0x02;
                } else {
                    resp_data[0] = IPMI_CC_INVALID_AUTH_TYPE; data_len = 1; break;
                }

                g_active_session_id = session_counter++; 
                g_current_session_priv_level = (req_priv_level > 0) ? req_priv_level : 0x04;
                if (g_current_session_priv_level > g_max_session_priv_level) {
                    g_current_session_priv_level = g_max_session_priv_level;
                }

                resp_data[0] = IPMI_CC_OK;
                resp_data[1] = req_auth_type;
                resp_data[2] = (uint8_t)(g_active_session_id & 0xFF);
                resp_data[3] = (uint8_t)((g_active_session_id >> 8) & 0xFF);
                resp_data[4] = (uint8_t)((g_active_session_id >> 16) & 0xFF);
                resp_data[5] = (uint8_t)((g_active_session_id >> 24) & 0xFF);
                resp_data[6] = 0x01;
                memset(&resp_data[7], 0, 3);
                resp_data[10] = g_max_session_priv_level;
                data_len = 11;
                break;
            }

            case IPMI_CMD_SET_SESSION_PRIV_LEVEL: {
                if (req_data_len < 1) {
                    resp_data[0] = IPMI_CC_REQ_DATA_LEN_INVALID; data_len = 1; break;
                }
                uint8_t req_priv = req_data[0] & 0x0F;
                if (req_priv == 0x00) {
                    resp_data[0] = IPMI_CC_OK;
                    resp_data[1] = g_current_session_priv_level;
                    data_len = 2; break;
                }
                if (req_priv > 0x04) {
                    resp_data[0] = IPMI_CC_INVALID_PRIV_LEVEL; data_len = 1; break;
                }            
                if (req_priv > g_max_session_priv_level) {
                    resp_data[0] = IPMI_CC_INSUFFICIENT_PRIVILEGE; data_len = 1; break;
                }
                g_current_session_priv_level = req_priv;
                resp_data[0] = IPMI_CC_OK;
                resp_data[1] = g_current_session_priv_level;
                data_len = 2;
                break;               
            }

            case IPMI_CMD_CLOSE_SESSION: {
                if (req_data_len < 4) {
                    resp_data[0] = IPMI_CC_REQ_DATA_LEN_INVALID; data_len = 1; break;
                }
                uint32_t close_sid = req_data[0] | (req_data[1] << 8) | (req_data[2] << 16) | (req_data[3] << 24);
                if (close_sid == 0x00000000 || close_sid == g_active_session_id) {
                    g_session_auth_type = 0x00;                
                    g_active_session_id = 0;
                    g_current_session_priv_level = 0;
                    g_max_session_priv_level = 0;
                    resp_data[0] = IPMI_CC_OK; 
                } else {
                    resp_data[0] = IPMI_CC_INVALID_SESSION_ID;                 
                }
                data_len = 1;
                break;
            }

            default: resp_data[0] = IPMI_CC_INVALID_CMD; data_len = 1;
        }
    }
    // --- NetFn STORAGE (0x0A) ---
    else if (netfn == IPMI_NETFN_STORAGE) {
        switch (cmd) {
            case IPMI_CMD_GET_FRU_INFO:
                resp_data[0] = IPMI_CC_OK;
                resp_data[1] = (uint8_t)(sizeof(g_fru_data) & 0xFF);
                resp_data[2] = (uint8_t)((sizeof(g_fru_data) >> 8) & 0xFF);
                resp_data[3] = 0x00;
                data_len = 4;
                break;

            case IPMI_CMD_READ_FRU_DATA: {
                if (req_data_len < 4) {
                    resp_data[0] = IPMI_CC_REQ_DATA_LEN_INVALID; data_len = 1; break;
                }
                uint16_t offset = req_data[1] | (req_data[2] << 8);
                uint8_t  count  = req_data[3];
                if (offset >= sizeof(g_fru_data)) {
                    resp_data[0] = IPMI_CC_PARAM_OUT_OF_RANGE; data_len = 1;
                } else {
                    if ((offset + count) > sizeof(g_fru_data)) count = sizeof(g_fru_data) - offset;
                    resp_data[0] = IPMI_CC_OK; resp_data[1] = count;
                    memcpy(&resp_data[2], &g_fru_data[offset], count);
                    data_len = 2 + count;
                }
                break;
            }

            case IPMI_CMD_GET_SDR_INFO:
                resp_data[0] = IPMI_CC_OK;
                resp_data[1] = 0x51; resp_data[2] = 0x02; resp_data[3] = 0x00;
                resp_data[4] = 0xFF; resp_data[5] = 0xFF;
                memset(&resp_data[6], 0, 8);
                resp_data[14] = 0x01;
                data_len = 15;
                break;

            case IPMI_CMD_RESERVE_SDR_REPO:
                resp_data[0] = IPMI_CC_OK; resp_data[1] = 0x01; resp_data[2] = 0x00;
                data_len = 3;
                break;

            case IPMI_CMD_GET_SDR: {
                if (req_data_len < 6) {
                    resp_data[0] = IPMI_CC_REQ_DATA_LEN_INVALID; data_len = 1; break;
                }
                uint16_t rec_id  = req_data[2] | (req_data[3] << 8);
                uint8_t  offset  = req_data[4];
                uint8_t  count   = req_data[5];
                const uint8_t *sdr_ptr = NULL;
                uint16_t sdr_size = 0;
                uint16_t next_id = 0xFFFF;
                
                // Cerca il sensore con il Record ID richiesto
                for (size_t i = 0; i < NUM_SENSORS; i++) {
                    if (g_sensors[i].sdr_data == NULL || g_sensors[i].sdr_size < 2) continue;
                    
                    // I primi 2 byte dell'SDR contengono il Record ID (little-endian)
                    uint16_t current_rec_id = g_sensors[i].sdr_data[0] | (g_sensors[i].sdr_data[1] << 8);
                    
                    // 0x0000 = "Get first record" secondo specifiche IPMI
                    if (rec_id == 0x0000 || current_rec_id == rec_id) {
                        sdr_ptr  = g_sensors[i].sdr_data;
                        sdr_size = g_sensors[i].sdr_size;
                        
                        // Il next_id è il Record ID del sensore successivo nell'array
                        if (i + 1 < NUM_SENSORS && g_sensors[i+1].sdr_data != NULL && g_sensors[i+1].sdr_size >= 2) {
                            next_id = g_sensors[i+1].sdr_data[0] | (g_sensors[i+1].sdr_data[1] << 8);
                        }
                        break;
                    }
                }
                
                if (sdr_ptr != NULL) {
                    if (offset >= sdr_size) {
                        resp_data[0] = IPMI_CC_PARAM_OUT_OF_RANGE; data_len = 1;
                    } else {
                        if ((offset + count) > sdr_size) count = sdr_size - offset;
                        resp_data[0] = IPMI_CC_OK;
                        resp_data[1] = (uint8_t)(next_id & 0xFF);
                        resp_data[2] = (uint8_t)((next_id >> 8) & 0xFF);
                        memcpy(&resp_data[3], &sdr_ptr[offset], count);
                        data_len = 3 + count;
                    }
                } else {
                    resp_data[0] = IPMI_CC_REQ_DATA_NOT_PRESENT; data_len = 1;
                }
                break;
            }

            // --- COMANDI SEL (SYSTEM EVENT LOG) ---

            case IPMI_CMD_GET_SEL_INFO: {
                uint16_t free_bytes = (MAX_SEL_ENTRIES > g_sel_count) ? 
                                      (uint16_t)((MAX_SEL_ENTRIES - g_sel_count) * sizeof(sel_entry_t)) : 0;
                resp_data[0] = IPMI_CC_OK;
                resp_data[1] = 0x51; // SEL Version v1.5 / v2.0
                resp_data[2] = (uint8_t)(g_sel_count & 0xFF);
                resp_data[3] = (uint8_t)((g_sel_count >> 8) & 0xFF);
                resp_data[4] = (uint8_t)(free_bytes & 0xFF);
                resp_data[5] = (uint8_t)((free_bytes >> 8) & 0xFF);
                memset(&resp_data[6], 0, 8);
                
                // Bit 1 (0x02) = Reserve SEL supported | Bit 3 (0x08) = Delete SEL Entry supported
                resp_data[14] = (g_sel_count >= MAX_SEL_ENTRIES ? 0x80 : 0x00) | 0x02 | 0x08;
                data_len = 15;
                break;
            }

            case IPMI_CMD_RESERVE_SEL: {
                g_sel_reservation_id++;
                if (g_sel_reservation_id == 0) g_sel_reservation_id = 1;
                resp_data[0] = IPMI_CC_OK;
                resp_data[1] = (uint8_t)(g_sel_reservation_id & 0xFF);
                resp_data[2] = (uint8_t)((g_sel_reservation_id >> 8) & 0xFF);
                data_len = 3;
                break;
            }

            case IPMI_CMD_GET_SEL_ENTRY: {
                if (req_data_len < 6) {
                    resp_data[0] = IPMI_CC_REQ_DATA_LEN_INVALID; data_len = 1; break;
                }
                uint16_t req_rec_id = req_data[2] | (req_data[3] << 8);
                uint8_t  offset     = req_data[4];
                uint8_t  read_bytes = req_data[5];

                if (g_sel_count == 0) {
                    resp_data[0] = IPMI_CC_REQ_DATA_NOT_PRESENT; data_len = 1; break;
                }

                int found_idx = -1;
                if (req_rec_id == 0x0000) {
                    found_idx = 0;
                } else if (req_rec_id == 0xFFFF) {
                    found_idx = g_sel_count - 1;
                } else {
                    for (uint16_t i = 0; i < g_sel_count; i++) {
                        if (g_sel_log[i].record_id == req_rec_id) {
                            found_idx = (int)i; break;
                        }
                    }
                }

                if (found_idx < 0) {
                    resp_data[0] = IPMI_CC_REQ_DATA_NOT_PRESENT; data_len = 1; break;
                }

                uint16_t next_rec_id = 0xFFFF;
                if ((uint16_t)found_idx + 1 < g_sel_count) {
                    next_rec_id = g_sel_log[found_idx + 1].record_id;
                }

                const uint8_t *entry_bytes = (const uint8_t *)&g_sel_log[found_idx];
                uint8_t total_size = sizeof(sel_entry_t);

                if (offset >= total_size) {
                    resp_data[0] = IPMI_CC_PARAM_OUT_OF_RANGE; data_len = 1; break;
                }

                uint8_t chunk = read_bytes;
                if (chunk == 0xFF || (offset + chunk) > total_size) {
                    chunk = total_size - offset;
                }

                resp_data[0] = IPMI_CC_OK;
                resp_data[1] = (uint8_t)(next_rec_id & 0xFF);
                resp_data[2] = (uint8_t)((next_rec_id >> 8) & 0xFF);
                memcpy(&resp_data[3], &entry_bytes[offset], chunk);
                data_len = 3 + chunk;
                break;
            }

            case IPMI_CMD_ADD_SEL_ENTRY: {
                if (req_data_len < 16) {
                    resp_data[0] = IPMI_CC_REQ_DATA_LEN_INVALID; data_len = 1; break;
                }
                if (g_sel_count >= MAX_SEL_ENTRIES) {
                    resp_data[0] = IPMI_CC_OUT_OF_SPACE; data_len = 1; break;
                }

                sel_entry_t *entry = &g_sel_log[g_sel_count];
                memcpy(entry, req_data, sizeof(sel_entry_t));
                
                entry->record_id = g_sel_next_id++;
                g_sel_count++;

                resp_data[0] = IPMI_CC_OK;
                resp_data[1] = (uint8_t)(entry->record_id & 0xFF);
                resp_data[2] = (uint8_t)((entry->record_id >> 8) & 0xFF);
                data_len = 3;
                break;
            }

            case IPMI_CMD_DELETE_SEL_ENTRY: {
                if (req_data_len < 4) {
                    resp_data[0] = IPMI_CC_REQ_DATA_LEN_INVALID; data_len = 1; break;
                }
                uint16_t res_id     = req_data[0] | (req_data[1] << 8);
                uint16_t del_rec_id = req_data[2] | (req_data[3] << 8);

                // Controllo esteso della validità del Reservation ID
                if (res_id != 0 && res_id != g_sel_reservation_id) {
                    resp_data[0] = IPMI_CC_INVALID_RESERVATION; // 0xC5
                    data_len = 1;
                    break;
                }

                int target_idx = -1;
                for (uint16_t i = 0; i < g_sel_count; i++) {
                    if (g_sel_log[i].record_id == del_rec_id) {
                        target_idx = (int)i; break;
                    }
                }

                if (target_idx >= 0) {
                    for (uint16_t i = (uint16_t)target_idx; i < g_sel_count - 1; i++) {
                        g_sel_log[i] = g_sel_log[i + 1];
                    }
                    g_sel_count--;
                    resp_data[0] = IPMI_CC_OK;
                    resp_data[1] = (uint8_t)(del_rec_id & 0xFF);
                    resp_data[2] = (uint8_t)((del_rec_id >> 8) & 0xFF);
                    data_len = 3;
                } else {
                    resp_data[0] = IPMI_CC_REQ_DATA_NOT_PRESENT; data_len = 1;
                }
                break;
            }

            case IPMI_CMD_CLEAR_SEL: {
                if (req_data_len < 6) {
                    resp_data[0] = IPMI_CC_REQ_DATA_LEN_INVALID; data_len = 1; break;
                }

                uint16_t res_id = req_data[0] | (req_data[1] << 8);

                // Controllo della firma obbligatoria 'C', 'L', 'R' (0x43, 0x4C, 0x52)
                if (req_data[2] != 'C' || req_data[3] != 'L' || req_data[4] != 'R') {
                    resp_data[0] = IPMI_CC_PARAM_OUT_OF_RANGE; data_len = 1; break;
                }

                // Controllo esteso della validità del Reservation ID
                if (res_id != 0 && res_id != g_sel_reservation_id) {
                    resp_data[0] = IPMI_CC_INVALID_RESERVATION; // 0xC5
                    data_len = 1;
                    break;
                }

                uint8_t operation = req_data[5];
                if (operation == 0xAA) {
                    // 0xAA = Initiate Erase (Valore standard IPMI inviato da ipmitool)
                    g_sel_count = 0;
                    g_sel_next_id = 0x0001;
                    g_sel_reservation_id = 0x0000;
                    resp_data[0] = IPMI_CC_OK;
                    resp_data[1] = 0x01; // 0x01 = Cancellazione completata
                    data_len = 2;
                } else if (operation == 0x00) {
                    // 0x00 = Get Erase Status
                    resp_data[0] = IPMI_CC_OK;
                    resp_data[1] = 0x01;
                    data_len = 2;
                } else {
                    resp_data[0] = IPMI_CC_PARAM_OUT_OF_RANGE; data_len = 1;
                }
                break;
            }

            default: resp_data[0] = IPMI_CC_INVALID_CMD; data_len = 1;
        }
    }
    // --- NetFn OEM CUSTOM (0x30) ---
    else if (netfn == IPMI_NETFN_OEM) {
        switch (cmd) {
            case IPMI_CMD_OEM_SET_GPIO: {
                if (req_data_len < 2) {
                    resp_data[0] = IPMI_CC_REQ_DATA_LEN_INVALID; data_len = 1; break;
                }
                if (g_current_session_priv_level < 0x04) {
                    resp_data[0] = IPMI_CC_INSUFFICIENT_PRIVILEGE; data_len = 1; break;
                }
                uint8_t pin = req_data[0];
                uint8_t val = req_data[1];
                if (pin < 32) {
                    g_gpio_pins[pin] = (val != 0) ? 1 : 0;
                    IPMI_LOG("\n>>> [OEM GPIO] Pin %d -> %d <<<\n\n", pin, g_gpio_pins[pin]);
                    resp_data[0] = IPMI_CC_OK;
                } else {
                    resp_data[0] = IPMI_CC_PARAM_OUT_OF_RANGE;
                }
                data_len = 1;
                break;
            }

            case IPMI_CMD_OEM_GET_GPIO: {
                if (req_data_len < 1) {
                    resp_data[0] = IPMI_CC_REQ_DATA_LEN_INVALID; data_len = 1; break;
                }
                uint8_t pin = req_data[0];
                if (pin < 32) {
                    resp_data[0] = IPMI_CC_OK;
                    resp_data[1] = g_gpio_pins[pin];
                    data_len = 2;
                } else {
                    resp_data[0] = IPMI_CC_PARAM_OUT_OF_RANGE;
                    data_len = 1;
                }
                break;
            }

            default: resp_data[0] = IPMI_CC_INVALID_CMD; data_len = 1;
        }
    } else {
        resp_data[0] = IPMI_CC_INVALID_CMD;
        data_len = 1;
    }

    uint16_t chk2_len = 3 + data_len;
    out[base + 6 + data_len] = ipmi_checksum(&out[base + 3], chk2_len);

    uint8_t total_ipmi_msg_len = 7 + data_len;
    out[13 + auth_code_len] = total_ipmi_msg_len;

    return 14 + auth_code_len + total_ipmi_msg_len;
}