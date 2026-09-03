// main_pc.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "ipmi_defs.h"

#define BMC_PORT 6230

static volatile sig_atomic_t keep_running = 1;
static int sockfd = -1;

void handle_sigint(int sig) {
    (void)sig;
    keep_running = 0;
    if (sockfd >= 0) {
        close(sockfd);
        sockfd = -1;
    }
}

int main(int argc, char *argv[]) {
    uint8_t *rx_buf = NULL;
    uint8_t *tx_buf = NULL;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    // Controllo flag -v
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) {
            ipmi_debug = 1;
            break;
        }
    }

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    rx_buf = (uint8_t *)malloc(1024);
    tx_buf = (uint8_t *)malloc(1024);
    if (!rx_buf || !tx_buf) {
        fprintf(stderr, "Errore allocazione memoria!\n");
        goto cleanup;
    }

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Errore creazione socket");
        goto cleanup;
    }

    // Timeout di 1 secondo sulla socket UDP per permettere i tick del monitor sensori
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(BMC_PORT);

    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Errore bind socket");
        goto cleanup;
    }

    // Inizializzazione automatica delle soglie sensori estraendole dai record SDR statici
    ipmi_sensors_init();

    printf("==================================================\n");
    printf("  BMC Simulator v%s attivo su 127.0.0.1:%d\n", IPMI_SIM_VERSION, BMC_PORT);
    if (ipmi_debug) {
        printf("  DEBUG MODE ENABLED (stampe dettagliate)\n");
    } else {
        printf("  Usa -v per abilitare il debug\n");
    }
    printf("  Premi Ctrl+C per fermare il server in modo pulito.\n");
    printf("==================================================\n\n");

    while (keep_running) {
        ipmi_sensor_monitoring_tick();
        addr_len = sizeof(client_addr);

        ssize_t rx_len = recvfrom(sockfd, rx_buf, 1024, 0,
                                  (struct sockaddr *)&client_addr, &addr_len);

        if (rx_len > 0) {
            printf("[RX] Ricevuto pacchetto di %zd byte\n", rx_len);
            if (ipmi_debug) {
                printf("  RAW: ");
                for (int i = 0; i < rx_len; i++) {
                    printf("%02X ", rx_buf[i]);
                }
                printf("\n");
            }

            uint16_t tx_len = ipmi_process_packet(rx_buf, (uint16_t)rx_len, tx_buf);

            if (tx_len > 0) {
                sendto(sockfd, tx_buf, tx_len, 0,
                       (struct sockaddr *)&client_addr, addr_len);
                printf("[TX] Inviati %d byte di risposta\n", tx_len);
                if (ipmi_debug) {
                    printf("  RAW: ");
                    for (int i = 0; i < tx_len; i++) {
                        printf("%02X ", tx_buf[i]);
                    }
                    printf("\n");
                }
                printf("\n");
            } else {
                printf("[TX] Nessuna risposta generata\n\n");
            }
        }
    }

cleanup:
    printf("\n[SHUTDOWN] Arresto del server in corso...\n");
    if (sockfd >= 0) {
        close(sockfd);
        printf("[SHUTDOWN] Socket UDP chiusa.\n");
    }
    if (rx_buf) {
        free(rx_buf);
        printf("[SHUTDOWN] Buffer RX deallocato.\n");
    }
    if (tx_buf) {
        free(tx_buf);
        printf("[SHUTDOWN] Buffer TX deallocato.\n");
    }
    printf("[SHUTDOWN] Terminato con successo.\n");
    return 0;
}