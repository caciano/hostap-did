/*
 * EAP-DID Test: Socket Disconnect (#12)
 *
 * Tests that the transport layer correctly detects a remote socket
 * disconnect during an active EAP-DID session.  The proxy drops the
 * connection mid-handshake; the C code should detect EOF and handle
 * it gracefully (no hang, no crash).
 *
 * Build: gcc -Wall -I../../src -I../../src/utils \
 *          test-socket-disconnect.c \
 *          ../../src/eap_common/eap_did_common.o \
 *          ../../src/utils/os_unix.o \
 *          ../../src/utils/wpa_debug.o \
 *          ../../src/utils/common.o \
 *          ../../src/wpabuf.o \
 *          -lcrypto -lpthread -o test-socket-disconnect
 */

#include "includes.h"
#include "common.h"
#include "eap_common/eap_did_common.h"
#include "eap_common/eap_did_transport.h"

#include <pthread.h>
#include <sys/stat.h>

#define TEST_SOCKET "/tmp/eap-did-test-disconnect.sock"

static int test_result = 1;

static void *fake_proxy_disconnect(void *arg)
{
	int srv_fd, cli_fd;
	struct sockaddr_un addr;

	(void)arg;

	srv_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (srv_fd < 0) {
		perror("socket");
		return NULL;
	}

	unlink(TEST_SOCKET);
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, TEST_SOCKET, sizeof(addr.sun_path) - 1);

	if (bind(srv_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(srv_fd);
		return NULL;
	}

	chmod(TEST_SOCKET, 0666);
	listen(srv_fd, 1);

	printf("  [proxy] Waiting for connection...\n");
	cli_fd = accept(srv_fd, NULL, NULL);
	if (cli_fd < 0) {
		perror("accept");
		close(srv_fd);
		return NULL;
	}

	/* Read the initial message */
	uint32_t mtype, mlen;
	uint8_t *payload = NULL;
	if (did_transport_recv(cli_fd, &mtype, &payload, &mlen, 5000) == 0) {
		printf("  [proxy] Got msg type=%u len=%u\n", mtype, mlen);
		free(payload);
	}

	/* Disconnect abruptly */
	printf("  [proxy] Disconnecting abruptly...\n");
	close(cli_fd);
	close(srv_fd);
	unlink(TEST_SOCKET);
	return NULL;
}

int main(void)
{
	pthread_t proxy_thread;
	int fd;
	int rc;
	uint32_t mtype, mlen;
	uint8_t *payload = NULL;

	printf("\n");
	printf("═══════════════════════════════════════════════\n");
	printf("  Test: Socket Disconnect (#12)\n");
	printf("═══════════════════════════════════════════════\n\n");

	/* Start fake proxy */
	if (pthread_create(&proxy_thread, NULL, fake_proxy_disconnect, NULL) != 0) {
		perror("pthread_create");
		return 1;
	}

	usleep(200000);

	/* Connect */
	printf("  [client] Connecting...\n");
	fd = did_transport_connect(TEST_SOCKET);
	if (fd < 0) {
		perror("connect");
		pthread_join(proxy_thread, NULL);
		return 1;
	}

	/* Send a message */
	const char *msg = "test-payload";
	did_transport_send(fd, DID_MSG_OOB_REQUEST,
			   (const uint8_t *)msg, strlen(msg));
	printf("  [client] Sent OOB_REQUEST (%zu bytes)\n", strlen(msg));

	/* Wait for proxy to disconnect */
	usleep(500000);

	/* Try to recv — should get -3 (EOF) or -1 (error) */
	printf("  [client] Attempting recv after disconnect...\n");
	rc = did_transport_recv(fd, &mtype, &payload, &mlen, 3000);

	if (rc == -3) {
		printf("  [client] Got EOF (rc=%d) — correctly detected disconnect\n", rc);
		test_result = 0;
	} else if (rc == -1) {
		printf("  [client] Got error (rc=%d) — detected disconnect via errno\n", rc);
		test_result = 0;
	} else {
		printf("  [client] Unexpected rc=%d (expected -3 or -1)\n", rc);
		free(payload);
	}

	close(fd);
	pthread_join(proxy_thread, NULL);

	printf("\n═══════════════════════════════════════════════\n");
	printf("  %s\n", test_result == 0 ? "✓ PASSED" : "✗ FAILED");
	printf("═══════════════════════════════════════════════\n\n");

	return test_result;
}
