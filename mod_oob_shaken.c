#include "mod_oob_shaken.h"


#define SERVER_PORT 9877

struct oob_globals_s {
	switch_threadattr_t	*thread_attr;
	switch_mutex_t		*mutex;
	switch_thread_t		*thread;
	switch_memory_pool_t *pool;
} oob;

SWITCH_MODULE_LOAD_FUNCTION(mod_oob_shaken_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_oob_shaken_shutdown);
SWITCH_MODULE_DEFINITION(mod_oob_shaken, mod_oob_shaken_load, mod_oob_shaken_shutdown, NULL);


#define MAXLINE 6000

static void oob_shaken_print_cert_fields(stir_shaken_cert_t *cert)
{
	if (!cert) return;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "STI Cert: Serial number: %s %s\n", stir_shaken_cert_get_serialHex(cert), stir_shaken_cert_get_serialDec(cert));
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "STI Cert: Issuer: %s\n", stir_shaken_cert_get_issuer(cert));
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "STI Cert: Subject: %s\n", stir_shaken_cert_get_subject(cert));
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "STI Cert: Valid from: %s\n", stir_shaken_cert_get_notBefore(cert));
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "STI Cert: Valid to: %s\n", stir_shaken_cert_get_notAfter(cert));
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "STI Cert: Version: %d\n", stir_shaken_cert_get_version(cert));
}

static void oob_do_shaken(char *passport_encoded)
{
	stir_shaken_context_t ss = { 0 };
	const char *error_description = NULL;
	char *passport_decoded = NULL;
	stir_shaken_error_t error_code = 0;
	jwt_t *jwt = NULL;
	stir_shaken_cert_t *cert = NULL;
	

	if (jwt_new(&jwt) != 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Cannot init PASSporT decoding\n");
		return;
	}

	if (0 != jwt_decode(&jwt, passport_encoded, NULL, 0)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Cannot read PASSporT\n");
		return;
	}

	passport_decoded = jwt_dump_str(jwt, 1);
	if (!passport_decoded) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Cannot dump PASSporT\n");
		return;
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Remote PASSporT is\n%s\n\n", passport_decoded);
	jwt_free_str(passport_decoded);
	passport_decoded = NULL;

	if (STIR_SHAKEN_STATUS_OK != stir_shaken_jwt_verify_and_check_x509_cert_path(&ss, passport_encoded, &cert)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "--- Fake Caller\n");
    
		if (stir_shaken_is_error_set(&ss)) {
			error_description = stir_shaken_get_error(&ss, &error_code);
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error description is: '%s'\n", error_description);
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error code is: '%d'\n", error_code);
		}
	} else {

		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "\n\nRemote STI certificate is:\n");
		oob_shaken_print_cert_fields(cert);

		stir_shaken_destroy_cert(cert);
		free(cert);

		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "\n\n+++ Caller verified\n\n");
	}
}

static void oob_process_connection(int sockfd, const char *ip_str, uint16_t port)
{
	int			n;
	char		line[MAXLINE] = { 0 };

	for ( ; ; ) {
		if ((n = read(sockfd, line, MAXLINE)) == -1) {
			// error
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error %d reading Shaken Oob socket from %s:%u\n", n, ip_str, port);
		} else if (n == 0) {
			// connection closed by client
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Client closed Shaken Oob connection from %s:%u\n", ip_str, port);
			return;
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Got %d bytes from %s:%u. Message is:\n%s\n", n, ip_str, port, line);
			oob_do_shaken(line);
		}
	}
}

static int oob_do_run_tcp(void)
{
	int                 listenfd = -1, connfd = -1;
	socklen_t           clilen = 0;
	struct sockaddr_in  cliaddr = { 0 }, servaddr = { 0 };
    uint16_t            port = 0;

	char ip_str[INET_ADDRSTRLEN] = { 0 };
	struct in_addr		*ip_addr = NULL;

    port = SERVER_PORT;

	if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to init listening socket...\n");
		return -1;
	}

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family      = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port        = htons(port);

	if (bind(listenfd, (struct sockaddr *) &servaddr, sizeof( servaddr)) < 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Cannot bind listening socket...\n");
		return -1;
	}

	if (listen(listenfd, 100) != 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Cannot start listening socket...\n");
		return -1;
	}

	for ( ; ; ) {

		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Oob listening on port %u...\n", SERVER_PORT);

		clilen = sizeof(cliaddr);
		if ((connfd = accept( listenfd, (struct sockaddr *) &cliaddr, &clilen)) < 0) {
			if (errno == EINTR) {
				continue;		/* back to for() */
			} else {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Cannot accept connections on listening socket...\n");
				return -1;
			}
		}

		ip_addr = &cliaddr.sin_addr;
		port = ntohs(cliaddr.sin_port);
		inet_ntop(AF_INET, ip_addr, ip_str, INET_ADDRSTRLEN);

		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "New Shaken Oob connection from %s:%u\n", ip_str, port);
		oob_process_connection(connfd, ip_str, port);
	}

	close(connfd);
	return 0;
}

void *SWITCH_THREAD_FUNC oob_run_tcp(switch_thread_t *thread, void *obj)
{
	if (oob_do_run_tcp() != 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "TCP server exited with error...\n");
		return NULL;
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "TCP server exit OK...\n");
	return NULL;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_oob_shaken_load)
{
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);
	oob.pool = pool;

	switch_mutex_init(&oob.mutex, SWITCH_MUTEX_NESTED, oob.pool);
	switch_mutex_lock(oob.mutex);
	switch_threadattr_create(&oob.thread_attr, oob.pool);
	switch_thread_create(&oob.thread, oob.thread_attr, oob_run_tcp, &oob, oob.pool);
	switch_mutex_unlock(oob.mutex);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Oob Shaken ready...\n");

	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_oob_shaken_shutdown)
{
	return SWITCH_STATUS_SUCCESS;
}


/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4 noet:
 */
