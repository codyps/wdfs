/* 
 *  this file is part of wdfs --> http://noedler.de/projekte/wdfs/
 *
 *  wdfs is a webdav filesystem with special features for accessing subversion
 *  repositories. it is based on fuse v2.5+ and neon v0.24.7+.
 * 
 *  copyright (c) 2005 - 2007 jens m. noedler, noedler@web.de
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 *  This program is released under the GPL with the additional exemption
 *  that compiling, linking and/or using OpenSSL is allowed.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <termios.h>
#include <ne_basic.h>
#include <ne_auth.h>
#include <ne_locks.h>
#include <ne_socket.h>
#include <ne_redirect.h>

#include "wdfs-main.h"
#include "webdav.h"


/* used to authorize at the webdav server */
struct ne_auth_data {
	const char *username;
	const char *password;
};

ne_session *session;
ne_lock_store *store = NULL;
struct ne_auth_data auth_data;


/* reads from the terminal without displaying the typed chars. used to type
 * the password savely. */
static int fgets_hidden(char *lineptr, size_t n, FILE *stream)
{
	struct termios settings_old, settings_new;
	int ret = 0;

	if (isatty(fileno(stream)))	{
		/* turn echoing off and fail if we can't */
		if (tcgetattr(fileno(stream), &settings_old) == 0) {
			settings_new = settings_old;
			settings_new.c_lflag &= ~ECHO;
			if (tcsetattr(fileno(stream), TCSAFLUSH, &settings_new) == 0)
				ret = 1;
		}
	}
	else
		ret = 1;

	/* read the password */
	if (ret == 1 &&	fgets(lineptr, n, stream) == NULL)
		ret = 0;

	if (isatty(fileno(stream)))
		/* restore terminal */
		(void) tcsetattr(fileno(stream), TCSAFLUSH, &settings_old);

	return ret;
}


/* this method is envoked, if the server requires authentication */
static int ne_set_server_auth_callback(
	void *userdata, const char *realm, 
	int attempt, char *username, char *password)
{
	const size_t length = 100;
	char buffer[length];

	/* ask the user for the username and password if needed */
	if (auth_data.username == NULL) {
		printf("username: ");
		if (fgets(buffer, length, stdin)) {
			int len = strlen(buffer);
			if (buffer[len - 1] == '\n')
				buffer[len - 1] = '\0';
			auth_data.username = strdup(buffer);
		}
	}
	if (auth_data.password == NULL) {
		printf("password: ");
		if (fgets_hidden(buffer, length, stdin)) {
			int len = strlen(buffer);
			if (buffer[len - 1] == '\n')
				buffer[len - 1] = '\0';
			auth_data.password = strdup(buffer);
		}
		printf("\n");
	}

	assert(auth_data.username && auth_data.password);
	strncpy(username, auth_data.username, NE_ABUFSIZ);
	strncpy(password, auth_data.password, NE_ABUFSIZ);

	return attempt;
}


/* this is called from ne_ssl_set_verify() if there is something wrong with the 
 * ssl certificate.  */
static int verify_ssl_certificate(
	void *userdata, int failures, const ne_ssl_certificate *certificate)
{
	ne_uri *uri = (ne_uri*)userdata;
	char from[NE_SSL_VDATELEN], to[NE_SSL_VDATELEN];
	const char *ident;

	ident = ne_ssl_cert_identity(certificate);

	if (ident) {
		fprintf(stderr,
			"WARNING: untrusted server certificate for '%s':\n", ident);
	}

	if (failures & NE_SSL_IDMISMATCH) {
		fprintf(stderr,
			" certificate was issued to hostname '%s' rather than '%s'\n", 
			ne_ssl_cert_identity(certificate), uri->host);
		fprintf(stderr, " this connection could have been intercepted!\n");
	}

	ne_ssl_cert_validity(certificate, from, to);
	printf(" certificate is valid from %s to %s\n", from, to);
	if (failures & NE_SSL_EXPIRED)
		fprintf(stderr, " >> certificate expired! <<\n");

	char *issued_to = ne_ssl_readable_dname(ne_ssl_cert_subject(certificate));
	char *issued_by = ne_ssl_readable_dname(ne_ssl_cert_issuer(certificate));
	printf(" issued to: %s\n", issued_to);
	printf(" issued by: %s\n", issued_by);
	free_chars(&issued_to, &issued_by, NULL);

	/* don't prompt the user if the parameter "-ac" was passed to wdfs */
	if (wdfs.accept_certificate == true)
		return 0;

	/* prompt the user wether he/she wants to accept this certificate */
	int answer;
	while (1) {
		printf(" do you wish to accept this certificate? (y/n) ");
		answer = getchar();
		/* delete the input buffer (if the char is not a newline) */
		if (answer != '\n')
			while (getchar() != '\n');
		/* stop asking if the answer was 'y' or 'n' */ 
		if (answer == 'y' || answer == 'n')
			break;
	}

	if (answer == 'y') {
		return 0;
	} else {
		printf(" certificate rejected.\n");
		return -1;
	}
}


/* sets up a webdav connection. if the servers needs authentication, the passed
 * parameters username and password are used. if they were not passed they can
 * be entered interactively. this method returns 0 on success or -1 on error. */
int setup_webdav_session(
	const char *uri_string, const char *username, const char *password)
{
	assert(uri_string);

	auth_data.username = username;
	auth_data.password = password;

	/* parse the uri_string and return a uri struct */
	ne_uri uri;
	if (ne_uri_parse(uri_string, &uri)) {
		fprintf(stderr,
			"## ne_uri_parse() error: invalid URI '%s'.\n", uri_string);
		ne_uri_free(&uri);
		return -1;
	}

	assert(uri.scheme && uri.host && uri.path);

	/* if no port was defined use the default port */
	uri.port = uri.port ? uri.port : ne_uri_defaultport(uri.scheme);

	/* needed for ssl connections. it's not documented. nice to know... ;-) */
	ne_sock_init();

	/* create a session object, that allows to access the server */
	session = ne_session_create(uri.scheme, uri.host, uri.port);

	/* init ssl if needed */
	if (!strcasecmp(uri.scheme, "https")) {
#if NEON_VERSION >= 25
		if (ne_has_support(NE_FEATURE_SSL)) {
#else
		if (ne_supports_ssl()) {
#endif
			ne_ssl_trust_default_ca(session);
			ne_ssl_set_verify(session, verify_ssl_certificate, &uri);
		} else {
			fprintf(stderr, "## error: neon ssl support is not enabled.\n");
			ne_session_destroy(session);
			ne_uri_free(&uri);
			return -1;
		}
	}

	/* enable this for on-demand authentication */
	ne_set_server_auth(session, ne_set_server_auth_callback, NULL);

	/* enable redirect support */
	ne_redirect_register(session);

	/* escape the path for the case that it contains special chars */
	char *path = unify_path(uri.path, ESCAPE | LEAVESLASH);
	if (path == NULL) {
		printf("## error: unify_path() returned NULL\n");
		ne_session_destroy(session);
		ne_uri_free(&uri);
		return -1;
	}

	/* try to access the server */
	ne_server_capabilities capabilities;
	int ret = ne_options(session, path, &capabilities);
	if (ret != NE_OK) {
		fprintf(stderr,
			"## error: could not mount remote server '%s'. ", uri_string);
		fprintf(stderr, "reason: %s", ne_get_error(session));
		/* if we got a redirect, print the new destination uri and exit */
		if (ret == NE_REDIRECT) {
			const ne_uri *new_uri = ne_redirect_location(session);
			char *new_uri_string = ne_uri_unparse(new_uri);
			fprintf(stderr, " to '%s'", new_uri_string);
			FREE(new_uri_string);
		}
		fprintf(stderr, ".\n");
		ne_session_destroy(session);
		ne_uri_free(&uri);
		FREE(path);
		return -1;
	}
	FREE(path);

	/* is this a webdav server that fulfills webdav class 1? */
	if (capabilities.dav_class1 != 1) {
		fprintf(stderr, 
			"## error: '%s' is not a webdav enabled server.\n", uri_string);
		ne_session_destroy(session);
		ne_uri_free(&uri);
		return -1;
	}

	/* set a useragent string, to identify wdfs in the server log files */
	ne_set_useragent(session, project_name);

	/* save the remotepath, because each fuse callback method need it to 
	 * access the files at the webdav server */
	remotepath_basedir = remove_ending_slashes(uri.path);
	if (remotepath_basedir == NULL) {
		ne_session_destroy(session);
		ne_uri_free(&uri);
		return -1;
	}

	ne_uri_free(&uri);
	return 0;
}


/* +++++++ locking methods +++++++ */

/* returns the lock for this file from the lockstore on success 
 * or NULL if the lock is not found in the lockstore. */
static struct ne_lock* get_lock_by_path(const char *remotepath)
{
	assert(remotepath);

	/* unless the lockstore is initialized, no lock can be found */
	if (store == NULL)
		return NULL;

	/* generate a ne_uri object to find the lock by its uri */
	ne_uri uri;
	uri.path = (char *)remotepath;
	ne_fill_server_uri(session, &uri);

	/* find the lock for this uri in the lockstore */
	struct ne_lock *lock = NULL;
	lock = ne_lockstore_findbyuri(store, &uri);

	/* ne_fill_server_uri() malloc()d these fields, time to free them */
	free_chars(&uri.scheme, &uri.host, NULL);

	return lock;
}


/* tries to lock the file and returns 0 on success and 1 on error */
int lockfile(const char *remotepath, const int timeout)
{
	assert(remotepath && timeout);

	/* initialize the lockstore, if needed (e.g. first locking a file). */
	if (store == NULL) {
		store = ne_lockstore_create();
		if (store == NULL)
			return 1;
		ne_lockstore_register(store, session);
	}


	/* check, if we already hold a lock for this file */
	struct ne_lock *lock = get_lock_by_path(remotepath);

	/* we already hold a lock for this file, simply return 0 */
	if (lock != NULL) {
		if (wdfs.debug == true)
			fprintf(stderr, "++ file '%s' is already locked.\n", remotepath);
		return 0;
	}

	/* otherwise lock the file exclusivly */
	lock = ne_lock_create();
	enum ne_lock_scope scope = ne_lockscope_exclusive;
	lock->scope	= scope;
	lock->owner = ne_concat("wdfs, user: ", getenv("USER"), NULL);
	lock->timeout = timeout;
	lock->depth = NE_DEPTH_ZERO;
	ne_fill_server_uri(session, &lock->uri);
	lock->uri.path = ne_strdup(remotepath);

	if (ne_lock(session, lock)) {
		fprintf(stderr, "## ne_lock() error:\n");
		fprintf(stderr, "## could _not_ lock file '%s'.\n", lock->uri.path);
		ne_lock_destroy(lock);
		return 1;
	} else {
		ne_lockstore_add(store, lock);
		if (wdfs.debug == true)
			fprintf(stderr, "++ locked file '%s'.\n", remotepath);
	}

	return 0;
}


/* tries to unlock the file and returns 0 on success and 1 on error */
int unlockfile(const char *remotepath)
{
	assert(remotepath);

	struct ne_lock *lock = get_lock_by_path(remotepath);

	/* if the lock was not found, the file is already unlocked */
	if (lock == NULL)
		return 0;


	/* if the lock was found, unlock the file */
	if (ne_unlock(session, lock)) {
		fprintf(stderr, "## ne_unlock() error:\n");
		fprintf(stderr, "## could _not_ unlock file '%s'.\n", lock->uri.path);
		ne_lock_destroy(lock);
		return 1;
	} else {
		/* on success remove the lock from the store and destroy the lock */
		ne_lockstore_remove(store, lock);
		ne_lock_destroy(lock);
		if (wdfs.debug == true)
			fprintf(stderr, "++ unlocked file '%s'.\n", remotepath);
	}

	return 0;
}


/* this method unlocks all files of the lockstore and destroys the lockstore */
void unlock_all_files()
{
	/* only unlock all files, if the lockstore is initialized */
	if (store != NULL) {
		/* get each lock from the lockstore and try to unlock the file */
		struct ne_lock *this_lock = NULL;
		this_lock = ne_lockstore_first(store);
		while (this_lock != NULL) {
			if (ne_unlock(session, this_lock)) {
				fprintf(stderr,
					"## ne_unlock() error:\n"
				 	"## could _not_ unlock file '%s'.\n", this_lock->uri.path);
			} else {
				if (wdfs.debug == true)
					fprintf(stderr,
						"++ unlocked file '%s'.\n", this_lock->uri.path);
			}
			/* get the next lock from the lockstore */
			this_lock = ne_lockstore_next(store);
		}

		/* finally destroy the lockstore */
		if (wdfs.debug == true)
			fprintf(stderr, "++ destroying lockstore.\n");
		ne_lockstore_destroy(store);
	}
}

