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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <glib.h>
#include <fuse_opt.h>
#include <ne_props.h>
#include <ne_dates.h>
#include <ne_redirect.h>

#include "wdfs-main.h"
#include "webdav.h"
#include "cache.h"
#include "svn.h"


/* there are four locking modes available. the simple locking mode locks a file 
 * on open()ing it and unlocks it on close()ing the file. the advanced mode 
 * prevents data curruption by locking the file on open() and holds the lock 
 * until the file was writen and closed or the lock timed out. the eternity 
 * mode holds the lock until wdfs is unmounted or the lock times out. the last
 * mode is to do no locking at all which is the default behaviour. */
#define NO_LOCK 0
#define SIMPLE_LOCK 1
#define ADVANCED_LOCK 2
#define ETERNITY_LOCK 3


static void print_help();
static int call_fuse_main(struct fuse_args *args);

/* define package name and version if config.h is not available. */
#ifndef HAVE_CONFIG_H
	#define PACKAGE_NAME 	"wdfs"
	#define PACKAGE_VERSION	"unknown"
#endif

/* product string according RFC 2616, that is included in every request.     */
const char *project_name = PACKAGE_NAME"/"PACKAGE_VERSION;

/* homepage of this filesystem                                               */
const char *project_uri = "http://noedler.de/projekte/wdfs/";

/* init settings with default values */
struct wdfs_conf wdfs = {
	.debug = false,
	.accept_certificate = false,
	.username = NULL,
	.password = NULL,
	.redirect = true,
	.svn_mode = false,
	.locking_mode = NO_LOCK,
	.locking_timeout = 300,
	.webdav_resource = NULL,
};

enum {
	KEY_HELP,
	KEY_VERSION,
	KEY_VERSION_FULL,
	KEY_DEBUG,
	KEY_LOCKING_MODE,
	KEY_NOOP,
};

#define WDFS_OPT(t, p, v) { t, offsetof(struct wdfs_conf, p), v }

static struct fuse_opt wdfs_opts[] = {
	FUSE_OPT_KEY("-h",				KEY_HELP),
	FUSE_OPT_KEY("--help",			KEY_HELP),
	FUSE_OPT_KEY("-v",				KEY_VERSION),
	FUSE_OPT_KEY("--version",		KEY_VERSION),
	FUSE_OPT_KEY("-vv",				KEY_VERSION_FULL),
	FUSE_OPT_KEY("--all-versions",	KEY_VERSION_FULL),
	FUSE_OPT_KEY("-D",				KEY_DEBUG),
	FUSE_OPT_KEY("wdfs_debug",		KEY_DEBUG),
	FUSE_OPT_KEY("-m %u",			KEY_LOCKING_MODE),
	FUSE_OPT_KEY("-a",				KEY_NOOP),
	WDFS_OPT("-D",					debug, true),
	WDFS_OPT("wdfs_debug",			debug, true),
	WDFS_OPT("-ac",					accept_certificate, true),
	WDFS_OPT("accept_sslcert",		accept_certificate, true),
	WDFS_OPT("-u %s",				username, 0),
	WDFS_OPT("username=%s",			username, 0),
	WDFS_OPT("-p %s",				password, 0),
	WDFS_OPT("password=%s",			password, 0),
	WDFS_OPT("no_redirect",			redirect, false),
	WDFS_OPT("-S",					svn_mode, true),
	WDFS_OPT("svn_mode",			svn_mode, true),
	WDFS_OPT("-l",					locking_mode, SIMPLE_LOCK),
	WDFS_OPT("locking",				locking_mode, SIMPLE_LOCK),
	WDFS_OPT("locking=0",			locking_mode, NO_LOCK),
	WDFS_OPT("locking=none",		locking_mode, NO_LOCK),
	WDFS_OPT("locking=1",			locking_mode, SIMPLE_LOCK),
	WDFS_OPT("locking=simple",		locking_mode, SIMPLE_LOCK),
	WDFS_OPT("locking=2",			locking_mode, ADVANCED_LOCK),
	WDFS_OPT("locking=advanced",	locking_mode, ADVANCED_LOCK),
	WDFS_OPT("locking=3",			locking_mode, ETERNITY_LOCK),
	WDFS_OPT("locking=eternity",	locking_mode, ETERNITY_LOCK),
	WDFS_OPT("-t %u",				locking_timeout, 300),
	WDFS_OPT("locking_timeout=%u",	locking_timeout, 300),
	FUSE_OPT_END
};

static int wdfs_opt_proc(
	void *data, const char *option, int key, struct fuse_args *option_list)
{
	switch (key) {
		case KEY_HELP:
			print_help();
			fuse_opt_add_arg(option_list, "-ho");
			call_fuse_main(option_list);
			exit(1);

		case KEY_VERSION:
			fprintf(stderr, "%s version: %s\n", PACKAGE_NAME, PACKAGE_VERSION);
			exit(0);

		case KEY_VERSION_FULL:
			fprintf(stderr, "%s version: %s\n", PACKAGE_NAME, PACKAGE_VERSION);
			fprintf(stderr, "%s homepage: %s\n", PACKAGE_NAME, project_uri);
			fprintf(stderr, "neon version: 0.%d\n", NEON_VERSION);
			fuse_opt_add_arg(option_list, "--version");
			call_fuse_main(option_list);
			exit(0);

		case KEY_DEBUG:
			return fuse_opt_add_arg(option_list, "-f");

		case KEY_LOCKING_MODE:
			if (option[3] != '\0' || option[2] < '0' || option[2] > '3') {
				fprintf(stderr, "%s: unknown locking mode '%s'\n",
				wdfs.program_name, option + 2);
				exit(1);
			} else {
				wdfs.locking_mode = option[2] - '0';
			}
			return 0;

		case KEY_NOOP:
			return 0;

		case FUSE_OPT_KEY_NONOPT:
			if (wdfs.webdav_resource == NULL && 
					strncmp(option, "http", 4) == 0) {
				wdfs.webdav_resource = strdup(option);
				return 0;
			}
			return 1;

		case FUSE_OPT_KEY_OPT:
			return 1;

		default:
			fprintf(stderr, "%s: unknown option '%s'\n",
				wdfs.program_name, option);
			exit(1);
	}
}


/* webdav server base directory. if you are connected to "http://server/dir/"
 * remotepath_basedir is set to "/dir" (starting slash, no ending slash).
 * if connected to the root directory (http://server/) it will be set to "". */
char *remotepath_basedir;

/* infos about an open file. used by open(), read(), write() and release()   */
struct open_file {
	unsigned long fh;	/* this file's filehandle                            */
	bool_t modified;	/* set true if the filehandle's content is modified  */
};


/* webdav properties used to get file attributes */
static const ne_propname properties_fileattr[] = {
	{ "DAV:", "resourcetype" },
	{ "DAV:", "getcontentlength" },
	{ "DAV:", "getlastmodified" },
	{ "DAV:", "creationdate" },
	{ NULL }  /* MUST be NULL terminated! */
};


/* +++ exported method +++ */


/* free()s each char passed that is not NULL and sets it to NULL after freeing */
void free_chars(char **arg, ...)
{
	va_list ap;
	va_start(ap, arg);
	while (arg) {
		if (*arg != NULL)
			free(*arg);
		*arg = NULL;
		/* get the next parameter */
		arg = va_arg(ap, char **);
	}
	va_end(ap);
}


/* removes all trailing slashes from the path. 
 * returns the new malloc()d path or NULL on error.  */
char* remove_ending_slashes(const char *path)
{
	char *new_path = strdup(path);
	int pos = strlen(path) - 1;

	while(pos >= 0  &&  new_path[pos] == '/')
		new_path[pos--] = '\0';

	return new_path;
}


/* unifies the given path by removing the ending slash and escaping or 
 * unescaping the path. returns the new malloc()d string or NULL on error. */
char* unify_path(const char *path_in, int mode)
{
	assert(path_in);
	char *path_tmp, *path_out = NULL;

	path_tmp = strdup(path_in);
	if (path_tmp == NULL)
		return NULL;

	/* some servers send the complete URI not only the path.
	 * hence remove the server part and use the path only.
	 * example1:  before: "https://server.com/path/to/hell/"
	 *            after:  "/path/to/hell/"
	 * example2:  before: "http://server.com"
	 *            after:  ""                    */
	if (g_str_has_prefix(path_tmp, "http")) {
		char *tmp0 = strdup(path_in);
		FREE(path_tmp);
		/* jump to the 1st '/' of http[s]:// */
		char *tmp1 = strchr(tmp0, '/');
		/* jump behind '//' and get the next '/'. voila: the path! */
		char *tmp2 = strchr(tmp1 + 2, '/');

		if (tmp2 == NULL)
			path_tmp = strdup("");
		else
			path_tmp = strdup(tmp2);

		FREE(tmp0);
	}

	if (mode & LEAVESLASH) {
		mode &= ~LEAVESLASH;
	} else {
		path_tmp = remove_ending_slashes(path_tmp);
	}
	
	if (path_tmp == NULL)
		return NULL;

	switch (mode) {
		case ESCAPE:
			path_out = ne_path_escape(path_tmp);
			break;
		case UNESCAPE:
			path_out = ne_path_unescape(path_tmp);
			break;
		default:
			fprintf(stderr, "## fatal error: unknown mode in %s()\n", __func__);
			exit(1);
	}

	FREE(path_tmp);
	if (path_out == NULL)
		return NULL;

	return path_out;
}


/* mac os x lacks support for strndup() because it's a gnu extension. 
 * be gentle to the apples and define the required method. */
#ifndef HAVE_STRNDUP
char* strndup(const char *str, size_t len1)
{
 	size_t len2 = strlen(str);
	if (len1 < len2)
		len2 = len1;

	char *result = (char *)malloc(len2 + 1);
	if (result == NULL)
		return NULL;

	result[len2] = '\0';
	return (char *)memcpy(result, str, len2);
}
#endif


/* +++ helper methods +++ */


/* this method prints some debug output and sets the http user agent string to
 * a more informative value. */
static void print_debug_infos(const char *method, const char *parameter)
{
	assert(method);
	fprintf(stderr, ">> %s(%s)\n", method, parameter);
	char *useragent = 
		ne_concat(project_name, " ", method, "(", parameter, ")", NULL);
	ne_set_useragent(session, useragent);
	FREE(useragent);
}


/* returns the malloc()ed escaped remotepath on success or NULL on error */
static char* get_remotepath(const char *localpath)
{
	assert(localpath);
	char *remotepath = ne_concat(remotepath_basedir, localpath, NULL);
	if (remotepath == NULL)
		return NULL;
	char *remotepath2 = unify_path(remotepath, ESCAPE | LEAVESLASH);
	FREE(remotepath);
	if (remotepath2 == NULL)
		return NULL;
	return remotepath2;
}


/* returns a filehandle for read and write on success or -1 on error */
static int get_filehandle()
{
	char dummyfile[] = "/tmp/wdfs-tmp-XXXXXX";
	/* mkstemp() replaces XXXXXX by unique random chars and
	 * returns a filehandle for reading and writing */
	int fh = mkstemp(dummyfile);
	if (fh == -1)
		fprintf(stderr, "## mkstemp(%s) error\n", dummyfile);
	if (unlink(dummyfile))
		fprintf(stderr, "## unlink() error\n");
	return fh;
}


/* evaluates the propfind result set and sets the file's attributes (stat) */
static void set_stat(struct stat* stat, const ne_prop_result_set *results)
{
	if (wdfs.debug == true)
		print_debug_infos(__func__, "");

	const char *resourcetype, *contentlength, *lastmodified, *creationdate;
	assert(stat && results);
	memset(stat, 0, sizeof(struct stat));

	/* get the values from the propfind result set */
	resourcetype	= ne_propset_value(results, &properties_fileattr[0]);
	contentlength	= ne_propset_value(results, &properties_fileattr[1]);
	lastmodified	= ne_propset_value(results, &properties_fileattr[2]);
	creationdate	= ne_propset_value(results, &properties_fileattr[3]);

	/* webdav collection == directory entry */
	if (resourcetype != NULL && !strstr("<collection", resourcetype)) {
		/* "DT_DIR << 12" equals "S_IFDIR" */
		stat->st_mode = S_IFDIR | 0777;
		stat->st_size = 4096;
	} else {
		stat->st_mode = S_IFREG | 0666;
		if (contentlength != NULL)
			stat->st_size = atoll(contentlength);
		else
			stat->st_size = 0;
	}

	stat->st_nlink = 1;
	stat->st_atime = time(NULL);

	if (lastmodified != NULL)
		stat->st_mtime = ne_rfc1123_parse(lastmodified);
	else
		stat->st_mtime = 0;

	if (creationdate != NULL)
		stat->st_ctime = ne_iso8601_parse(creationdate);
	else
		stat->st_ctime = 0;

	/* calculate number of 512 byte blocks */
	stat->st_blocks	= (stat->st_size + 511) / 512;

	/* no need to set a restrict mode, because fuse filesystems can
	 * only be accessed by the user that mounted the filesystem.  */
	stat->st_mode &= ~umask(0);
	stat->st_uid = getuid();
	stat->st_gid = getgid();
}


/* this method is invoked, if a redirect needs to be done. therefore the current
 * remotepath is freed and set to the redirect target. returns -1 and prints an
 * error if the current host and new host differ. returns 0 on success and -1 
 * on error. side effect: remotepath is freed on error. */
static int handle_redirect(char **remotepath)
{
	if (wdfs.debug == true)
		print_debug_infos(__func__, *remotepath);

	/* free the old value of remotepath, because it's no longer needed */
	FREE(*remotepath);

	/* get the current_uri and new_uri structs */
	ne_uri current_uri;
	ne_fill_server_uri(session, &current_uri);
	const ne_uri *new_uri = ne_redirect_location(session);

	if (strcasecmp(current_uri.host, new_uri->host)) {
		fprintf(stderr,
			"## error: wdfs does not support redirecting to another host!\n");
		free_chars(&current_uri.host, &current_uri.scheme, NULL);
		return -1;
	}

	/* can't use ne_uri_free() here, because only host and scheme are mallocd */
	free_chars(&current_uri.host, &current_uri.scheme, NULL);

	/* set the new remotepath to the redirect target path */
	*remotepath = ne_strdup(new_uri->path);

	return 0;
}


/* +++ fuse callback methods +++ */


/* this method is called by ne_simple_propfind() from wdfs_getattr() for a
 * specific file. it sets the file's attributes and and them to the cache. */
static void wdfs_getattr_propfind_callback(
#if NEON_VERSION >= 26
	void *userdata, const ne_uri* href_uri, const ne_prop_result_set *results)
#else
	void *userdata, const char *remotepath, const ne_prop_result_set *results)
#endif
{
#if NEON_VERSION >= 26
	char *remotepath = ne_uri_unparse(href_uri);
#endif

	if (wdfs.debug == true)
		print_debug_infos(__func__, remotepath);

	struct stat *stat = (struct stat*)userdata;
	memset(stat, 0, sizeof(struct stat));

	assert(stat && remotepath);

	set_stat(stat, results);
	cache_add_item(stat, remotepath);

#if NEON_VERSION >= 26
	FREE(remotepath);
#endif
}


/* this method returns the file attributes (stat) for a requested file either
 * from the cache or directly from the webdav server by performing a propfind
 * request. */
static int wdfs_getattr(const char *localpath, struct stat *stat)
{
	if (wdfs.debug == true)
		print_debug_infos(__func__, localpath);

	assert(localpath && stat);

	char *remotepath;

	/* for details about the svn_mode, please have a look at svn.c */
	/* get the stat for the svn_basedir, if localpath equals svn_basedir. */
	if (wdfs.svn_mode == true && !strcmp(localpath, svn_basedir)) {
		*stat = svn_get_static_dir_stat();
		return 0;
	}

	/* if svn_mode is enabled and string localpath starts with svn_basedir... */
	if (wdfs.svn_mode == true && g_str_has_prefix(localpath, svn_basedir)) {
		/* ...get stat for the level 1 directories... */
		if (svn_get_level1_stat(stat, localpath) == 0) {
			return 0;
		/* ...or get remotepath and go on. */
		} else {
			remotepath = svn_get_remotepath(localpath);
		}
	/* normal mode; no svn mode */
	} else {
		remotepath = get_remotepath(localpath);
	}

	if (remotepath == NULL)
		return -ENOMEM;

	/* stat not found in the cache? perform a propfind to get stat! */
	if (cache_get_item(stat, remotepath)) {
		int ret = ne_simple_propfind(
			session, remotepath, NE_DEPTH_ZERO, properties_fileattr,
			wdfs_getattr_propfind_callback, stat);
		/* handle the redirect and retry the propfind with the new target */
		if (ret == NE_REDIRECT && wdfs.redirect == true) {
			if (handle_redirect(&remotepath))
				return -ENOENT;
			ret = ne_simple_propfind(
				session, remotepath, NE_DEPTH_ZERO, properties_fileattr,
				wdfs_getattr_propfind_callback, stat);
		}
		if (ret != NE_OK) {
			fprintf(stderr, "## PROPFIND error in %s(): %s\n",
				__func__, ne_get_error(session));
			FREE(remotepath);
			return -ENOENT;
		}
	}

	FREE(remotepath);
	return 0;
}


/* this method is called by ne_simple_propfind() from wdfs_readdir() for each 
 * member (file) of the requested collection. this method extracts the file's
 * attributes from the webdav response, adds it to the cache and calls the fuse
 * filler method to add the file to the requested directory. */
static void wdfs_readdir_propfind_callback(
#if NEON_VERSION >= 26
	void *userdata, const ne_uri* href_uri, const ne_prop_result_set *results)
#else
	void *userdata, const char *remotepath0, const ne_prop_result_set *results)
#endif
{
#if NEON_VERSION >= 26
	char *remotepath = ne_uri_unparse(href_uri);
#else
	char *remotepath = strdup(remotepath0);
#endif

	if (wdfs.debug == true)
		print_debug_infos(__func__, remotepath);

	struct dir_item *item_data = (struct dir_item*)userdata;
	assert(item_data);

	char *remotepath1 = unify_path(remotepath, UNESCAPE);
	char *remotepath2 = unify_path(item_data->remotepath, UNESCAPE);
	if (remotepath1 == NULL || remotepath2 == NULL) {
		free_chars(&remotepath, &remotepath1, &remotepath2, NULL);
		fprintf(stderr, "## fatal error: unify_path() returned NULL\n");
		return;
	}

	/* don't add this directory to itself */
	if (!strcmp(remotepath2, remotepath1)) {
		free_chars(&remotepath, &remotepath1, &remotepath2, NULL);
		return;
	}

	/* extract filename from the path. it's the string behind the last '/'. */
	char *filename = strrchr(remotepath1, '/');
	filename++;

	/* set this file's attributes. the "ne_prop_result_set *results" contains
	 * the file attributes of all files of this collection (directory). this 
	 * performs better then single requests for each file in getattr().  */
	struct stat stat;
	set_stat(&stat, results);

	/* add this file's attributes to the cache */
	cache_add_item(&stat, remotepath1);

	/* add directory entry */
	if (item_data->filler(item_data->buf, filename, &stat, 0))
		fprintf(stderr, "## filler() error in %s()!\n", __func__);

	free_chars(&remotepath, &remotepath1, &remotepath2, NULL);
}


/* this method adds the files to the requested directory using the webdav method
 * propfind. the server responds with status code 207 that contains metadata of 
 * all files of the requested collection. for each file the method 
 * wdfs_readdir_propfind_callback() is called. */
static int wdfs_readdir(
	const char *localpath, void *buf, fuse_fill_dir_t filler,
	off_t offset, struct fuse_file_info *fi)
{
	if (wdfs.debug == true)
		print_debug_infos(__func__, localpath);

	assert(localpath && filler);

	struct dir_item item_data;
	item_data.buf = buf;
	item_data.filler = filler;

	/* for details about the svn_mode, please have a look at svn.c */
	/* if svn_mode is enabled, add svn_basedir to root */
	if (wdfs.svn_mode == true && !strcmp(localpath, "/")) {
		filler(buf, svn_basedir + 1, NULL, 0);
	}

	/* if svn_mode is enabled, add level 1 directories to svn_basedir */
	if (wdfs.svn_mode == true && !strcmp(localpath, svn_basedir)) {
		svn_add_level1_directories(&item_data);
		return 0;
	}

	/* if svn_mode is enabled and string localpath starts with svn_basedir... */
	if (wdfs.svn_mode == true && g_str_has_prefix(localpath, svn_basedir)) {
		/* ... add level 2 directories and return... */
		if (svn_add_level2_directories(&item_data, localpath) == 0) {
			return 0;
		/* ...or get remote path and go on */
		} else {
			item_data.remotepath = svn_get_remotepath(localpath);
		}
	/* normal mode; no svn mode */
	} else {
		item_data.remotepath = get_remotepath(localpath);
	}

	if (item_data.remotepath == NULL)
		return -ENOMEM;


	int ret = ne_simple_propfind(
		session, item_data.remotepath, NE_DEPTH_ONE,
		properties_fileattr, wdfs_readdir_propfind_callback, &item_data);
	/* handle the redirect and retry the propfind with the redirect target */
	if (ret == NE_REDIRECT && wdfs.redirect == true) {
		if (handle_redirect(&item_data.remotepath))
			return -ENOENT;
		ret = ne_simple_propfind(
			session, item_data.remotepath, NE_DEPTH_ONE,
			properties_fileattr, wdfs_readdir_propfind_callback, &item_data);
	}
	if (ret != NE_OK) {
			fprintf(stderr, "## PROPFIND error in %s(): %s\n",
				__func__, ne_get_error(session));
		FREE(item_data.remotepath);
		return -ENOENT;
	}

	struct stat st;
	memset(&st, 0, sizeof(st));
	st.st_mode = S_IFDIR | 0777;
	filler(buf, ".", &st, 0);
	filler(buf, "..", &st, 0);

	FREE(item_data.remotepath);
	return 0;
}


/* author jens, 13.08.2005 11:22:20, location: unknown, refactored in goettingen
 * get the file from the server already at open() and write the data to a new
 * filehandle. also create a "struct open_file" to store the filehandle. */
static int wdfs_open(const char *localpath, struct fuse_file_info *fi)
{
	if (wdfs.debug == true) {
		print_debug_infos(__func__, localpath);
		fprintf(stderr,
			">> %s() by PID %d\n", __func__, fuse_get_context()->pid);
	}

	assert(localpath &&  &fi);

	struct open_file *file = g_new0(struct open_file, 1);
	file->modified = false;

	file->fh = get_filehandle();
	if (file->fh == -1)
		return -EIO;

	char *remotepath;

	if (wdfs.svn_mode == true && g_str_has_prefix(localpath, svn_basedir))
		remotepath = svn_get_remotepath(localpath);
	else
		remotepath = get_remotepath(localpath);

	if (remotepath == NULL) {
		FREE(file);
		return -ENOMEM;
	}

	/* try to lock, if locking is enabled and file is not below svn_basedir. */
	if (wdfs.locking_mode != NO_LOCK && 
			!g_str_has_prefix(localpath, svn_basedir)) {
		if (lockfile(remotepath, wdfs.locking_timeout)) {
			/* locking the file is not possible, because the file is locked by 
			 * somebody else. read-only access is allowed. */
			if ((fi->flags & O_ACCMODE) == O_RDONLY) {
				fprintf(stderr,
					"## error: file %s is already locked. "
					"allowing read-only (O_RDONLY) access!\n", remotepath);
			} else {
				FREE(file);
				FREE(remotepath);
				return -EACCES;
			}
		}
	}

	/* GET the data to the filehandle even if the file is opened O_WRONLY,
	 * because the opening application could use pwrite() or use O_APPEND
	 * and than the data needs to be present. */
	if (ne_get(session, remotepath, file->fh)) {
		fprintf(stderr, "## GET error: %s\n", ne_get_error(session));
		FREE(remotepath);
		return -ENOENT;
	}

	FREE(remotepath);

	/* save our "struct open_file" to the fuse filehandle
	 * this looks like a dirty hack too me, but it's the fuse way... */
	fi->fh = (unsigned long)file;

	return 0;
}


/* reads data from the filehandle with pread() to fulfill read requests */
static int wdfs_read(
	const char *localpath, char *buf, size_t size,
	off_t offset, struct fuse_file_info *fi)
{
	if (wdfs.debug == true)
		print_debug_infos(__func__, localpath);

	assert(localpath && buf &&  &fi);

	struct open_file *file = (struct open_file*)(uintptr_t)fi->fh;

	int ret = pread(file->fh, buf, size, offset);
	if (ret < 0) {
		fprintf(stderr, "## pread() error: %d\n", ret);
		return -EIO;
	}

	return ret;
}


/* writes data to the filehandle with pwrite() to fulfill write requests */
static int wdfs_write(
	const char *localpath, const char *buf, size_t size,
	off_t offset, struct fuse_file_info *fi)
{
	if (wdfs.debug == true)
		print_debug_infos(__func__, localpath);

	assert(localpath && buf &&  &fi);

	/* data below svn_basedir is read-only */
	if (wdfs.svn_mode == true && g_str_has_prefix(localpath, svn_basedir))
		return -EROFS;

	struct open_file *file = (struct open_file*)(uintptr_t)fi->fh;

	int ret = pwrite(file->fh, buf, size, offset);
	if (ret < 0) {
		fprintf(stderr, "## pwrite() error: %d\n", ret);
		return -EIO;
	}

	/* set this flag, to indicate that data has been modified and needs to be
	 * put to the webdav server. */
	file->modified = true;

	return ret;
}


/* author jens, 13.08.2005 11:28:40, location: unknown, refactored in goettingen
 * wdfs_release is called by fuse, when the last reference to the filehandle is
 * removed. this happens if the file is closed. after closing the file it's
 * time to put it to the server, but only if it was modified. */
static int wdfs_release(const char *localpath, struct fuse_file_info *fi)
{
	if (wdfs.debug == true)
		print_debug_infos(__func__, localpath);

	struct open_file *file = (struct open_file*)(uintptr_t)fi->fh;

	char *remotepath = get_remotepath(localpath);
	if (remotepath == NULL)
		return -ENOMEM;

	/* put the file only to the server, if it was modified. */
	if (file->modified == true) 	{
		if (ne_put(session, remotepath, file->fh)) {
			fprintf(stderr, "## PUT error: %s\n", ne_get_error(session));
			FREE(remotepath);
			return -EIO;
		}

		if (wdfs.debug == true)
			fprintf(stderr, ">> wdfs_release(): PUT the file to the server.\n");

		/* attributes for this file are no longer up to date.
		 * so remove it from cache. */
		cache_delete_item(remotepath);

		/* unlock if locking is enabled and mode is ADVANCED_LOCK, because data
		 * has been read and writen and so now it's time to remove the lock. */
		if (wdfs.locking_mode == ADVANCED_LOCK) {
			if (unlockfile(remotepath)) {
				FREE(remotepath);
				return -EACCES;
			}
		}
	}

	/* if locking is enabled and mode is SIMPLE_LOCK, simple unlock on close() */
	if (wdfs.locking_mode == SIMPLE_LOCK) {
		if (unlockfile(remotepath)) {
			FREE(remotepath);
			return -EACCES;
		}
	}

	/* close filehandle and free memory */
	close(file->fh);
	FREE(file);
	FREE(remotepath);

	return 0;
}


/* author jens, 13.08.2005 11:32:20, location: unknown, refactored in goettingen
 * wdfs_truncate is called by fuse, when a file is opened with the O_TRUNC flag
 * or truncate() is called. according to 'man truncate' if the file previously 
 * was larger than this size, the extra data is lost. if the file previously 
 * was shorter, it is extended, and the extended part is filled with zero bytes.
 */
static int wdfs_truncate(const char *localpath, off_t size)
{
	if (wdfs.debug == true) {
		print_debug_infos(__func__, localpath);
		fprintf(stderr, ">> truncate() at offset %li\n", (long int)size);
	}

	assert(localpath);

	/* data below svn_basedir is read-only */
	if (wdfs.svn_mode == true && g_str_has_prefix(localpath, svn_basedir))
		return -EROFS;

	/* the truncate procedure:
	 *  1. get the complete file and write into fh_in
	 *  2. read size bytes from fh_in to buffer
	 *  3. write size bytes from buffer to fh_out
	 *  4. read from fh_out and put file to the server
	 */

	char *remotepath = get_remotepath(localpath);
	if (remotepath == NULL)
		return -ENOMEM;

	int ret;
	int fh_in  = get_filehandle();
	int fh_out = get_filehandle();
	if (fh_in == -1 || fh_out == -1)
		return -EIO;

	char buffer[size];
	memset(buffer, 0, size);

	/* if truncate(0) is called, there is no need to get the data, because it 
	 * would not be used. */
	if (size != 0) {
		if (ne_get(session, remotepath, fh_in)) {
			fprintf(stderr, "## GET error: %s\n", ne_get_error(session));
			close(fh_in);
			close(fh_out);
			FREE(remotepath);
			return -ENOENT;
		}

		ret = pread(fh_in, buffer, size, 0);
		if (ret < 0) {
			fprintf(stderr, "## pread() error: %d\n", ret);
			close(fh_in);
			close(fh_out);
			FREE(remotepath);
			return -EIO;
		}
	}

	ret = pwrite(fh_out, buffer, size, 0);
	if (ret < 0) {
		fprintf(stderr, "## pwrite() error: %d\n", ret);
		close(fh_in);
		close(fh_out);
		FREE(remotepath);
		return -EIO;
	}

	if (ne_put(session, remotepath, fh_out)) {
		fprintf(stderr, "## PUT error: %s\n", ne_get_error(session));
		close(fh_in);
		close(fh_out);
		FREE(remotepath);
		return -EIO;
	}

	/* stat for this file is no longer up to date. remove it from the cache. */
	cache_delete_item(remotepath);

	close(fh_in);
	close(fh_out);
	FREE(remotepath);
	return 0;
}


/* author jens, 12.03.2006 19:44:23, location: goettingen in the winter
 * ftruncate is called on already opened files, truncate on not yet opened
 * files. ftruncate is supported since wdfs 1.2.0 and needs at least 
 * fuse 2.5.0 and linux kernel 2.6.15. */
static int wdfs_ftruncate(
	const char *localpath, off_t size, struct fuse_file_info *fi)
{
	if (wdfs.debug == true)
		print_debug_infos(__func__, localpath);

	assert(localpath &&  &fi);

	/* data below svn_basedir is read-only */
	if (wdfs.svn_mode == true && g_str_has_prefix(localpath, svn_basedir))
		return -EROFS;

	char *remotepath = get_remotepath(localpath);
	if (remotepath == NULL)
		return -ENOMEM;

	struct open_file *file = (struct open_file*)(uintptr_t)fi->fh;

	int ret = ftruncate(file->fh, size);
	if (ret < 0) {
		fprintf(stderr, "## ftruncate() error: %d\n", ret);
		FREE(remotepath);
		return -EIO;
	}

	/* set this flag, to indicate that data has been modified and needs to be
	 * put to the webdav server. */
	file->modified = true;

	/* update the cache item of the ftruncate()d file */
	struct stat stat;
	if (cache_get_item(&stat, remotepath) < 0) {
		fprintf(stderr,
			"## cache_get_item() error: item '%s' not found!\n", remotepath);
		FREE(remotepath);
		return -EIO;
	}

	/* set the new size after the ftruncate() call */
	stat.st_size = size;

	/* calculate number of 512 byte blocks */
	stat.st_blocks	= (stat.st_size + 511) / 512;

	/* update the cache */
	cache_add_item(&stat, remotepath);

	FREE(remotepath);

	return 0;
}


/* author jens, 28.07.2005 18:15:12, location: noedlers garden in trubenhausen
 * this method creates a empty file using the webdav method put. */
static int wdfs_mknod(const char *localpath, mode_t mode, dev_t rdev)
{
	if (wdfs.debug == true)
		print_debug_infos(__func__, localpath);

	assert(localpath);

	/* data below svn_basedir is read-only */
	if (wdfs.svn_mode == true && g_str_has_prefix(localpath, svn_basedir))
		return -EROFS;

	char *remotepath = get_remotepath(localpath);
	if (remotepath == NULL)
		return -ENOMEM;

	int fh = get_filehandle();
	if (fh == -1) {
		FREE(remotepath);
		return -EIO;
	}

	if (ne_put(session, remotepath, fh)) {
		fprintf(stderr, "## PUT error: %s\n", ne_get_error(session));
		close(fh);
		FREE(remotepath);
		return -EIO;
	}

	close(fh);
	FREE(remotepath);
	return 0;
}


/* author jens, 03.08.2005 12:03:40, location: goettingen
 * this method creates a directory / collection using the webdav method mkcol. */
static int wdfs_mkdir(const char *localpath, mode_t mode)
{
	if (wdfs.debug == true)
		print_debug_infos(__func__, localpath);

	assert(localpath);

	/* data below svn_basedir is read-only */
	if (wdfs.svn_mode == true && g_str_has_prefix(localpath, svn_basedir))
		return -EROFS;

	char *remotepath = get_remotepath(localpath);
	if (remotepath == NULL)
		return -ENOMEM;

	if (ne_mkcol(session, remotepath)) {
		fprintf(stderr, "MKCOL error: %s\n", ne_get_error(session));
		FREE(remotepath);
		return -ENOENT;
	}

	FREE(remotepath);
	return 0;
}


/* author jens, 30.07.2005 13:08:11, location: heli at heinemanns
 * this methods removes a file or directory using the webdav method delete. */
static int wdfs_unlink(const char *localpath)
{
	if (wdfs.debug == true)
		print_debug_infos(__func__, localpath);

	assert(localpath);

	/* data below svn_basedir is read-only */
	if (wdfs.svn_mode == true && g_str_has_prefix(localpath, svn_basedir))
		return -EROFS;

	char *remotepath = get_remotepath(localpath);
	if (remotepath == NULL)
		return -ENOMEM;

	/* unlock the file, to be able to unlink it */
	if (wdfs.locking_mode != NO_LOCK) {
		if (unlockfile(remotepath)) {
			FREE(remotepath);
			return -EACCES;
		}
	}

	int ret = ne_delete(session, remotepath);
	if (ret == NE_REDIRECT && wdfs.redirect == true) {
		if (handle_redirect(&remotepath))
			return -ENOENT;
		ret = ne_delete(session, remotepath);
	}

	/* file successfully deleted! remove it also from the cache. */
	if (ret == 0) {
		cache_delete_item(remotepath);
	/* return more specific error message in case of permission problems */
	} else if (!strcmp(ne_get_error(session), "403 Forbidden")) {
		ret = -EPERM;
	} else {
		fprintf(stderr, "## DELETE error: %s\n", ne_get_error(session));
		ret = -EIO;
	}

	FREE(remotepath);
	return ret;
}


/* author jens, 31.07.2005 19:13:39, location: heli at heinemanns
 * this methods renames a file. it uses the webdav method move to do that. */
static int wdfs_rename(const char *localpath_src, const char *localpath_dest)
{
	if (wdfs.debug == true) {
		print_debug_infos(__func__, localpath_src);
		print_debug_infos(__func__, localpath_dest);
	}

	assert(localpath_src && localpath_dest);

	/* data below svn_basedir is read-only */
	if	(wdfs.svn_mode == true &&
		(g_str_has_prefix(localpath_src, svn_basedir) ||
		 g_str_has_prefix(localpath_dest, svn_basedir)))
		return -EROFS;

	char *remotepath_src  = get_remotepath(localpath_src);
	char *remotepath_dest = get_remotepath(localpath_dest);
	if (remotepath_src == NULL || remotepath_dest == NULL )
		return -ENOMEM;

	/* unlock the source file, before renaming */
	if (wdfs.locking_mode != NO_LOCK) {
		if (unlockfile(remotepath_src)) {
			FREE(remotepath_src);
			return -EACCES;
		}
	}

	int ret = ne_move(session, 1, remotepath_src, remotepath_dest);
	if (ret == NE_REDIRECT && wdfs.redirect == true) {
		if (handle_redirect(&remotepath_src))
			return -ENOENT;
		ret = ne_move(session, 1, remotepath_src, remotepath_dest);
	}

	if (ret == 0) {
		/* rename was successful and the source file no longer exists.
		 * hence, remove it from the cache. */
		cache_delete_item(remotepath_src);
	} else {
		fprintf(stderr, "## MOVE error: %s\n", ne_get_error(session));
		ret = -EIO;
	}

	free_chars(&remotepath_src, &remotepath_dest, NULL);
	return ret;
}


/* this is just a dummy implementation to avoid errors, when running chmod. */
int wdfs_chmod(const char *localpath, mode_t mode)
{
	if (wdfs.debug == true)
		print_debug_infos(__func__, localpath);

	fprintf(stderr, "## error: chmod() is not (yet) implemented.\n");

	return 0;
}


/* this is just a dummy implementation to avoid errors, when setting attributes.
 * a usefull implementation is not possible, because the webdav standard only 
 * defines a "getlastmodified" property that is read-only and just updated when
 * the file's content or properties change. */
static int wdfs_setattr(const char *localpath, struct utimbuf *buf)
{
	if (wdfs.debug == true)
		print_debug_infos(__func__, localpath);

	return 0;
}


/* this is a dummy implementation that pretends to have 1000 GB free space :D */
static int wdfs_statfs(const char *localpath, struct statvfs *buf)
{
	if (wdfs.debug == true)
		print_debug_infos(__func__, localpath);

	/* taken from sshfs v1.7, thanks miklos! */
	buf->f_bsize = 512;
	buf->f_blocks = buf->f_bfree = buf->f_bavail =
		1000ULL * 1024 * 1024 * 1024 / buf->f_bsize;
	buf->f_files = buf->f_ffree = 1000000000;

	return 0;
}


/* just say hello when fuse takes over control. */
#if FUSE_VERSION >= 26
	static void* wdfs_init(struct fuse_conn_info *conn)
#else
	static void* wdfs_init()
#endif
{
	if (wdfs.debug == true)
		fprintf(stderr, ">> %s()\n", __func__);
	return NULL;
}


/* author jens, 04.08.2005 17:41:12, location: goettingen
 * this method is called, when the filesystems is unmounted. time to clean up! */
static void wdfs_destroy()
{
	if (wdfs.debug == true)
		fprintf(stderr, ">> freeing globaly used memory\n");

	/* free globaly used memory */
	cache_destroy();
	unlock_all_files();
	ne_session_destroy(session);
	FREE(remotepath_basedir);
	svn_free_repository_root();
}


static struct fuse_operations wdfs_operations = {
	.getattr	= wdfs_getattr,
	.readdir	= wdfs_readdir,
	.open		= wdfs_open,
	.read		= wdfs_read,
	.write		= wdfs_write,
	.release	= wdfs_release,
	.truncate	= wdfs_truncate,
	.ftruncate	= wdfs_ftruncate,
	.mknod		= wdfs_mknod,
	.mkdir		= wdfs_mkdir,
	/* webdav treats file and directory deletions equal, both use wdfs_unlink */
	.unlink		= wdfs_unlink,
	.rmdir		= wdfs_unlink,
	.rename		= wdfs_rename,
	.chmod		= wdfs_chmod,
	/* utime should be better named setattr
	 * see: http://sourceforge.net/mailarchive/message.php?msg_id=11344401 */
	.utime		= wdfs_setattr,
	.statfs		= wdfs_statfs,
	.init		= wdfs_init,
	.destroy	= wdfs_destroy,
};


/* author jens, 26.08.2005 12:26:59, location: lystrup near aarhus 
 * this method prints help and usage information, call fuse to print its
 * help information. */
static void print_help()
{
	fprintf(stderr,
"usage: %s http[s]://server[:port][/directory/] mountpoint [options]\n\n"
"wdfs options:\n"
"    -v, --version          show version of wdfs\n"
"    -vv, --all-versions    show versions of wdfs, neon and fuse\n"
"    -h, --help             show this help page\n"
"    -D, -o wdfs_debug      enable wdfs debug output\n"
"    -o accept_sslcert      accept ssl certificate, don't prompt the user\n"
"    -o username=arg        replace arg with username of the webdav resource\n"
"    -o password=arg        replace arg with password of the webdav resource\n"
"                           username/password can also be entered interactively\n"
"    -o no_redirect         disable http redirect support\n"
"    -o svn_mode            enable subversion mode to access all revisions\n"
"    -o locking             same as -o locking=simple\n"
"    -o locking=mode        select a file locking mode:\n"
"                           0 or none:     disable file locking (default)\n"
"                           1 or simple:   from open until close\n"
"                           2 or advanced: from open until write + close\n"
"                           3 or eternity: from open until umount or timeout\n"
"    -o locking_timeout=sec timeout for a lock in seconds, -1 means infinite\n"
"                           default is 300 seconds (5 minutes)\n\n"
"wdfs backwards compatibility options: (used until wdfs 1.3.1)\n"
"    -a uri                 address of the webdav resource to mount\n"
"    -ac                    same as -o accept_sslcert\n"
"    -u arg                 same as -o username=arg\n"
"    -p arg                 same as -o password=arg\n"
"    -S                     same as -o svn_mode\n"
"    -l                     same as -o locking=simple\n"
"    -m locking_mode        same as -o locking=mode (only numerical modes)\n"
"    -t seconds             same as -o locking_timeout=sec\n\n",
	wdfs.program_name);
}


/* just a simple wrapper for fuse_main(), because the interface changed...  */
static int call_fuse_main(struct fuse_args *args)
{
#if FUSE_VERSION >= 26
	return fuse_main(args->argc, args->argv, &wdfs_operations, NULL);
#else
	return fuse_main(args->argc, args->argv, &wdfs_operations);
#endif
}


/* the main method does the option parsing using fuse_opt_parse(), establishes
 * the connection to the webdav resource and finally calls main_fuse(). */
int main(int argc, char *argv[])
{
	int status_program_exec = 1;

	struct fuse_args options = FUSE_ARGS_INIT(argc, argv);
	wdfs.program_name = argv[0];

	if (fuse_opt_parse(&options, &wdfs, wdfs_opts, wdfs_opt_proc) == -1)
		exit(1);

	if (!wdfs.webdav_resource) {
		fprintf(stderr, "%s: missing webdav uri\n", wdfs.program_name);
		exit(1);
	}

	if (wdfs.locking_timeout < -1 || wdfs.locking_timeout == 0) {
		fprintf(stderr, "## error: timeout must be bigger than 0 or -1!\n");
		exit(1);
	}

	if (wdfs.debug == true) {
		fprintf(stderr, 
			"wdfs settings:\n  program_name: %s\n  webdav_resource: %s\n"
			"  accept_certificate: %s\n  username: %s\n  password: %s\n"
			"  redirect: %s\n  svn_mode: %s\n  locking_mode: %i\n"
			"  locking_timeout: %i\n",
			wdfs.program_name,
			wdfs.webdav_resource ? wdfs.webdav_resource : "NULL",
			wdfs.accept_certificate == true ? "true" : "false",
			wdfs.username ? wdfs.username : "NULL",
			wdfs.password ? "****" : "NULL",
			wdfs.redirect == true ? "true" : "false",
			wdfs.svn_mode == true ? "true" : "false",
			wdfs.locking_mode, wdfs.locking_timeout);
	}

	/* set a nice name for /proc/mounts */
	char *fsname = ne_concat("-ofsname=wdfs (", wdfs.webdav_resource, ")", NULL);
	fuse_opt_add_arg(&options, fsname);
	FREE(fsname);

	/* ensure that wdfs is called in single thread mode */
	fuse_opt_add_arg(&options, "-s");

	/* wdfs must not use the fuse caching of names (entries) and attributes! */
	fuse_opt_add_arg(&options, "-oentry_timeout=0");
	fuse_opt_add_arg(&options, "-oattr_timeout=0");

	/* reset parameters to avoid storing sensitive data in the process table */
	int arg_number = 1;
	for (; arg_number < argc; arg_number++)
		memset(argv[arg_number], 0, strlen(argv[arg_number]));

	/* set up webdav connection, exit on error */
	if (setup_webdav_session(wdfs.webdav_resource, wdfs.username, wdfs.password)) {
		status_program_exec = 1;
		goto cleanup;
	}

	if (wdfs.svn_mode == true) {
		if(svn_set_repository_root()) {
			fprintf(stderr,
				"## error: could not set subversion repository root.\n");
			ne_session_destroy(session);
			status_program_exec = 1;
			goto cleanup;
		}
	}

	cache_initialize();

	/* finally call fuse */
	status_program_exec = call_fuse_main(&options);

	/* clean up and quit wdfs */
cleanup:
	free_chars(&wdfs.webdav_resource, &wdfs.username, &wdfs.password, NULL);
	fuse_opt_free_args(&options);

	return status_program_exec;
}
