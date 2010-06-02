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
#include <assert.h>
#include <unistd.h>
#include <glib.h>
#include <ne_props.h>

#include "wdfs-main.h"
#include "webdav.h"
#include "svn.h"


/* wdfs has some special subversion (svn) related features. if "svn_mode" is
 * set to "true", wdfs will provide transparent access to all svn revisions via
 * a virtual directory, that will be added below the fuse mountpoint. the name
 * of the virtual directory is set to the value of the variable "svn_basedir".
 * 
 * below the svn_basedir there will be a dirctory for each revision, that
 * contains all files, that belong to the specific revision. because there 
 * can be a lot of revision, the directories will be clustered into chunks.
 * 
 * the directory chunks are called "level 1" and the ones, which contains the
 * specific revision's data are called "level 2":
 *  
 * level 2 -----------------\
 * level 1 ---------\       |
 *                  |       |
 * ...              |       |
 * /svn_basedir/5000-5199/5000/
 * /svn_basedir/5000-5199/5001/
 * ...
 * /svn_basedir/5000-5199/5119/
 * /svn_basedir/5200-5399/5200/
 * /svn_basedir/5200-5399/5201/
 * ...
 * 
 */


/* svn_basedir specifies the name of the virtual directory, that allows
 * accessing all svn revisions. it must start with '/' and end without '/'. 
 * it may be edited here. */
const char *svn_basedir = "/0-all-revisions";

/* svn_repository_root is the path to the root of the svn repository. this is
 * needed, if a subdir of the repository is mounted to allow access to the old
 * revisions, because the path to access them always starts at the root of a 
 * repository. */
char *svn_repository_root = NULL;

/* controls how many directories are put in a single level 2 chunk. editable. */
static const int svn_revisions_per_level2_directory = 200;

/* webdav properties used to get the latest svn revision */
static const ne_propname property_checked_in[] = {
	{ "DAV:", "checked-in"},
	{ NULL } /* MUST be NULL terminated! */
};

static const ne_propname property_vcc[] = {
	{ "DAV:", "version-controlled-configuration"},
	{ NULL } /* MUST be NULL terminated! */
};



/* +++++++ local static methods +++++++ */

/* author jens, 03.08.2005 14:39:23, location: goettingen */


/* this function extracts the revision number from a string */
static void svn_get_latest_revision_callback(
#if NEON_VERSION >= 26
	void *userdata, const ne_uri* href_uri, const ne_prop_result_set *results)
#else
	void *userdata, const char *href, const ne_prop_result_set *results)
#endif
{
	assert(userdata && results);

	int *latest_revision = (int*)userdata;
	char *latest_revision_string = NULL;
	const char delimiters[] = "/";
	char *token = NULL;
	char *result = (char*)ne_propset_value(results, &property_checked_in[0]);
	/* result now looks like this "<href>/svn/dir1/dirx/!svn/bln/1234</href>".
	 * extracting the number in a bit tricky. split the string at each '/'
	 * and check if it's "!svn" followed by "bln" followed by the number. */
	do {
		token = strsep(&result, delimiters);
		if (token != NULL && !strcmp("!svn", token)) {
			/* next token should be bln */
			token = strsep(&result, delimiters);
			if (token != NULL && !strcmp("bln", token)) {
				/* the next token is the svn revision */
				token = strsep(&result, delimiters);
				if (token != NULL) {
					/* remove the last char; e.g. "1234<" to "1234" */
					latest_revision_string = strndup(token, strlen(token) - 1);
				}
			}
		}
	} while (token != NULL );

	if (wdfs.debug == true)
		fprintf(stderr,
			">> SVN latest revision _string_: %s\n", latest_revision_string);

	/* string to integer conversion */
	*latest_revision = atoi(latest_revision_string);

	FREE(latest_revision_string);
}


/* returns -1 on error or the latest svn revision on success */
static int svn_get_latest_revision()
{
	int latest_revision;
	char *uri = ne_concat(svn_repository_root, "!svn/vcc/default", NULL);
	ne_propfind_handler *pfh = ne_propfind_create(session, uri, NE_DEPTH_ZERO);
	int ret = ne_propfind_named(pfh, property_checked_in,
					&svn_get_latest_revision_callback, &latest_revision);
	ne_propfind_destroy(pfh);
	FREE(uri);
	if (ret != NE_OK) {
		fprintf(stderr, "## ne_propfind_named() error\n");
		return -1;
	}
	return latest_revision;
}


/* return the number of '/' found in a given string */
static int svn_directory_depth(const char *in)
{
	assert(in);

	int i, ret = 0;
	int len = strlen(in);
	for (i = 0; i < len; i++) {
		if (in[i] == '/')
			ret++;
	}
	return ret;
}


/* like strlen(), but for integers */
static int get_integer_length(int in)
{
	assert(in);

	int length = 1;
	while (in >= 10) {
		in = in / 10;
		length++;
	}
	return length;
}


/* callback from svn_set_repository_root() to do the dirty string parsing. */
static void svn_set_repository_root_callback(
#if NEON_VERSION >= 26
	void *userdata, const ne_uri* href_uri, const ne_prop_result_set *results)
#else
	void *userdata, const char *href, const ne_prop_result_set *results)
#endif
{
	assert(results);

	/* the string looks like "<href>/.../.../!svn/vcc/default</href>" */
	char *result = (char*)ne_propset_value(results, &property_vcc[0]);
	/* use a GString struct for comfortable string erasing */
	GString *g_result = g_string_new(result);
	/* remove starting tag ("<href>") */
	g_string_erase(g_result, 0, 6);
	/* remove trailing stuff ("!svn/vcc/default</href>"),
	 * so that only "/.../.../" -- the repository root path -- remains. */
	g_string_erase(g_result, g_result->len - 23, 23);
	svn_repository_root = strdup(g_result->str);
	g_string_free(g_result, TRUE);
}


/* +++++++ exported non-static methods +++++++ */

/* set the root path of the mounted repository. this path might differ from the
 * mounted uri if a subdir of the repository is mounted. return 0 on success or
 * -1 on error. */
int svn_set_repository_root()
{
	/* if remotepath_basedir is empty set svn_repository_root to "/" and quit */
	if (!strcmp(remotepath_basedir, "")) {
		svn_repository_root = strdup("/");
		return 0;
	}

	ne_propfind_handler *pfh = 
		ne_propfind_create(session, remotepath_basedir, NE_DEPTH_ZERO);
	int ret = ne_propfind_named(pfh, property_vcc, 
		&svn_set_repository_root_callback, NULL);
	ne_propfind_destroy(pfh);
	if (ret != NE_OK) {
		fprintf(stderr, "## ne_propfind_named() error\n");
		return -1;
	}
	return 0;
}

void svn_free_repository_root()
{
	FREE(svn_repository_root);
}


/* converts a localpath to a remotepath to access old revision 
 * IN:              /svn_basedir/x-y/1234/directory/file.txt
 * OUT: /svn_repository_root/!svn/bc/1234/directory/file.txt or NULL on error */
char* svn_get_remotepath(const char *localpath)
{
	assert(localpath);
	/* use a GString struct for comfortable string erasing */
	GString *g_localpath = g_string_new(localpath);
	/* remove the svn_basedir and the next char from the start of the string */
	g_string_erase(g_localpath, 0, strlen(svn_basedir) + 1);
	/* save the string starting with the next '/', because it's the relative
	 * path including the revision. e.g. "/1234/directory/file.txt" */
	char *path = strchr(g_localpath->str, '/');
	/* concat the svn uri string, that allows to access this revision */
	char *remotepath = ne_concat(svn_repository_root, "!svn/bc", path, NULL);
	g_string_free(g_localpath, TRUE);
	if (remotepath == NULL)
		return NULL;
	/* finally escape the string */
	char *remotepath2 = ne_path_escape(remotepath);
	FREE(remotepath);
	if (remotepath2 == NULL)
		return NULL;
	return remotepath2;
}


/* return a static stat, used for svn_basedir and level 1 directories */
struct stat svn_get_static_dir_stat()
{
	struct stat stat;
	stat.st_mode	= S_IFDIR | 0777; 
	stat.st_size	= 4096;
	stat.st_nlink	= 1;
	stat.st_atime	= stat.st_mtime = stat.st_ctime = time(NULL);
	stat.st_blocks	= (stat.st_size + 511) / 512;
	stat.st_mode	&= ~umask(0);
	stat.st_uid		= getuid();
	stat.st_gid		= getgid();
	return stat;
}


/* gets the latest revision number from subversion and adds the level1-dirs */
void svn_add_level1_directories(struct dir_item *item_data)
{
	assert(item_data);

	int latest_revision = svn_get_latest_revision();
	if (latest_revision >= 0) {

		GString *int2string = 
			g_string_new_len("", get_integer_length(latest_revision));

		int i, rest = latest_revision % svn_revisions_per_level2_directory;
		for (i = 0; i <= latest_revision; i++) {
			if (i % svn_revisions_per_level2_directory == 0) {
				GString *directory_name = g_string_new("");
				sprintf(int2string->str, "%d", i);
				g_string_append(directory_name, int2string->str);
				g_string_append_c(directory_name, '-'); 
				if (i + svn_revisions_per_level2_directory > latest_revision)
					sprintf(int2string->str, "%d", i + rest );
				else
					sprintf(int2string->str, "%d", 
						i + (svn_revisions_per_level2_directory - 1) );
				g_string_append(directory_name, int2string->str);
				item_data->filler(item_data->buf, directory_name->str, NULL, 0);
				g_string_free(directory_name, TRUE);
			}
		}
		g_string_free(int2string, TRUE);
	} else {
		fprintf(stderr, "## Error: Could not get latest revision from SVN.\n");
	}
}


/* sets the stat for a level1 directory and returns 0 (success) or 1 (error). */
int svn_get_level1_stat(struct stat *stat, const char *localpath)
{
	assert(stat && localpath);

	if (svn_directory_depth(localpath) == 2) {
		*stat = svn_get_static_dir_stat();
		return 0;
	}
	return 1;
}


/* IN:  /svn_basedir/x-y/        (as string, x and y are revision numbers)
 * OUT: /svn_basedir/x-y/x/      (as level2-dentry, added with filler method)
 *      /svn_basedir/x-y/x+1/    (as level2-dentry, added with filler method)
 *      /svn_basedir/x-y/../     (as level2-dentry, added with filler method)
 *      /svn_basedir/x-y/y-1/    (as level2-dentry, added with filler method)
 *      /svn_basedir/x-y/y/      (as level2-dentry, added with filler method)
 * returns 0 on success (added level2 directories) and 1 otherwise. */
int svn_add_level2_directories(
	struct dir_item *item_data, const char *localpath)
{
	assert(item_data && localpath);

	if (svn_directory_depth(localpath) == 2) {
		/* use a GString object for comfortable string erasing */
		GString *g_localpath = g_string_new(localpath);
		/* remove the svn_basedir and the next char from the start */
		g_string_erase(g_localpath, 0, strlen(svn_basedir) + 1);

		char delimiters[] = "-";
		char *token;
		/* the variable x_y contains the string "x-y", x and y are numbers */
		char *x_y = strdup(g_localpath->str);
		g_string_free(g_localpath, TRUE);

		char *pointer = x_y;
		token = strsep(&x_y, delimiters);
		int x = atoi(token);
		token = strsep(&x_y, delimiters);
		int y = atoi(token);
		FREE(pointer);

		GString *int2string = g_string_new_len("", get_integer_length(y));
		int i;
		/* insert all level2-dentries from x to y */
		for (i = x; i <= y; i++) {
			/* convert int to string by printing it into a string object */
			sprintf(int2string->str, "%d", i);
			item_data->filler(item_data->buf, int2string->str, NULL, 0);
		}
		g_string_free(int2string, TRUE);
		return 0;
	}
	return 1;
}

