#ifndef WDFSMAIN_H_
#define WDFSMAIN_H_

#ifdef HAVE_CONFIG_H
	#include <config.h>
#endif

#define FUSE_USE_VERSION 25

#include <fuse.h>
#include <ne_basic.h>

/* build the neon version, which is not directly exported by the neon library */
#if defined(NE_FEATURE_TS_SSL)	/* true for neon 0.26+  */
	#define NEON_VERSION 26
#elif defined(NE_FEATURE_SSL)	/* true for neon 0.25+  */
	#define NEON_VERSION 25
#else							/* neon 0.24 is the minimal requirement */
	#define NEON_VERSION 24
#endif
/* 	it's also possible to replace the above with the following: 
	(file configure.ac, after the PKG_CHECK_MODULES call)

	case `pkg-config --modversion neon` in
		0.24*) AC_DEFINE(NEON_VERSION, 24,
				[The minor version number of the neon library]) ;;
		0.25*) AC_DEFINE(NEON_VERSION, 25) ;;
		*)     AC_DEFINE(NEON_VERSION, 26) ;;
	esac
*/

typedef enum {
	true 	= 1,
	false 	= 0
} bool_t;

/* used as mode for unify_path() */
enum {
	ESCAPE     = 0x0,
	UNESCAPE   = 0x1,
	/* do not remove trailing slashes */
	LEAVESLASH = 0x2
};

struct wdfs_conf {
	/* the name of the wdfs executable */
	char *program_name;
	/* if set to "true" wdfs specific debug output is generated */
	bool_t debug;
	/* if set to "true" every certificate is accepted without asking the user */
	bool_t accept_certificate;
	/* username of the webdav resource */
	char *username;
	/* password of the webdav resource */
	char *password;
	/* if set to "true" enables http redirect support */
	bool_t redirect;
	/* if set to "true" enables transparent access to all svn revisions in
	 * a repository thru a virtual directory. */
	bool_t svn_mode;
	/* locking mode of files */
	int locking_mode;
	/* timeout for a lock in seconds */
	int locking_timeout;
	/* address of the webdav resource we are connecting to */
	char *webdav_resource;
};

extern struct wdfs_conf wdfs;

/* look at wdfs-main.c for comments on these extern variables */
extern const char *project_name;
extern char *remotepath_basedir;

/* used by wdfs_readdir() and by svn.h/svn.c to add files to requested 
 * directories using fuse's filler() method. */
struct dir_item {
	void *buf;
	fuse_fill_dir_t filler;
	char *remotepath;
};

char* remove_ending_slashes(const char *in);
char* unify_path(const char *in, int mode);
void free_chars(char **arg, ...);

/* takes an lvalue and sets it to NULL after freeing. taken from neon. */
#define FREE(x) do { if ((x) != NULL) free((x)); (x) = NULL; } while (0)

#ifndef HAVE_STRNDUP
	char* strndup(const char *s, size_t n);
#endif

#endif /*WDFSMAIN_H_*/
