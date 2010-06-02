#ifndef SVN_H_
#define SVN_H_

#include "wdfs-main.h"

/* look at svn.c for comments on these extern variables */
extern const char *svn_basedir;

int svn_set_repository_root();
void svn_free_repository_root();

char* svn_get_remotepath(const char *localpath);
void svn_add_level1_directories(struct dir_item *item_data);
int svn_add_level2_directories(
	struct dir_item *item_data, const char *localpath);
struct stat svn_get_static_dir_stat();
int svn_get_level1_stat(struct stat *stat, const char *localpath);

#endif /*SVN_H_*/
