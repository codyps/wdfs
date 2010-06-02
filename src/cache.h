#ifndef CACHE_H_
#define CACHE_H_

void cache_initialize();
void cache_destroy();
void cache_add_item(struct stat *stat, const char *remotepath);
void cache_delete_item(const char *remotepath);
int cache_get_item(struct stat *stat, const char *remotepath);

#endif /*CACHE_H_*/
