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
#include <glib.h>
#include <pthread.h>
#include <unistd.h>

#include "wdfs-main.h"
#include "cache.h"

/* this cache is designed to buffer the file's attributes (struct stat) locally
 * instead of sending a new request to the webdav server. this leads into a
 * better responsiveness of the filesystem.
 * every file's attributes is stored in a 'struct cache_item' that contains a
 * 'struct stat' and a 'time_t timeout' field. the timeout field is used to 
 * purge the cache_item, if it is too old. how long a cache_item is stored is
 * configured at CACHE_ITEM_TIMEOUT (in seconds).
 * the cache_items are stored in a hash as a hash value and the corresponding
 * remotepath (uri) as the hash key. because the remotepath (uri) is unique,
 * a hash is a appropriate data structure and accessing it is fast.
 * a 2nd thread runs every CACHE_ITEM_TIMEOUT seconds in the background and
 * removed timed out cache_items. 
 */


/* lifetime of a cache item in seconds. this value can be edit here. */
const size_t cache_item_lifetime = 20;

/* initalize this mutex, which is used to prevent data 
 * inconsistencies due to race conditions. */
pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;

/* every created thread needs an id. this is the cache control thread's id. */
pthread_t cache_control_thread_id;

/* hash object to store the cache items */
static GHashTable *cache;


struct cache_item {
	struct stat stat;	/* 96 bytes (i386) */
	time_t timeout;		/*  4 bytes (i386) */
};


/* +++++++ local static methods +++++++ */
/* author jens, 31.07.2005 18:44:28, location: heli at heinemanns */


/* returns 0 if the item is _not_ timed out, returns 1 if it _is_ timed out. */
static int cache_item_timed_out(const int timeout)
{
	if (timeout - time(NULL) <= 0)
		return 1;
	else 
		return 0;
}


/* callback method for g_hash_table_foreach_remove() called in cache_control_
 * thread(). this method check if a cache item has reached it's timeout and 
 * then removes it from the cache.  */
static int cache_control_thread_callback(void *key, void *value, void *userdata)
{
	struct cache_item *item = (struct cache_item *)value;
	if (cache_item_timed_out(item->timeout)) {
		if (wdfs.debug == true) {
			fprintf(stderr,
				"** cache control thread: "
				"item has timed out and is removed '%s'\n", (char*)key);
		}
		/* remove this item */
		return 1;
	}
	/* don't remove this item */
	return 0;
}


/* +++++++ exported non-static methods +++++++ */


/* this thread runs until it is canceled by the main thread and
 * removes every CACHE_ITEM_TIMEOUT seconds timed out cache items. */
static void* cache_control_thread(void *unused)
{
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	/* thread exits if a cancel signal is recieved and
	 * cansel state is PTHREAD_CANCEL_ENABLE */
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	while (1) {
		sleep(cache_item_lifetime);
		/* do not allow cancling this thread while doing it's work */
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		/* to avoid conflict with cache_delete_item() lock */
		pthread_mutex_lock(&cache_mutex);
		/* check each cache item, if it is timed out and remove it */
		g_hash_table_foreach_remove(cache, &cache_control_thread_callback, NULL);
		pthread_mutex_unlock(&cache_mutex);
		/* now this thread might be cancel, because it is idle */
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	}
	return NULL;
}


/* initializes the cache's hash table and start a 2nd thread, that removed 
 * timed out item from the cache periodically. */
void cache_initialize()
{
	cache = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	assert(cache);

	/* setup a thread, that removes timed out cache items in the background */
	pthread_create(&cache_control_thread_id, NULL, &cache_control_thread, NULL);
}


/* detroys the cache if it's no longer needed. joins the 2nd thread and kills
 * the hash table. */
void cache_destroy()
{
	if (wdfs.debug == true)
		fprintf(stderr,
			"** destroying %d cache items\n", g_hash_table_size(cache));
	/* exit cache control thread */
	pthread_cancel(cache_control_thread_id);
	pthread_join(cache_control_thread_id, NULL);

	/* to avoid conflict with cache_control_thread() lock */
	pthread_mutex_lock(&cache_mutex);
	g_hash_table_destroy(cache);
	pthread_mutex_unlock(&cache_mutex);
}


/* adds a new item to the cache and sets the items timeout. */
void cache_add_item(struct stat *stat, const char *remotepath)
{
	assert(remotepath && stat);

	char *remotepath2 = unify_path(remotepath, UNESCAPE);
	if (remotepath2 == NULL) {
		fprintf(stderr, "## fatal error: unify_path() returned NULL\n");
		return;
	}

	/* get the new cache item and set it's values */
	struct cache_item *item = g_new0(struct cache_item, 1);
	item->stat = *stat;
	item->timeout = time(NULL) + cache_item_lifetime;

	/* to avoid conflict with cache_control_thread() lock */
	pthread_mutex_lock(&cache_mutex);
	g_hash_table_insert(cache, strdup(remotepath2), item);
	pthread_mutex_unlock(&cache_mutex);

	if (wdfs.debug == true)
		fprintf(stderr, "** added cache item for '%s'\n", remotepath2);
	FREE(remotepath2);
}


/* deletes a cache item from the cache. */
void cache_delete_item(const char *remotepath)
{
	assert(remotepath);

	char *remotepath2 = unify_path(remotepath, UNESCAPE);
	if (remotepath2 == NULL) {
		fprintf(stderr, "## fatal error: unify_path() returned NULL\n");
		return;
	}

	/* to avoid conflict with cache_control_thread() lock */
	pthread_mutex_lock(&cache_mutex);
	struct cache_item *item = 
		(struct cache_item *)g_hash_table_lookup(cache, remotepath2);
	if (item != NULL) {
		g_hash_table_remove(cache, remotepath2);
		if (wdfs.debug == true)
			fprintf(stderr, "** removed cache item for '%s'\n", remotepath2);
	}
	pthread_mutex_unlock(&cache_mutex);
	FREE(remotepath2);
}


/* looks at the cache for the wanted item. if it's found and not already timed
 * out, the "struct stat *stat" is pointing to the wanted item's stat. 
 * returns 0 on success or -1 on error. */
int cache_get_item(struct stat *stat, const char *remotepath)
{
	int ret = -1;
	assert(remotepath && stat);

	char *remotepath2 = unify_path(remotepath, UNESCAPE);
	if (remotepath2 == NULL) {
		fprintf(stderr, "## error: unify_path() returned NULL\n");
		return -1;
	}

	/* to avoid conflict with cache_control_thread() lock */
	pthread_mutex_lock(&cache_mutex);
	if (g_hash_table_lookup(cache, remotepath2) != NULL) {
		struct cache_item *item =
			(struct cache_item *)g_hash_table_lookup(cache, remotepath2);
		pthread_mutex_unlock(&cache_mutex);
		/* used cached item, if it's not timed out */
		if (!cache_item_timed_out(item->timeout)) {
			*stat = item->stat;
			ret = 0;
			if (wdfs.debug == true)
				fprintf(stderr, "** cache hit for '%s'\n", remotepath2);
		/* if this cache item has timed out, remove it */
		} else {
			if (wdfs.debug == true)
				fprintf(stderr, "** cache item timed out '%s'\n", remotepath2);
			cache_delete_item(remotepath2);
		}
	} else {
		pthread_mutex_unlock(&cache_mutex);
		if (wdfs.debug == true)
			fprintf(stderr, "** <no> cache hit for '%s'\n", remotepath2);
	}
	FREE(remotepath2);
	return ret;
}

