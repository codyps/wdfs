#ifndef WEBDAV_H_
#define WEBDAV_H_

extern ne_session *session;

int setup_webdav_session();

int lockfile(const char *remotepath, const int timeout);
int unlockfile(const char *remotepath);
void unlock_all_files();

#endif /*WEBDAV_H_*/
