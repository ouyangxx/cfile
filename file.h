#ifndef __FILE_H__
#define __FILE_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif
    
int path_format(const char *src, char *dest_buf, int size);//replace all "\\" with "/"
int path_addPrefix(const char *src, char *dest_buf, int size);//add "/" at the first of path
int path_addSuffix(const char *src, char *dest_buf, int size);//add "/" at the end of path
int path_removePrefix(const char *src, char *dest_buf, int size);//remove "/" at the first of path
int path_removeSuffix(const char *src, char *dest_buf, int size);//remove "/" at the end of path

int isdir(const char *name);//1(yes), 0(no)

int forder_access(const char *name);
int forder_touch(const char *name, int mode);

int file_rename(const char *oldname, const char *newname);
int file_remove(const char *name);
FILE * file_open(const char *name, const char *mode);
int file_access(const char *name);
int file_touch(const char *name, int mode);
int file_allocate(const char *name, int mode, int64_t offset, int64_t len);
int file_mode(const char *name, int *mode);
int file_size(const char *name, int64_t *fileSize);
int file_md5(const char *name, char *md5_buf, int size);
int file_sha1(const char *name, char *sha1_buf, int size);
int file_lasttime_write(const char *name, time_t *lasttime);
int file_path(const char *name, char *path_buf, int size);
int file_name(const char *name, char *name_buf, int size);
int file_uniqueName(const char *name, char *uniqueName_buf, int size);

#ifdef __cplusplus
}
#endif

#endif
