#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#include <windows.h>
#include <io.h>
#include <direct.h>
#else
#define _FILE_OFFSET_BITS (64)
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#endif
#include "config.h"
#include "file.h"
#include "openssl/md5.h"
#include "openssl/sha.h"
#include "openssl/crypto.h"

#define PATH_BUF_LEN    (512)
#define MODE_BUF_LEN	(16)

#ifdef WIN32
int UTF8ToUnicode(const char* str_utf8, wchar_t* str_unicode)
{
	DWORD len_unicode = MultiByteToWideChar(CP_UTF8, 0, str_utf8, -1, NULL, 0);
	TCHAR *pwText = malloc(sizeof(TCHAR)* len_unicode);
	if (NULL == pwText)
	{
		return -1;
	}
	MultiByteToWideChar(CP_UTF8, 0, str_utf8, -1, pwText, len_unicode);
	wcscpy(str_unicode, pwText);
	free(pwText);
	return 0;
}
#endif

int path_format(const char *src, char *dest_buf, int size)
{
	memset(dest_buf, 0, size);
	strncpy(dest_buf, src, size);
	dest_buf[size - 1] = '\0';
	if (dest_buf[strlen(dest_buf) - 1] == '/')
	{
		dest_buf[strlen(dest_buf) - 1] = '\0';
	}
	char *str = dest_buf;
	char *out = strstr(str, "\\");
	while (out != NULL)
	{
		*out = '/';
		++out;
		str = out;
		out = strstr(str, "\\");
	}
    return 0;
}

int path_addPrefix(const char *src, char *dest_buf, int size)
{
	memset(dest_buf, 0, size);
	strncpy(dest_buf, src, size);
	dest_buf[size-1] = '\0';
	if (strcmp(dest_buf, "") == 0)
	{
		dest_buf[0] = '/';
		dest_buf[size - 1] = '\0';
		return 0;
	}
	if (dest_buf[0] != '/')
	{
		memmove(dest_buf + 1, dest_buf, strlen(dest_buf));
		dest_buf[0] = '/';
		dest_buf[size - 1] = '\0';
	}
	return 0;
}

int path_addSuffix(const char *src, char *dest_buf, int size)
{
	memset(dest_buf, 0, size);
	strncpy(dest_buf, src, size);
	dest_buf[size - 1] = '\0';
	if (strcmp(dest_buf, "") == 0)
	{
		dest_buf[0] = '/';
		dest_buf[size - 1] = '\0';
		return 0;
	}
	if (dest_buf[strlen(dest_buf)-1] != '/')
	{
		dest_buf[strlen(dest_buf)] = '/';
		dest_buf[size - 1] = '\0';
	}
	return 0;
}

int path_removePrefix(const char *src, char *dest_buf, int size)
{
	memset(dest_buf, 0, size);
	strncpy(dest_buf, src, size);
	dest_buf[size - 1] = '\0';
	if (strlen(dest_buf) > 0 && dest_buf[0] == '/')
	{
		memmove(dest_buf, dest_buf + 1, strlen(dest_buf));
	}
	return 0;
}

int path_removeSuffix(const char *src, char *dest_buf, int size)
{
	memset(dest_buf, 0, size);
	strncpy(dest_buf, src, size);
	dest_buf[size - 1] = '\0';
	if (strlen(dest_buf) > 0 && dest_buf[strlen(dest_buf) - 1] == '/')
	{
		dest_buf[strlen(dest_buf) - 1] = '\0';
	}
	return 0;
}

int isdir(const char *name)
{
	#ifdef WIN32
	wchar_t wname[sizeof(wchar_t)* PATH_BUF_LEN];
	if (UTF8ToUnicode(name, wname) == -1)
	{
		return 0;
	}
	DWORD attr = GetFileAttributesW(wname);
	if (attr != INVALID_FILE_ATTRIBUTES && attr & FILE_ATTRIBUTE_DIRECTORY)
	{
		return 1;
	}
	#else
	struct stat buf;
	if (stat(name, &buf) == 0 && buf.st_mode & S_IFDIR)
	{
		return 1;
	}
	#endif
	return 0;
}

int forder_access(const char *name)
{
	#ifdef WIN32
	/* move last '/' to '\0' */
	char dest_buf[PATH_BUF_LEN];
	memset(dest_buf, 0, sizeof(dest_buf));
	strncpy(dest_buf, name, sizeof(dest_buf));
	dest_buf[sizeof(dest_buf)-1] = '\0';
	if (dest_buf[strlen(dest_buf) - 1] == '/')
	{
		dest_buf[strlen(dest_buf) - 1] = '\0';
	}
	wchar_t wname[sizeof(wchar_t)* PATH_BUF_LEN];
	if (UTF8ToUnicode(dest_buf, wname) == -1)
	{
		return -1;
	}
	return _waccess(wname, 0);
	#else
	return access(name, F_OK);
	#endif
}

int forder_touch(const char *name, int mode)
{
	/* add '/' to last */
	char dest_buf[PATH_BUF_LEN];
	memset(dest_buf, '\0', sizeof(dest_buf));
	path_addSuffix(name, dest_buf, sizeof(dest_buf));

	char onepath[PATH_BUF_LEN];
	memset(onepath, '\0', sizeof(onepath));

	char *ptr;
	char *save = dest_buf;
	
	while ((ptr = strstr(save, "/")) != NULL)
	{
		strncat(onepath, save, strlen(save) - strlen(ptr + 1));
		onepath[sizeof(onepath) - 1] = '\0';

		if (forder_access(onepath) == -1)//not exist
		{
			#ifdef WIN32
			wchar_t wonepath[sizeof(wchar_t)* PATH_BUF_LEN];
			if (UTF8ToUnicode(onepath, wonepath) == -1)
			{
				return -1;
			}
			if (_wmkdir(wonepath) == -1)
			{
				return -1;
			}
			#else
			if (mkdir(onepath, mode) == -1)
			{
				return -1;
			}
			#endif
		}
		save = ptr + 1;
	}
	return 0;
}

int file_rename(const char *oldname, const char *newname)
{
	#ifdef WIN32
	wchar_t woldname[sizeof(wchar_t)* PATH_BUF_LEN];
	wchar_t wnewname[sizeof(wchar_t)* PATH_BUF_LEN];
	if (UTF8ToUnicode(oldname, woldname) == -1)
	{
		return -1;
	}
	if (UTF8ToUnicode(newname, wnewname) == -1)
	{
		return -1;
	}
	return _wrename(woldname, wnewname);
	#else
	return rename(oldname, newname);
	#endif
}

int file_remove(const char *name)
{
	#ifdef WIN32
	wchar_t wname[sizeof(wchar_t)* PATH_BUF_LEN];
	if (UTF8ToUnicode(name, wname) == -1)
	{
		return -1;
	}
	return _wremove(wname);
	#else
	return remove(name);
	#endif
}

FILE * file_open(const char *name, const char *mode)
{
	#ifdef WIN32
	wchar_t wmode[sizeof(wchar_t)* MODE_BUF_LEN];
	wchar_t wname[sizeof(wchar_t)* PATH_BUF_LEN];
	//char buf_mode[MODE_BUF_LEN];
	//memset(buf_mode, 0, sizeof(buf_mode));
	//strcat(buf_mode, mode);
	//strcat(buf_mode, ", ccs=UTF-8");
	//buf_mode[sizeof(buf_mode)-1] = '\0';
	//if (UTF8ToUnicode(buf_mode, wmode) == -1)
	//{
	//	return NULL;
	//}
	if (UTF8ToUnicode(mode, wmode) == -1)
	{
		return NULL;
	}
	if (UTF8ToUnicode(name, wname) == -1)
	{
		return NULL;
	}
	return _wfopen(wname, wmode);
	#else
	return fopen(name, mode);
	#endif
}

int file_access(const char *name)
{
	#ifdef WIN32
	wchar_t wname[sizeof(wchar_t)* PATH_BUF_LEN];
	if (UTF8ToUnicode(name, wname) == -1)
	{
		return -1;
	}
	return _waccess(wname, 0);
	#else
	return access(name, F_OK);
	#endif
}

int file_touch(const char *name, int mode)
{
	if (file_access(name) == -1)
	{
		#ifdef WIN32
		FILE *fp = file_open(name, "w+");
		if (NULL == fp)
		{
			return -1;
		}
		fclose(fp);
		#else
		int fd = creat(name, mode);
		if (fd == -1)
		{
			return -1;
		}
		close(fd);
		#endif
	}
	return 0;
}

int file_allocate(const char *name, int mode, int64_t offset, int64_t len)
{
	if (file_access(name) == -1)
	{
		#ifdef WIN32
		wchar_t wname[sizeof(wchar_t)* PATH_BUF_LEN];
		if (UTF8ToUnicode(name, wname) == -1)
		{
			return -1;
		}
		HANDLE hFile = CreateFile(wname, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			return -1;
		}
		// preallocate disk file                
		LARGE_INTEGER size;
		size.QuadPart = len;
		SetFilePointerEx(hFile, size, 0, FILE_BEGIN);
		SetEndOfFile(hFile);
		SetFilePointer(hFile, 0, 0, FILE_BEGIN);
		CloseHandle(hFile);
		#elif __APPLE__

		#elif ANDROID

		#else
		int fd = creat(name, mode);
		if (fd == -1)
		{
			//LogError("creat name:%s error:%s", name, strerror(errno));
			return -1;
		}
		if (fallocate(fd, 0, offset, len) == -1)
		{
			//LogError("fallocate offset=%lld len=%lld error:%s", offset, len, strerror(errno));
			return -1;
		}
		close(fd);
		#endif
	}
	return 0;
}

int file_mode(const char *name, int *mode)
{
	#ifdef WIN32
	*mode = (00400 | 00200 | 00100 | 00040 | 00004); //0744
	#else
	struct stat buf;
	if (stat(name, &buf) == 0)
	{
		*mode = buf.st_mode;
		return 0;
	}
	#endif
	return -1;
}

int file_size(const char *name, int64_t *fileSize)
{
	*fileSize = 0;
	#ifdef WIN32
	FILE *fp = file_open(name, "r");
	if (NULL == fp)
	{
		return -1;
	}
	if (fseeko64(fp, (off64_t)0, SEEK_END) == -1)
	{
		fclose(fp);
		return -1;
	}
	*fileSize = ftello64(fp);
	fclose(fp);
	#else
	struct stat buf;
	if (stat(name, &buf) == -1)
	{
		return -1;
	}
	*fileSize = buf.st_size;
	#endif
	return 0;
}

int file_md5(const char *name, char *md5_buf, int size)
{
	MD5_CTX ctx;
	int len = 0;
	unsigned char buffer[1024] = { 0 };
	unsigned char digest[MD5_DIGEST_LENGTH] = { 0 };
	FILE *fp = file_open(name, "rb");
	if (NULL == fp)
	{
		return -1;
	}
	MD5_Init(&ctx);
	while ((len = fread(buffer, 1, 1024, fp)) > 0)
	{
		MD5_Update(&ctx, buffer, len);
	}
	MD5_Final(digest, &ctx);
	OPENSSL_cleanse(&ctx, sizeof(ctx));
	fclose(fp);
	int i = 0;
	char buf[128] = { 0 };
	char tmp[3] = { 0 };
	for (i = 0; i < MD5_DIGEST_LENGTH; i++)
	{
		sprintf(tmp, "%02X", digest[i]);
		strcat(buf, tmp);
	}
	memset(md5_buf, 0, size);
	strncpy(md5_buf, buf, size);
	md5_buf[size - 1] = '\0';
	return 0;
}

int file_sha1(const char *name, char *sha1_buf, int size)
{
	SHA_CTX ctx;
	int len = 0;
	unsigned char buffer[1024] = { 0 };
	unsigned char digest[SHA_DIGEST_LENGTH] = { 0 };
	FILE *fp = file_open(name, "rb");
	if (NULL == fp)
	{
		return -1;
	}
	SHA1_Init(&ctx);
	while ((len = fread(buffer, 1, 1024, fp)) > 0)
	{
		SHA1_Update(&ctx, buffer, len);
	}
	SHA1_Final(digest, &ctx);
	OPENSSL_cleanse(&ctx, sizeof(ctx));
	fclose(fp);
	int i = 0;
	char buf[160] = { 0 };
	char tmp[3] = { 0 };
	for (i = 0; i < SHA_DIGEST_LENGTH; i++)
	{
		sprintf(tmp, "%02X", digest[i]);
		strcat(buf, tmp);
	}
	memset(sha1_buf, 0, size);
	strncpy(sha1_buf, buf, size);
	sha1_buf[size - 1] = '\0';
	return 0;
}

int file_lasttime_write(const char *name, time_t *lasttime)
{
	#ifdef WIN32
	WIN32_FIND_DATA ffd;
	HANDLE hFind = FindFirstFile(name, &ffd);
	if (NULL == hFind)
	{
		return -1;
	}
	FindClose(hFind);
	FILETIME ft = ffd.ftLastWriteTime;
	LONGLONG ll;
	ULARGE_INTEGER ui;
	ui.LowPart = ft.dwLowDateTime;
	ui.HighPart = ft.dwHighDateTime;
	ll = ft.dwHighDateTime << 32 + ft.dwLowDateTime;
	*lasttime = ((LONGLONG)(ui.QuadPart - 116444736000000000) / 10000000);
	#else
	struct stat buf;
	if (stat(name, &buf) == -1)
	{
		return -1;
	}
	*lasttime = buf.st_mtime;
	#endif
	return 0;
}

int file_path(const char *name, char *path_buf, int size)
{
	char dest_buf[PATH_BUF_LEN];
	memset(dest_buf, 0, sizeof(dest_buf));
	if (path_format(name, dest_buf, sizeof(dest_buf)) == -1)
	{
		return -1;
	}
	memset(path_buf, 0, size);
	strncpy(path_buf, dest_buf, size);
	path_buf[size - 1] = '\0';
	char *out = strrchr(path_buf, '/');
	if (out != NULL)
	{
		*(out+1) = '\0';
	}
	return 0;
}

int file_name(const char *name, char *name_buf, int size)
{
    char dest_buf[PATH_BUF_LEN];
    memset(dest_buf, 0, sizeof(dest_buf));
    if (path_format(name, dest_buf, sizeof(dest_buf)) == -1)
    {
        return -1;
    }
    memset(name_buf, 0, size);
    strncpy(name_buf, dest_buf, size);
    name_buf[size - 1] = '\0';
    char *out = strrchr(name_buf, '/');
    if (out != NULL)
    {
        memmove(name_buf, out+1, strlen(out));
    }
    return 0;
}

int file_uniqueName(const char *name, char *uniqueName_buf, int size)
{
	memset(uniqueName_buf, 0, size);
	strncpy(uniqueName_buf, name, size);
	uniqueName_buf[size - 1] = '\0';
	if (file_access(uniqueName_buf) == -1)//not exist
	{
		return 0;
	}
	char suffix[PATH_BUF_LEN];//eg: .txt  .jpg
	char body[PATH_BUF_LEN];
	memset(suffix, 0, sizeof(suffix));
	memset(body, 0, sizeof(body));
	char *pSpliter = (char *)strrchr(name, '.');
	if (pSpliter != NULL)
	{
		strncpy(suffix, pSpliter, strlen(pSpliter));
		suffix[sizeof(suffix) - 1] = '\0';
		strncpy(body, name, strlen(name) - strlen(pSpliter));
		body[sizeof(body)-1] = '\0';
	}
	else
	{
		strncpy(body, name, strlen(name));
		body[sizeof(body) - 1] = '\0';
	}
	int tryNum = 0;
	while (1)
	{
		tryNum++;
		memset(uniqueName_buf, 0, size);
		char addstr[PATH_BUF_LEN];
		memset(addstr, 0, sizeof(addstr));
		sprintf(addstr, "(%d)", tryNum);
		strcat(uniqueName_buf, body);
		strcat(uniqueName_buf, addstr);
		strcat(uniqueName_buf, suffix);
		uniqueName_buf[size-1] = '\0';
		if (file_access(uniqueName_buf) == -1)//not exist
		{
			break;
		}
	}
	return 0;
}
