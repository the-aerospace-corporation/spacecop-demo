#include "camera_funcs.h"
#include "camera_app.h"   /* CAMERA_LOG_DIR / CAMERA_IMAGE_DIR */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

int32_t CAMERA_CheckAvailable(void)
{
	if (system("command -v rpicam-still > /dev/null 2>&1") == 0)
	{
		return CAMERA_SUCCESS;
	}

	if (system("command -v libcamera-still > /dev/null /2>&1") == 0)
	{
		return CAMERA_SUCCESS;
	}

	return CAMERA_ERROR;
}

int32_t CAMERA_EnsureDirectory(const char *directory)
{
	struct stat st;

	if (directory == NULL)
	{
		return CAMERA_ERROR;
	}

	if (stat(directory, &st) == 0)
	{
		if (S_ISDIR(st.st_mode))
		{
			return CAMERA_SUCCESS;
		}

		return CAMERA_ERROR;
	}

	if (mkdir(directory, 0775) != 0)
	{
		return CAMERA_ERROR;
	}

	return CAMERA_SUCCESS;
}

int32_t CAMERA_BuildImagePath(char *out_path, uint32_t out_path_size, const char *directory, uint32_t image_counter)
{
	if (out_path == NULL || directory == NULL || out_path_size == 0)
	{
		return CAMERA_ERROR;
	}

	snprintf(out_path, out_path_size, "%s/capture_%lu.jpg", directory, (unsigned long)image_counter);

	return CAMERA_SUCCESS;
}

int32_t CAMERA_TakeImage(const char *output_path, uint32_t width, uint32_t height, uint32_t timeout_ms)
{
	char cmd[512];

	if (output_path == NULL)
	{
		return CAMERA_ERROR;
	}

	snprintf(cmd, sizeof(cmd), "rpicam-still --nopreview --timeout %lu --width %lu --height %lu -o '%s' > " CAMERA_LOG_DIR "/camera_app.log 2>&1", (unsigned long)timeout_ms, (unsigned long)width, (unsigned long)height, output_path);

	if (system(cmd) == 0 && access(output_path, F_OK) == 0)
	{
		return CAMERA_SUCCESS;
	}

	snprintf(cmd, sizeof(cmd), "raspistill -w %lu -h %lu -t %lu -o '%s' > " CAMERA_LOG_DIR "/camera_app.log 2>&1", (unsigned long)width, (unsigned long)height, (unsigned long)timeout_ms, output_path);

	if (system(cmd) == 0 && access(output_path, F_OK) == 0)
	{
		return CAMERA_SUCCESS;
	}

	return CAMERA_ERROR;
}

int32_t CAMERA_GetFileSizeBytes(const char *path, uint32_t *size_bytes)
{
	struct stat st;

	if (path == NULL || size_bytes == NULL)
	{
		return CAMERA_ERROR;
	}

	if (stat(path, &st) != 0)
	{
		return CAMERA_ERROR;
	}

	*size_bytes = (uint32_t)st.st_size;
	return CAMERA_SUCCESS;
}

int32_t CAMERA_DeleteImage(const char *path)
{
	if (path == NULL || path[0] == '\0')
	{
		return CAMERA_ERROR;
	}

	if (unlink(path) != 0)
	{
		return CAMERA_ERROR;
	}

	return CAMERA_SUCCESS;
}

uint32_t CAMERA_GetUnixTime(void)
{
	return (uint32_t)time(NULL);
}