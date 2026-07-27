#ifndef CAMERA_FUNCS_H
#define CAMERA_FUNCS_H

#include <stdint.h>

#define CAMERA_SUCCESS 0
#define CAMERA_ERROR -1

int32_t CAMERA_CheckAvailable(void);
int32_t CAMERA_EnsureDirectory(const char *directory);
int32_t CAMERA_BuildImagePath(char *out_path, uint32_t out_path_size, const char *directory, uint32_t image_counter);
int32_t CAMERA_TakeImage(const char *output_path, uint32_t width, uint32_t height, uint32_t timeout_ms);
int32_t CAMERA_GetFileSizeBytes(const char *path, uint32_t *size_bytes);
int32_t CAMERA_DeleteImage(const char *path);
uint32_t CAMERA_GetUnixTime(void);

#endif