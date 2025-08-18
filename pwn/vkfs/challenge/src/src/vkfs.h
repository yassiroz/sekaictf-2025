#ifndef VKFS_H
#define VKFS_H

#define FUSE_USE_VERSION 314

#include <stdint.h>
#include <sys/types.h>

#include <vulkan/vulkan.h>

struct vk_coord {
    uint8_t mip;
    uint8_t block_x;
    uint8_t block_y;
};

#define VK_SIGNATURE 0x8008 // haha
#define VK_MAX_FDS 1024
#define VK_BLOCK_SIZE 0x10000
#define VK_PATH_MAX 512

struct vk_header {
    uint16_t signature;
    uint8_t next_lfs_block;
    uint32_t nlink;
    mode_t mode;
    uid_t uid;
    gid_t gid;
    size_t size;
    struct timespec atime;
    struct timespec mtime;
    struct timespec ctime;
    VkDeviceMemory memory_handle;
};

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE  1
#endif
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE   2
#endif

#define VK_FILE_SYNC     1
#define VK_FILE_DSYNC    2
#define VK_FILE_APPEND   4
#define VK_FILE_READ     8
#define VK_FILE_WRITE   16
struct vk_file {
    VkImage image;
    VkDeviceMemory memory;
    int16_t lfs_fd;
    uint8_t flags;
};

struct vk_state {
    VkInstance instance;
    VkPhysicalDevice physical_device;
    VkDevice device;
    VkQueue queue;
    VkImage image;
    VkCommandPool command_pool;
    VkCommandBuffer command_buffer;
    struct vk_file files[VK_MAX_FDS];
    struct vk_file staging_file;
};
#define VK_DATA ((struct vk_state *) fuse_get_context()->private_data)

#endif
