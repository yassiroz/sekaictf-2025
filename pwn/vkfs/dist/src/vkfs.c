#include "vkfs.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>

#include <fuse3/fuse.h>
#include <openssl/sha.h>

#define MAXMIP 6

char *flag;

static struct vk_coord path_coord(const char *path) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(path, strlen(path), hash);

    struct vk_coord coord = { 0, 0, 0 };

    coord.mip = (((uint64_t *)hash)[0] % MAXMIP) + 1;
    uint8_t max_val = (1 << (MAXMIP - coord.mip)) - 1;
    coord.block_x = ((uint64_t *)hash)[1] & max_val;
    coord.block_y = ((uint64_t *)hash)[2] & max_val;

    return coord;
}

static inline uint16_t coord_ino(struct vk_coord coord) {
    // mmmmxxxxxxyyyyyy
    return (coord.block_y & 0x3f) | ((coord.block_x & 0x3f) << 6) | ((coord.mip & 0xf) << 12);
}

static inline struct vk_coord ino_coord(uint16_t ino) {
    struct vk_coord coord = {
        .mip = (ino >> 12) & 0xf,
        .block_x = (ino >> 6) & 0x3f,
        .block_y = ino & 0x3f
    };
    return coord;
}

static const char *get_parent_and_filename(const char *path, char *parent) {
    char *last_slash = strrchr(path, '/');
    if (last_slash == path) {
        strncpy(parent, path, 1);
        parent[1] = '\0';
        return path + 1;
    } else {
        strncpy(parent, path, last_slash - path);
        parent[last_slash - path] = '\0';
        return path + strlen(parent) + 1;
    }
}

static void read_coord(struct vk_coord coord, struct vk_file file) {
    struct vk_state *state = VK_DATA;

    VkCommandBufferBeginInfo begin_info = {
        .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
        .flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT
    };
    vkBeginCommandBuffer(state->command_buffer, &begin_info);
    VkImageCopy copy = {
        .srcSubresource = {
            .aspectMask = VK_IMAGE_ASPECT_COLOR_BIT,
            .mipLevel = coord.mip,
            .baseArrayLayer = 0,
            .layerCount = 1
        },
        .srcOffset = {
            .x = 256 * coord.block_x,
            .y = 256 * coord.block_y,
            .z = 0
        },
        .dstSubresource = {
            .aspectMask = VK_IMAGE_ASPECT_COLOR_BIT,
            .mipLevel = 0,
            .baseArrayLayer = 0,
            .layerCount = 1
        },
        .dstOffset = {
            .x = 0,
            .y = 0,
            .z = 0
        },
        .extent = {
            .width = 256,
            .height = 256,
            .depth = 1
        }
    };
    vkCmdCopyImage(state->command_buffer, state->image, VK_IMAGE_LAYOUT_GENERAL, file.image, VK_IMAGE_LAYOUT_GENERAL, 1, &copy);
    vkEndCommandBuffer(state->command_buffer);

    VkSubmitInfo submit_info = {
        .sType = VK_STRUCTURE_TYPE_SUBMIT_INFO,
        .commandBufferCount = 1,
        .pCommandBuffers = &state->command_buffer
    };
    vkQueueSubmit(state->queue, 1, &submit_info, VK_NULL_HANDLE);
    vkQueueWaitIdle(state->queue);

    vkResetCommandBuffer(state->command_buffer, 0);
}

static void write_coord(struct vk_coord coord, struct vk_file file) {
    struct vk_state *state = VK_DATA;

    VkCommandBufferBeginInfo begin_info = {
        .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
        .flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT
    };
    vkBeginCommandBuffer(state->command_buffer, &begin_info);
    VkImageCopy copy = {
        .srcSubresource = {
            .aspectMask = VK_IMAGE_ASPECT_COLOR_BIT,
            .mipLevel = 0,
            .baseArrayLayer = 0,
            .layerCount = 1
        },
        .srcOffset = {
            .x = 0,
            .y = 0,
            .z = 0
        },
        .dstSubresource = {
            .aspectMask = VK_IMAGE_ASPECT_COLOR_BIT,
            .mipLevel = coord.mip,
            .baseArrayLayer = 0,
            .layerCount = 1
        },
        .dstOffset = {
            .x = 256 * coord.block_x,
            .y = 256 * coord.block_y,
            .z = 0
        },
        .extent = {
            .width = 256,
            .height = 256,
            .depth = 1
        }
    };
    vkCmdCopyImage(state->command_buffer, file.image, VK_IMAGE_LAYOUT_GENERAL, state->image, VK_IMAGE_LAYOUT_GENERAL, 1, &copy);
    vkEndCommandBuffer(state->command_buffer);
    VkSubmitInfo submit_info = {
        .sType = VK_STRUCTURE_TYPE_SUBMIT_INFO,
        .commandBufferCount = 1,
        .pCommandBuffers = &state->command_buffer
    };
    vkQueueSubmit(state->queue, 1, &submit_info, VK_NULL_HANDLE);
    vkQueueWaitIdle(state->queue);

    vkResetCommandBuffer(state->command_buffer, 0);
}

static void read_file(struct vk_file file, void *buf, size_t offset, size_t len) {
    struct vk_state *state = VK_DATA;

    void *data;
    vkMapMemory(state->device, file.memory, offset, len, 0, &data);
    memcpy(buf, data, len);
    vkUnmapMemory(state->device, file.memory);
}

static void write_file(struct vk_file file, void *buf, size_t offset, size_t len) {
    struct vk_state *state = VK_DATA;

    void *data;
    vkMapMemory(state->device, file.memory, offset, len, 0, &data);
    memcpy(data, buf, len);
    vkUnmapMemory(state->device, file.memory);
}

static VkDeviceMemory alloc_and_bind(struct vk_coord coord) {
    struct vk_state *state = VK_DATA;

    VkDeviceMemory memory;
    VkMemoryAllocateInfo allocate_info = {
        .sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
        .memoryTypeIndex = 0,
        .allocationSize = VK_BLOCK_SIZE,
    };
    if (vkAllocateMemory(state->device, &allocate_info, NULL, &memory) != VK_SUCCESS) {
        return VK_NULL_HANDLE;
    }

    VkSparseImageMemoryBind image_bind = {
        .subresource = {
            .aspectMask = VK_IMAGE_ASPECT_COLOR_BIT,
            .mipLevel = coord.mip,
            .arrayLayer = 0
        },
        .offset = {
            .x = 256 * coord.block_x,
            .y = 256 * coord.block_y,
            .z = 0
        },
        .extent = {
            .width = 256,
            .height = 256,
            .depth = 1
        },
        .memory = memory,
        .memoryOffset = 0,
    };

    VkSparseImageMemoryBindInfo image_bind_info = {
        .bindCount = 1,
        .image = state->image,
        .pBinds = &image_bind
    };

    VkBindSparseInfo bind_info = {
        .sType = VK_STRUCTURE_TYPE_BIND_SPARSE_INFO,
        .imageBindCount = 1,
        .pImageBinds = &image_bind_info,
    };

    vkQueueBindSparse(state->queue, 1, &bind_info, VK_NULL_HANDLE);
    vkQueueWaitIdle(state->queue);

    return memory;
}

static void unbind_and_free(struct vk_coord coord, VkDeviceMemory memory) {
    struct vk_state *state = VK_DATA;

    VkSparseImageMemoryBind image_bind = {
        .subresource = {
            .aspectMask = VK_IMAGE_ASPECT_COLOR_BIT,
            .mipLevel = coord.mip,
            .arrayLayer = 0
        },
        .offset = {
            .x = 256 * coord.block_x,
            .y = 256 * coord.block_y,
            .z = 0
        },
        .extent = {
            .width = 256,
            .height = 256,
            .depth = 1
        },
        .memory = VK_NULL_HANDLE,
        .memoryOffset = 0,
    };

    VkSparseImageMemoryBindInfo image_bind_info = {
        .bindCount = 1,
        .image = state->image,
        .pBinds = &image_bind
    };

    VkBindSparseInfo bind_info = {
        .sType = VK_STRUCTURE_TYPE_BIND_SPARSE_INFO,
        .imageBindCount = 1,
        .pImageBinds = &image_bind_info,
    };

    vkQueueBindSparse(state->queue, 1, &bind_info, VK_NULL_HANDLE);
    vkQueueWaitIdle(state->queue);

    vkFreeMemory(state->device, memory, NULL);
}

static int create_file(struct vk_file *file) {
    struct vk_state *state = VK_DATA;

    VkImageCreateInfo create_info = {
        .sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO,
        .imageType = VK_IMAGE_TYPE_2D,
        .format = VK_FORMAT_R8_UINT,
        .extent = {
            .width = 256,
            .height = 256,
            .depth = 1
        },
        .mipLevels = 1,
        .arrayLayers = 1,
        .samples = VK_SAMPLE_COUNT_1_BIT,
        .tiling = VK_IMAGE_TILING_LINEAR,
        .usage = VK_IMAGE_USAGE_TRANSFER_SRC_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT,
        .sharingMode = VK_SHARING_MODE_EXCLUSIVE,
        .initialLayout = VK_IMAGE_LAYOUT_UNDEFINED
    };

    if (vkCreateImage(state->device, &create_info, NULL, &file->image) != VK_SUCCESS) {
        return -ENOMEM;
    }

    VkMemoryAllocateInfo allocate_info = {
        .sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
        .memoryTypeIndex = 0,
        .allocationSize = VK_BLOCK_SIZE,
    };
    if (vkAllocateMemory(state->device, &allocate_info, NULL, &file->memory) != VK_SUCCESS) {
        return -ENOMEM;
    }

    if (vkBindImageMemory(state->device, file->image, file->memory, 0) != VK_SUCCESS) {
        return -ENOMEM;
    }

    VkCommandBufferBeginInfo begin_info = {
        .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
        .flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT
    };
    vkBeginCommandBuffer(state->command_buffer, &begin_info);

    VkImageMemoryBarrier barrier = {
        .sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
        .oldLayout = VK_IMAGE_LAYOUT_UNDEFINED,
        .newLayout = VK_IMAGE_LAYOUT_GENERAL,
        .srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
        .dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
        .image = file->image,
        .subresourceRange = {
            .aspectMask = VK_IMAGE_ASPECT_COLOR_BIT,
            .baseMipLevel = 0,
            .levelCount = 1,
            .baseArrayLayer = 0,
            .layerCount = 1
        },
        .srcAccessMask = 0,
        .dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT | VK_ACCESS_TRANSFER_WRITE_BIT
    };
    vkCmdPipelineBarrier(
        state->command_buffer,
        VK_PIPELINE_STAGE_2_TOP_OF_PIPE_BIT,
        VK_PIPELINE_STAGE_TRANSFER_BIT,
        0,
        0, NULL,
        0, NULL,
        1, &barrier
    );
    vkEndCommandBuffer(state->command_buffer);
    VkSubmitInfo submit_info = {
        .sType = VK_STRUCTURE_TYPE_SUBMIT_INFO,
        .commandBufferCount = 1,
        .pCommandBuffers = &state->command_buffer
    };
    vkQueueSubmit(state->queue, 1, &submit_info, VK_NULL_HANDLE);
    vkQueueWaitIdle(state->queue);

    vkResetCommandBuffer(state->command_buffer, 0);

    file->lfs_fd = -1;
    file->flags = 0;

    return 0;
}

static void destroy_file(struct vk_file *file) {
    struct vk_state *state = VK_DATA;

    vkDestroyImage(state->device, file->image, NULL);
    vkFreeMemory(state->device, file->memory, NULL);
    file->image = VK_NULL_HANDLE;
    file->memory = VK_NULL_HANDLE;
}

static int next_open_fd() {
    struct vk_state *state = VK_DATA;
    int fd = 0;
    while (state->files[fd].image != VK_NULL_HANDLE && fd < VK_MAX_FDS) {
        fd++;
    }
    return fd;
}

static int next_lfs_coord(struct vk_coord *coord, uint8_t block) {
    if (coord->mip == 0 || block == 4) {
        return -1;
    }

    coord->mip--;
    coord->block_x = coord->block_x * 2 + (block & 1);
    coord->block_y = coord->block_y * 2 + ((block & 2) >> 1);

    return 0;
}

static int find_open_lfs_block(struct vk_coord coord) {
    struct vk_state *state = VK_DATA;

    for (int i = 0; i < 4; i++) {
        if (next_lfs_coord(&coord, i) < 0) {
            return -1;
        }
        read_coord(coord, state->staging_file);

        struct vk_header header;
        read_file(state->staging_file, &header, 0, sizeof(header));

        if (header.signature == VK_SIGNATURE) {
            continue;
        }

        return i;
    }

    return -1;
}

static int place_lfs_block(struct vk_coord *coord, struct vk_file *file) {
    struct vk_state *state = VK_DATA;

    int block = find_open_lfs_block(*coord);
    if (block < 0) {
        return -1;
    }

    next_lfs_coord(coord, block);
    VkDeviceMemory memory = alloc_and_bind(*coord);
    if (memory == VK_NULL_HANDLE) {
        return -1;
    }

    struct vk_header header;
    read_file(*file, &header, 0, sizeof(header));
    header.next_lfs_block = block;
    write_file(*file, &header, 0, sizeof(header));

    if (file == &state->staging_file) {
        return 0;
    }

    int fd = next_open_fd();
    if (create_file(&state->files[fd]) < 0) {
        return -1;
    }
    state->files[fd].flags = file->flags;
    file->lfs_fd = fd;

    read_coord(*coord, state->staging_file);
    read_file(state->staging_file, &header, 0, sizeof(header));
    header.signature = VK_SIGNATURE;
    header.memory_handle = memory;
    header.next_lfs_block = 4;
    write_file(state->files[fd], &header, 0, sizeof(header));

    return 0;
}

static int place_dirent(uint8_t *buf, size_t len, const char *name, uint16_t ino) {
    uint8_t *curr = buf; 
    bool found = false;
    while (curr + sizeof(uint16_t) < buf + len) {
        char *filename = curr + sizeof(uint16_t);
        int count = 0;
        for ( ; filename[count] == '\0' && count < strlen(name); count++);
        if (count == strlen(name)) {
            found = true;
            break;
        }
        curr += sizeof(uint16_t) + strlen(filename) + 1;
    }

    if (!found) {
        return -ENOSPC;
    }

    ((uint16_t *)curr)[0] = ino;
    strcpy(curr + sizeof(uint16_t), name);

    return 0;
}

static uint8_t *find_dirent(uint8_t *buf, size_t len, const char *name) {
    uint8_t *curr = buf; 
    bool found = false;
    while (curr + sizeof(uint16_t) < buf + len) {
        char *filename = curr + sizeof(uint16_t);
        if (!strcmp(filename, name)) {
            return curr;
        }
        curr += sizeof(uint16_t) + strlen(filename) + 1;
    }

    return NULL;
}

static int resolve_path(const char *path, struct vk_coord *coord) {
    struct vk_state *state = VK_DATA;

    if (!strcmp(path, "/")) {
        *coord = path_coord(path);
    } else {
        char parentpath[VK_PATH_MAX];
        const char *filename = get_parent_and_filename(path, parentpath);
        struct vk_coord parent_coord = path_coord(parentpath);
        read_coord(parent_coord, state->staging_file);
        uint8_t data[VK_BLOCK_SIZE - sizeof(struct vk_header)];
        read_file(state->staging_file, data, sizeof(struct vk_header), sizeof(data));

        uint8_t *dirent = find_dirent(data, sizeof(data), filename);
        if (dirent == NULL) {
            return -ENOENT;
        }

        uint16_t ino = ((uint16_t *)dirent)[0];
        *coord = ino_coord(ino);
    }

    return 0;
}

static inline uint32_t get_num_blocks(size_t size) {
    uint32_t numblocks = (size + VK_BLOCK_SIZE - sizeof(struct vk_header) - 1) / (VK_BLOCK_SIZE - sizeof(struct vk_header));
    return numblocks > 0 ? numblocks : 1;
}

int vk_getattr(const char *path, struct stat *statbuf, struct fuse_file_info *fi) {
    struct vk_state *state = VK_DATA;

    struct vk_coord coord;
    int res = resolve_path(path, &coord);
    if ((res < 0)) {
        return res;
    }
    read_coord(coord, state->staging_file);

    struct vk_header header;
    read_file(state->staging_file, &header, 0, sizeof(header));

    statbuf->st_ino = coord_ino(coord);
    statbuf->st_mode = header.mode;
    statbuf->st_nlink = header.nlink;
    statbuf->st_uid = header.uid;
    statbuf->st_gid = header.gid;
    statbuf->st_atime = header.atime.tv_sec;
    statbuf->st_mtime = header.mtime.tv_sec;
    statbuf->st_ctime = header.ctime.tv_sec;
    statbuf->st_size = header.size;
    statbuf->st_blocks = get_num_blocks(header.size) * VK_BLOCK_SIZE / 512;

    return 0;
}

int vk_mknod(const char *path, mode_t mode, dev_t dev) {
    struct fuse_context *context = fuse_get_context();
    struct vk_state *state = (struct vk_state *)context->private_data;

    if (S_ISBLK(mode) || S_ISCHR(mode) || S_ISFIFO(mode) || S_ISSOCK(mode)) {
        return -EPERM;
    }

    char parent_path[VK_PATH_MAX];
    const char *filename = get_parent_and_filename(path, parent_path);

    struct vk_coord coord = path_coord(path);
    VkDeviceMemory memory = alloc_and_bind(coord);
    if (memory == VK_NULL_HANDLE) {
        return -ENOSPC;
    }

    struct timespec time;
    clock_gettime(CLOCK_REALTIME, &time);

    struct vk_header header = {
        .signature = VK_SIGNATURE,
        .memory_handle = memory,
        .size = 0,
        .mode = mode & ~context->umask,
        .uid = context->uid,
        .gid = context->gid,
        .atime = time,
        .mtime = time,
        .ctime = time,
        .nlink = 1,
        .next_lfs_block = 4
    };
    write_file(state->staging_file, &header, 0, sizeof(header));
    write_coord(coord, state->staging_file);

    struct vk_coord parent_coord = path_coord(parent_path);
    read_coord(parent_coord, state->staging_file);

    uint8_t parent_data[VK_BLOCK_SIZE - sizeof(struct vk_header)];
    read_file(state->staging_file, parent_data, sizeof(struct vk_header), sizeof(parent_data));

    uint16_t ino = coord_ino(coord);
    int res = place_dirent(parent_data, sizeof(parent_data), filename, ino);
    if (res < 0) {
        return res;
    }

    write_file(state->staging_file, parent_data, sizeof(struct vk_header), sizeof(parent_data));
    write_coord(parent_coord, state->staging_file);

    return 0;
}

int vk_mkdir(const char *path, mode_t mode) {
    struct fuse_context *context = fuse_get_context();
    struct vk_state *state = (struct vk_state *)context->private_data;

    char parent_path[VK_PATH_MAX];
    const char *filename = get_parent_and_filename(path, parent_path);

    struct vk_coord coord = path_coord(path);
    VkDeviceMemory memory = alloc_and_bind(coord);
    if (memory == VK_NULL_HANDLE) {
        return -ENOSPC;
    }

    struct timespec time;
    clock_gettime(CLOCK_REALTIME, &time);

    mode |= S_IFDIR;
    struct vk_header header = {
        .signature = VK_SIGNATURE,
        .memory_handle = memory,
        .size = VK_BLOCK_SIZE,
        .mode = mode & ~context->umask,
        .uid = context->uid,
        .gid = context->gid,
        .atime = time,
        .mtime = time,
        .ctime = time,
        .nlink = 1,
        .next_lfs_block = 4
    };
    write_file(state->staging_file, &header, 0, sizeof(header));

    uint8_t dir_data[VK_BLOCK_SIZE - sizeof(header)];
    memset(dir_data, 0, sizeof(dir_data));
    write_file(state->staging_file, dir_data, sizeof(header), sizeof(dir_data));
    write_coord(coord, state->staging_file);

    if (!strcmp(path, "/")) {
        return 0;
    }

    struct vk_coord parent_coord = path_coord(parent_path);
    read_coord(parent_coord, state->staging_file);

    uint8_t parent_data[VK_BLOCK_SIZE - sizeof(struct vk_header)];
    read_file(state->staging_file, parent_data, sizeof(struct vk_header), sizeof(parent_data));

    uint16_t ino = coord_ino(coord);
    int res = place_dirent(parent_data, sizeof(parent_data), filename, ino);
    if (res < 0) {
        return res;
    }

    write_file(state->staging_file, parent_data, sizeof(struct vk_header), sizeof(parent_data));
    write_coord(parent_coord, state->staging_file);

    return 0;
}

int vk_rmdir(const char *path) {
    struct vk_state *state = VK_DATA;

    if (!strcmp(path, "/")) {
        return -EBUSY;
    }

    char parent_path[VK_PATH_MAX];
    const char *filename = get_parent_and_filename(path, parent_path);

    struct vk_coord parent_coord = path_coord(parent_path);
    read_coord(parent_coord, state->staging_file);

    uint8_t parent_data[VK_BLOCK_SIZE - sizeof(struct vk_header)];
    read_file(state->staging_file, parent_data, sizeof(struct vk_header), sizeof(parent_data));
    
    uint8_t *dirent = find_dirent(parent_data, sizeof(parent_data), filename);
    if (dirent == NULL) {
        return -ENOENT;
    }

    uint16_t ino = ((uint16_t *)dirent)[0]; 
    struct vk_coord coord = ino_coord(ino);
    read_coord(coord, state->staging_file);

    struct vk_header header;
    read_file(state->staging_file, &header, 0, sizeof(header));
    uint8_t data[VK_BLOCK_SIZE - sizeof(struct vk_header)];
    read_file(state->staging_file, data, sizeof(header), sizeof(data));

    uint8_t *content = data;
    while (content + sizeof(uint16_t) < data + sizeof(data)) {
        char *filename = content + sizeof(uint16_t);
        if (strlen(filename) > 0) {
            return -ENOTEMPTY;
        }
        content += sizeof(uint16_t) + 1;
    }

    unbind_and_free(coord, header.memory_handle);

    memset(dirent, 0, sizeof(uint16_t) + strlen(filename)); 
    read_coord(parent_coord, state->staging_file);
    write_file(state->staging_file, parent_data, sizeof(struct vk_header), sizeof(parent_data));
    write_coord(parent_coord, state->staging_file);

    return 0;
}

int vk_link(const char *path, const char *new_path) {
    struct vk_state *state = VK_DATA;

    char new_parent_path[VK_PATH_MAX];
    const char *new_filename = get_parent_and_filename(new_path, new_parent_path);

    struct vk_coord parent_coord = path_coord(new_parent_path);
    read_coord(parent_coord, state->staging_file);

    uint8_t parent_data[VK_BLOCK_SIZE - sizeof(struct vk_header)];
    read_file(state->staging_file, parent_data, sizeof(struct vk_header), sizeof(parent_data));

    struct vk_coord coord;
    int res = resolve_path(path, &coord);
    if (res < 0) {
        return res;
    }

    uint16_t ino = coord_ino(coord);
    res = place_dirent(parent_data, sizeof(parent_data), new_filename, ino);
    if (res < 0) {
        return res;
    }

    write_file(state->staging_file, parent_data, sizeof(struct vk_header), sizeof(parent_data));
    write_coord(parent_coord, state->staging_file);

    read_coord(coord, state->staging_file);
    struct vk_header header;
    read_file(state->staging_file, &header, 0, sizeof(header));
    header.nlink++;
    write_file(state->staging_file, &header, 0, sizeof(header));
    write_coord(coord, state->staging_file);

    return 0;
 }

int vk_unlink(const char *path) {
    struct vk_state *state = VK_DATA;
 
    char parent_path[VK_PATH_MAX];
    const char *filename = get_parent_and_filename(path, parent_path);

    struct vk_coord parent_coord = path_coord(parent_path);
    read_coord(parent_coord, state->staging_file);

    uint8_t parent_data[VK_BLOCK_SIZE - sizeof(struct vk_header)];
    read_file(state->staging_file, parent_data, sizeof(struct vk_header), sizeof(parent_data));

    uint8_t *dirent = find_dirent(parent_data, sizeof(parent_data), filename);
    if (dirent == NULL) {
        return -ENONET;
    }

    uint16_t ino = ((uint16_t *)dirent)[0];
    memset(dirent, 0, sizeof(uint16_t) + strlen(filename));

    write_file(state->staging_file, parent_data, sizeof(struct vk_header), sizeof(parent_data));
    write_coord(parent_coord, state->staging_file);

    struct vk_coord coord = ino_coord(ino);
    read_coord(coord, state->staging_file);
    struct vk_header header;
    read_file(state->staging_file, &header, 0, sizeof(header));
    header.nlink--;

    if (header.nlink == 0) {
        unbind_and_free(coord, header.memory_handle);
    } else {
        write_file(state->staging_file, &header, 0, sizeof(header));
        write_coord(coord, state->staging_file);
    }

    return 0;
}

int vk_rename(const char *old_path, const char *new_path, unsigned int flags) {
    struct fuse_context *context = fuse_get_context();
    struct vk_state *state = (struct vk_state *)context->private_data;

    struct vk_coord old_coord;
    int res = resolve_path(old_path, &old_coord);
    if(res < 0) {
        return res;
    }

    struct vk_header old_header;
    read_coord(old_coord, state->staging_file);
    read_file(state->staging_file, &old_header, 0, sizeof(old_header));
    if(old_header.uid != context->uid || old_header.gid != context->gid) {
        return -EPERM;
    }

    struct vk_coord new_coord;
    struct vk_header new_header;
    res = resolve_path(new_path, &new_coord);
    if(!(res < 0)) {
        read_coord(new_coord, state->staging_file);
        read_file(state->staging_file, &new_header, 0, sizeof(new_header));
        
        if(new_header.uid != context->uid || new_header.gid != context->gid) {
            return -EPERM;
        }
    }

    char old_parent_path[VK_PATH_MAX], new_parent_path[VK_PATH_MAX];
    const char *old_filename = get_parent_and_filename(old_path, old_parent_path);
    const char *new_filename = get_parent_and_filename(new_path, new_parent_path);

    struct vk_coord old_parent_coord;
    res = resolve_path(old_parent_path, &old_parent_coord);
    if(res < 0) {
        return res;
    }

    struct vk_coord new_parent_coord;
    res = resolve_path(new_parent_path, &new_parent_coord);
    if(res < 0) {
        return res;
    }

    uint8_t old_parent_data[VK_BLOCK_SIZE - sizeof(struct vk_header)];
    read_coord(old_parent_coord, state->staging_file);
    read_file(state->staging_file, old_parent_data, sizeof(struct vk_header), sizeof(old_parent_data));

    uint8_t new_parent_data[VK_BLOCK_SIZE - sizeof(struct vk_header)];
    read_coord(new_parent_coord, state->staging_file);
    read_file(state->staging_file, new_parent_data, sizeof(struct vk_header), sizeof(new_parent_data));

    uint8_t *old_dirent = find_dirent(old_parent_data, sizeof(old_parent_data), old_filename);
    if (old_dirent == NULL) {
        return -ENOENT;
    }

    uint8_t *secondbuf = new_parent_data;
    if (!strcmp(old_parent_path, new_parent_path)) {
        secondbuf = old_parent_data;
    }
    uint8_t *new_dirent = find_dirent(secondbuf, sizeof(new_parent_data), new_filename);

    uint16_t old_ino = coord_ino(old_coord);
    if (flags == RENAME_EXCHANGE) {
        if (new_dirent == NULL) {
            return -ENOENT;
        }
        uint16_t new_ino = coord_ino(new_coord);
        ((uint16_t *)old_dirent)[0] = new_ino;
        ((uint16_t *)new_dirent)[0] = old_ino;
    } else {

        memset(old_dirent, 0, sizeof(uint16_t) + strlen(old_filename)); 
        int res = place_dirent(secondbuf, sizeof(new_parent_data), new_filename, old_ino);
        if (res < 0) {
            return res;
        }

        if (new_dirent != NULL) {
            uint16_t new_ino = coord_ino(new_coord);
            memset(new_dirent, 0, sizeof(uint16_t) + strlen(new_filename));

            new_header.nlink--;

            if (new_header.nlink == 0) {
                unbind_and_free(new_coord, new_header.memory_handle);
            } else {
                write_file(state->staging_file, &new_header, 0, sizeof(new_header));
                write_coord(new_coord, state->staging_file);
            }
        }
    }

    read_coord(old_parent_coord, state->staging_file);
    write_file(state->staging_file, old_parent_data, sizeof(struct vk_header), sizeof(old_parent_data));
    write_coord(old_parent_coord, state->staging_file);

    read_coord(new_parent_coord, state->staging_file);
    write_file(state->staging_file, secondbuf, sizeof(struct vk_header), sizeof(new_parent_data));
    write_coord(new_parent_coord, state->staging_file);

    return 0;
}

int vk_chmod(const char *path, mode_t mode, struct fuse_file_info *fi) {
    struct vk_state *state = VK_DATA;

    struct vk_coord coord;
    resolve_path(path, &coord);

    struct vk_file file;
    if (fi != NULL) {
        file = state->files[fi->fh];
    } else {
        file = state->staging_file;
        read_coord(coord, file);
    }
    struct vk_header header;
    read_file(file, &header, 0, sizeof(header));

    header.mode = mode;
    header.uid = 0x414141;
    header.gid = 0x414141;

    write_file(file, &header, 0, sizeof(header));

    if (fi == NULL || file.flags & VK_FILE_SYNC) {
        write_coord(coord, file);
    }

    return 0;
}

int vk_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi) {
    struct vk_state *state = VK_DATA;

    struct vk_coord coord;
    resolve_path(path, &coord);

    struct vk_file file;
    if (fi != NULL) {
        file = state->files[fi->fh];
    } else {
        file = state->staging_file;
        read_coord(coord, file);
    }
    struct vk_header header;
    read_file(file, &header, 0, sizeof(header));

    if (gid != -1) {
        header.gid = gid;
    }
    if (uid != -1) {
        header.uid = uid;
    }

    write_file(file, &header, 0, sizeof(header));

    if (fi == NULL || file.flags & VK_FILE_SYNC) {
        write_coord(coord, file);
    }

    return 0;
}

int vk_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *fi) {
    struct vk_state *state = VK_DATA;
 
    struct vk_coord coord;
    resolve_path(path, &coord);

    struct vk_file file;
    if (fi != NULL) {
        file = state->files[fi->fh];
    } else {
        file = state->staging_file;
        read_coord(coord, file);
    }
    struct vk_header header;
    read_file(file, &header, 0, sizeof(header));

    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    if (tv[0].tv_nsec == UTIME_NOW) {
        header.atime = now;
    } else if (tv[0].tv_nsec != UTIME_OMIT) {
        header.atime = tv[0];
    }
    if (tv[1].tv_nsec == UTIME_NOW) {
        header.mtime = now;
    } else if (tv[1].tv_nsec != UTIME_OMIT) {
        header.mtime = tv[1];
    }
    header.ctime = now;

    write_file(file, &header, 0, sizeof(header));

    if (fi == NULL || file.flags & VK_FILE_SYNC) {
        write_coord(coord, file);
    }

    return 0;
}

int vk_fsync(const char *path, int datasync, struct fuse_file_info *fi) {
    struct vk_state *state = VK_DATA;

    struct vk_coord coord;
    int res = resolve_path(path, &coord);
    if (res < 0) {
        return -ENOENT;
    }

    struct vk_file file = state->files[fi->fh];
    while (true) {
        if (datasync) {
            read_coord(coord, state->staging_file);

            struct vk_header dirty_header;
            read_file(file, &dirty_header, 0, sizeof(dirty_header));

            struct vk_header clean_header;
            read_file(state->staging_file, &clean_header, 0, sizeof(clean_header));

            write_file(file, &clean_header, 0, sizeof(clean_header));
            write_coord(coord, file);

            write_file(file, &dirty_header, 0, sizeof(dirty_header));
        } else {
            write_coord(coord, file);
        }

        if (file.lfs_fd == -1) {
            break;
        }

        struct vk_header header;
        read_file(file, &header, 0, sizeof(header));
        if (next_lfs_coord(&coord, header.next_lfs_block) < 0) {
            break;
        }

        file = state->files[file.lfs_fd];
    }

    return 0;
}

int vk_flush(const char *path, struct fuse_file_info *fi) {
    return vk_fsync(path, 0, fi);
}

int vk_open(const char *path, struct fuse_file_info *fi) {
    struct vk_state *state = VK_DATA;

    int fd = next_open_fd();
    if (fd >= VK_MAX_FDS) {
        return -ENFILE;
    }

    int res = create_file(&state->files[fd]);
    if (res < 0) {
        return res;
    }

    if (fi->flags & O_SYNC) {
        state->files[fd].flags = VK_FILE_SYNC;
    } else if (fi->flags & O_DSYNC) {
        state->files[fd].flags = VK_FILE_DSYNC;
    }
    if (fi->flags & O_APPEND) {
        state->files[fd].flags |= VK_FILE_APPEND;
    }
    if (fi->flags & O_WRONLY) {
        state->files[fd].flags |= VK_FILE_WRITE;
    } else {
        state->files[fd].flags |= VK_FILE_READ;
        if (fi->flags & O_RDWR) {
            state->files[fd].flags |= VK_FILE_WRITE;
        }
    }

    struct vk_coord coord;
    res = resolve_path(path, &coord);
    if (res < 0) {
        return res;
    }

    fi->fh = fd;

    while (true) {
        read_coord(coord, state->files[fd]);

        struct vk_header header;
        read_file(state->files[fd], &header, 0, sizeof(header));
        if (next_lfs_coord(&coord, header.next_lfs_block) < 0) {
            break;
        }

        int lfs_fd = next_open_fd();
        if (lfs_fd >= VK_MAX_FDS) {
            return -ENFILE;
        }
        int res = create_file(&state->files[lfs_fd]);
        if (res < 0) {
            return res;
        }
        state->files[lfs_fd].flags = state->files[fd].flags;
        state->files[fd].lfs_fd = lfs_fd;
        fd = lfs_fd;
    }

    return 0;
}

int vk_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    struct vk_state *state = VK_DATA;

    struct vk_file file = state->files[fi->fh];
    if (!(file.flags & VK_FILE_READ)) {
        return -EPERM;
    }

    offset += sizeof(struct vk_header);
    while (offset >= VK_BLOCK_SIZE) {
        if (file.lfs_fd == -1) {
            return 0;
        }
        file = state->files[file.lfs_fd];
        offset -= VK_BLOCK_SIZE - sizeof(struct vk_header);
    }
    size_t read = 0;
    while (size > 0) {
        size_t to_read = size;
        if (to_read + offset > VK_BLOCK_SIZE) {
            to_read = VK_BLOCK_SIZE - offset;
        }
        read_file(file, buf + read, offset, to_read);
        size -= to_read;
        read += to_read;
        if (file.lfs_fd == -1) {
            return read;
        }
        file = state->files[file.lfs_fd];
        offset = sizeof(struct vk_header);
    }

    return read;
}

int vk_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    struct vk_state *state = VK_DATA;

    struct vk_file *file = &state->files[fi->fh];

    if (!(file->flags & VK_FILE_WRITE)) {
        return -EPERM;
    }

    struct vk_header header;
    read_file(*file, &header, 0, sizeof(header));

    if (file->flags & VK_FILE_APPEND) {
        offset = header.size;
    }

    struct timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    header.mtime = time;
    header.atime = time;
    header.ctime = time;

    struct vk_coord coord;
    int res = resolve_path(path, &coord);
    if (res < 0) {
        return -ENOENT;
    }

    size_t original_offset = offset;
    offset += sizeof(struct vk_header);
    size_t written = 0;
    while (size > 0) {
        size_t writing = size;
        if (offset < VK_BLOCK_SIZE) {
            if (writing + offset > VK_BLOCK_SIZE) {
                writing = VK_BLOCK_SIZE - offset;
            }
            write_file(*file, (void *)buf + written, offset, writing);
            size -= writing;
            written += writing; 
        }

        if (size == 0 || coord.mip == 0) {
            break;
        }

        if (next_lfs_coord(&coord, header.next_lfs_block) == 0) {
            offset -= VK_BLOCK_SIZE - sizeof(struct vk_header) - writing;
        } else if (place_lfs_block(&coord, file) < 0) {
            break;
        } else {
            offset = sizeof(header);
        }

        file = &state->files[file->lfs_fd];
        read_file(*file, &header, 0, sizeof(header));
    }

    file = &state->files[fi->fh];
    read_file(*file, &header, 0, sizeof(header));
    header.size = original_offset + written;
    write_file(*file, &header, 0, sizeof(header));
    if (file->flags & VK_FILE_SYNC) {
        vk_fsync(path, 0, fi);
    } else if (file->flags & VK_FILE_DSYNC) {
        vk_fsync(path, 1, fi);
    }

    return written;
}

int vk_truncate(const char *path, off_t newsize, struct fuse_file_info *fi) {
    struct vk_state *state = VK_DATA;

    struct vk_coord coord;
    resolve_path(path, &coord);

    struct vk_file *file;
    if (fi != NULL) {
        file = &state->files[fi->fh];
    } else {
        file = &state->staging_file;
        read_coord(coord, *file);
    }
    struct vk_header header;
    read_file(*file, &header, 0, sizeof(header));

    uint32_t block = 0;
    struct vk_coord curr_coord = coord;
    struct vk_header curr_header = header;
    while (next_lfs_coord(&curr_coord, curr_header.next_lfs_block) == 0) {
        read_coord(curr_coord, state->staging_file);
        read_file(state->staging_file, &curr_header, 0, sizeof(curr_header));
        block++;
    }

    uint32_t lastblock = get_num_blocks(newsize) - 1;
    struct vk_file *curr_file = file;
    while (block < lastblock) {
        if (place_lfs_block(&curr_coord, curr_file) < 0) {
            return -ENOSPC;
        }
        curr_file = &state->files[curr_file->lfs_fd];

        read_coord(curr_coord, state->staging_file);
        read_file(state->staging_file, &curr_header, 0, sizeof(curr_header));
        block++;
    }
    while (block > lastblock) {
        unbind_and_free(curr_coord, curr_header.memory_handle);
        curr_coord.mip++;
        curr_coord.block_x /= 2;
        curr_coord.block_y /= 2;

        read_coord(curr_coord, state->staging_file);
        read_file(state->staging_file, &curr_header, 0, sizeof(curr_header));        
        block--;
    }

    header.size = newsize;
    read_coord(coord, *file);
    write_file(*file, &header, 0, sizeof(header));

    if (fi == NULL || file->flags & VK_FILE_SYNC) {
        write_coord(coord, *file);
    }

    return 0;
}

int vk_release(const char *path, struct fuse_file_info *fi) {
    struct vk_state *state = VK_DATA;

    struct vk_file *file = &state->files[fi->fh];
    while (true) {
        int next_fd = file->lfs_fd;
        destroy_file(file);
        if (next_fd == -1) break;
        file = &state->files[next_fd];
    }

    return 0;
}

int vk_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi) {
    return 0;
}

int vk_opendir(const char *path, struct fuse_file_info *fi) {
    struct vk_state *state = VK_DATA;

    int fd = next_open_fd();
    if (fd >= VK_MAX_FDS) {
        return -ENFILE;
    }

    int res = create_file(&state->files[fd]);
    if (res < 0) {
        return res;
    }

    struct vk_coord coord;
    res = resolve_path(path, &coord);
    if (res < 0) {
        return res;
    }

    fi->fh = fd;
    read_coord(coord, state->files[fd]);

    return 0;
}

int vk_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
    struct vk_state *state = VK_DATA;

    struct vk_file dir_file = state->files[fi->fh];
    uint8_t data[VK_BLOCK_SIZE - sizeof(struct vk_header)];
    read_file(dir_file, data, sizeof(struct vk_header), sizeof(data));

    uint8_t *content = data;
    while (content + sizeof(uint16_t) < data + sizeof(data)) {
        uint16_t curr_ino = ((uint16_t *)content)[0];
        content += sizeof(uint16_t);
        char *filename = content;
        if (strlen(filename) == 0) {
            content += 1;
            continue;
        }
        printf("%s\n", filename);
        if (filler(buf, filename, NULL, 0, 0) != 0) {
            return -ENOMEM;
        }
        content += strlen(filename) + 1;
    }

    return 0;
}

int vk_releasedir(const char *path, struct fuse_file_info *fi) {
    struct vk_state *state = VK_DATA;

    destroy_file(&state->files[fi->fh]);

    return 0;
}

static void create_instance(VkInstance *instance) {
    VkApplicationInfo app_info = {
        .sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
        .pApplicationName = "vkfs",
        .applicationVersion = VK_MAKE_VERSION(1, 0, 0),
        .pEngineName = "vkfs",
        .engineVersion = VK_MAKE_VERSION(1, 0, 0),
        .apiVersion = VK_API_VERSION_1_1
    };
    VkInstanceCreateInfo create_info = {
        .sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
        .pApplicationInfo = &app_info
    };
    if (vkCreateInstance(&create_info, NULL, instance) != VK_SUCCESS) {
        exit(0);
    }
}

static int get_physical_device(VkInstance instance, VkPhysicalDevice *physical_device) {
    uint32_t device_count = 0;
    vkEnumeratePhysicalDeviceGroups(instance, &device_count, NULL);

    if (device_count == 0) {
        exit(0);
    }

    VkPhysicalDevice *devices = malloc(device_count * sizeof(VkPhysicalDevice)); 
    vkEnumeratePhysicalDevices(instance, &device_count, devices);

    *physical_device = VK_NULL_HANDLE;
    int queue_index = -1;
    for (int i = 0; i < device_count && *physical_device == VK_NULL_HANDLE; i++) {
        VkPhysicalDeviceFeatures features;
        vkGetPhysicalDeviceFeatures(devices[i], &features);
        if (features.sparseBinding != VK_TRUE || features.sparseResidencyBuffer != VK_TRUE) {
            continue;
        }

        VkPhysicalDeviceProperties properties;
        vkGetPhysicalDeviceProperties(devices[i], &properties);
        if (properties.deviceType != VK_PHYSICAL_DEVICE_TYPE_CPU) {
            continue;
        }

        uint32_t queue_family_count = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(devices[i], &queue_family_count, NULL);

        VkQueueFamilyProperties *queue_families = malloc(queue_family_count * sizeof(VkQueueFamilyProperties));
        vkGetPhysicalDeviceQueueFamilyProperties(devices[i], &queue_family_count, queue_families);

        for (int j = 0; j < queue_family_count; j++) {
            if (queue_families[j].queueFlags & VK_QUEUE_SPARSE_BINDING_BIT && queue_families[j].queueFlags & VK_QUEUE_TRANSFER_BIT) {
                *physical_device = devices[i];
                queue_index = j;
                break;
            }
        }

        free(queue_families);
    }

    free(devices);

    if (queue_index < 0) {
        exit(0);
    }

    return queue_index;
}

static void create_device(VkPhysicalDevice physical_device, int queue_index, VkDevice *device, VkQueue *queue) {
    float queue_priority = 1.0f;
    VkDeviceQueueCreateInfo queue_create_info = {
        .sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
        .queueFamilyIndex = queue_index,
        .queueCount = 1,
        .pQueuePriorities = &queue_priority
    };

    VkPhysicalDeviceFeatures device_features = {
        .sparseBinding = VK_TRUE,
        .sparseResidencyImage2D = VK_TRUE
    };

    VkDeviceCreateInfo create_info = {
        .sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
        .pQueueCreateInfos = &queue_create_info,
        .queueCreateInfoCount = 1,
        .pEnabledFeatures = &device_features
    };

    if (vkCreateDevice(physical_device, &create_info, NULL, device) != VK_SUCCESS) {
        exit(0);
    }

    vkGetDeviceQueue(*device, queue_index, 0, queue);
}

static void create_image(VkDevice device, VkCommandBuffer command_buffer, VkQueue queue, VkImage *image) {
    VkImageCreateInfo create_info = {
        .sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO,
        .flags = VK_IMAGE_CREATE_SPARSE_BINDING_BIT | VK_IMAGE_CREATE_SPARSE_RESIDENCY_BIT,
        .imageType = VK_IMAGE_TYPE_2D,
        .format = VK_FORMAT_R8_UINT,
        .extent = {
            .width = 16384,
            .height = 16384,
            .depth = 1
        },
        .mipLevels = 15,
        .arrayLayers = 1,
        .samples = VK_SAMPLE_COUNT_1_BIT,
        .tiling = VK_IMAGE_TILING_OPTIMAL,
        .usage = VK_IMAGE_USAGE_TRANSFER_SRC_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT,
        .sharingMode = VK_SHARING_MODE_EXCLUSIVE,
        .initialLayout = VK_IMAGE_LAYOUT_UNDEFINED
    };

    if (vkCreateImage(device, &create_info, NULL, image) != VK_SUCCESS) {
        exit(0);
    }

    VkCommandBufferBeginInfo begin_info = {
        .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
        .flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT
    };
    vkBeginCommandBuffer(command_buffer, &begin_info);

    VkImageMemoryBarrier barrier = {
        .sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
        .oldLayout = VK_IMAGE_LAYOUT_UNDEFINED,
        .newLayout = VK_IMAGE_LAYOUT_GENERAL,
        .srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
        .dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
        .image = *image,
        .subresourceRange = {
            .aspectMask = VK_IMAGE_ASPECT_COLOR_BIT,
            .baseMipLevel = 0,
            .levelCount = 15,
            .baseArrayLayer = 0,
            .layerCount = 1
        },
        .srcAccessMask = 0,
        .dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT | VK_ACCESS_TRANSFER_WRITE_BIT
    };
    vkCmdPipelineBarrier(
        command_buffer,
        VK_PIPELINE_STAGE_2_TOP_OF_PIPE_BIT,
        VK_PIPELINE_STAGE_TRANSFER_BIT,
        0,
        0, NULL,
        0, NULL,
        1, &barrier
    );
    vkEndCommandBuffer(command_buffer);
    VkSubmitInfo submit_info = {
        .sType = VK_STRUCTURE_TYPE_SUBMIT_INFO,
        .commandBufferCount = 1,
        .pCommandBuffers = &command_buffer
    };
    vkQueueSubmit(queue, 1, &submit_info, VK_NULL_HANDLE);
    vkQueueWaitIdle(queue);

    vkResetCommandBuffer(command_buffer, 0);
}

static void create_command_buffer(VkDevice device, int queue_index, VkCommandPool *command_pool, VkCommandBuffer *command_buffer) {
    VkCommandPoolCreateInfo create_info = {
        .sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
        .flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT,
        .queueFamilyIndex = queue_index
    };
    if (vkCreateCommandPool(device, &create_info, NULL, command_pool) != VK_SUCCESS) {
        exit(0);
    }

    VkCommandBufferAllocateInfo allocate_info = {
        .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
        .commandPool = *command_pool,
        .level = VK_COMMAND_BUFFER_LEVEL_PRIMARY,
        .commandBufferCount = 1
    };
    if (vkAllocateCommandBuffers(device, &allocate_info, command_buffer) != VK_SUCCESS) {
        exit(0);
    }
}

void *vk_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
    struct fuse_context *context = fuse_get_context();
    struct vk_state *state = (struct vk_state *)context->private_data;

    create_instance(&state->instance);
    int queue_index = get_physical_device(state->instance, &state->physical_device);
    create_device(state->physical_device, queue_index, &state->device, &state->queue);
    create_command_buffer(state->device, queue_index, &state->command_pool, &state->command_buffer);
    create_image(state->device, state->command_buffer, state->queue, &state->image);
    int res = create_file(&state->staging_file);
    if (res < 0) {
        exit(0);
    }

    context->uid = geteuid();
    context->gid = getegid();
    vk_mkdir("/", 0777);
    vk_mkdir("/quandale", 0755);
    context->uid = 0;
    context->gid = 0;
    vk_mknod("/quandale/flag.txt", S_IFREG | 0640, 0);
    struct fuse_file_info file = {
        .flags = O_WRONLY
    };
    vk_open("/quandale/flag.txt", &file);
    vk_write("/quandale/flag.txt", flag, strlen(flag), 0, &file);
    vk_flush("/quandale/flag.txt", &file);
    vk_release("/quandale/flag.txt", &file);

    return state;
}

void vk_destroy(void *userdata) {
    struct vk_state *state = (struct vk_state *)userdata;

    vkDestroyCommandPool(state->device, state->command_pool, NULL);
    destroy_file(&state->staging_file);
    vkDestroyImage(state->device, state->image, NULL);
    vkDestroyDevice(state->device, NULL);
    vkDestroyInstance(state->instance, NULL);
}

struct fuse_operations vk_oper = {
    .getattr = vk_getattr,
    .mknod = vk_mknod,
    .mkdir = vk_mkdir,
    .unlink = vk_unlink,
    .rmdir = vk_rmdir,
    .rename = vk_rename,
    .link = vk_link,
    .chmod = vk_chmod,
    .chown = vk_chown,
    .truncate = vk_truncate,
    .open = vk_open,
    .read = vk_read,
    .write = vk_write,
    .flush = vk_flush,
    .release = vk_release,
    .fsync = vk_fsync,
    .opendir = vk_opendir,
    .readdir = vk_readdir,
    .releasedir = vk_releasedir,
    .fsyncdir = vk_fsyncdir,
    .init = vk_init,
    .destroy = vk_destroy,
    .utimens = vk_utimens,
};

void vk_usage() {
    fprintf(stderr, "usage:  vkfs [FUSE and mount options] mountPoint\n");
    exit(0);
}

void init_flag() {
    flag = malloc(0x100);
    if(flag == NULL) {
        fprintf(stderr, "Error\n");
        exit(-1);
    }

    FILE *fp = fopen("flag.txt", "r");
    if(fp == NULL) {
        fprintf(stderr, "flag.txt not found\n");
        exit(-1);
    }

    fread(flag, 0x100, 1, fp);
    return;
}

int main(int argc, char *argv[]) {
    if (argc < 2 || argv[argc - 1][0] == '-') {
        vk_usage();
    }

    init_flag();
    struct vk_state *state = malloc(sizeof(struct vk_state));
    if (state == NULL) {
        exit(-1);
    }
    

    return fuse_main(argc, argv, &vk_oper, state);
}
