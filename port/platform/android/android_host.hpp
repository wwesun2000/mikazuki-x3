#pragma once
#include <string>
namespace kx3::platform::android {
void mount_disc_fd(int fd);
void unmount_disc();
std::string mounted_disc_path();
}
