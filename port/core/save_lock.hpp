#pragma once
#include <filesystem>
#include <system_error>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace kx3 {
class SaveWriterLock {
public:
    SaveWriterLock(const std::filesystem::path& path,const char* operation){
#ifdef _WIN32
        handle_=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
        if(handle_==INVALID_HANDLE_VALUE)throw std::system_error(GetLastError(),std::system_category(),operation);
#else
        fd_=open(path.c_str(),O_CREAT|O_RDWR,0600);
        if(fd_<0)throw std::system_error(errno,std::generic_category(),operation);
        if(flock(fd_,LOCK_EX|LOCK_NB)!=0){const auto error=errno;close(fd_);throw std::system_error(error,std::generic_category(),operation);}
#endif
    }
    ~SaveWriterLock(){
#ifdef _WIN32
        CloseHandle(handle_);
#else
        close(fd_);
#endif
    }
    SaveWriterLock(const SaveWriterLock&)=delete;
    SaveWriterLock& operator=(const SaveWriterLock&)=delete;
private:
#ifdef _WIN32
    HANDLE handle_;
#else
    int fd_;
#endif
};
}
