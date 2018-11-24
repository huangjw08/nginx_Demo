cmake_minimum_required(VERSION 3.10)
project(nginx_monitor C)

set(CMAKE_C_STANDARD 11)

#通过查看nginx-1.1x.x目录下的objs/Makefile 可以得出这些INCS目录
include_directories(/home/hjw/lib/nginx-1.12.2/src/core /home/hjw/lib/nginx-1.12.2/src/event
        /home/hjw/lib/nginx-1.12.2/src/event/modules
        /home/hjw/lib/nginx-1.12.2/src/os/unix /home/hjw/lib/nginx-1.12.2/objs
        /home/hjw/lib/nginx-1.12.2/src/http /home/hjw/lib/nginx-1.12.2/src/http/modules)


add_library(nginx_mytest mytest/ngx_http_mytest_module.c mytest/ngx_http_mytest_module.h)
add_library(nginx_monitor monitor/ngx_http_monitor_module.c)

add_executable(main main.c )

target_link_libraries(nginx_mytest pthread crypt pcre z dl)
target_link_libraries(nginx_monitor pthread crypt pcre z dl)