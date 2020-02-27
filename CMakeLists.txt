#minimal cmake version
CMAKE_MINIMUM_REQUIRED ( VERSION 2.8 )
 
#Project Name
PROJECT ( "websocket_sample" )
SET ( PROJECT_VERSION_MAJOR 0 )
SET ( PROJECT_VERSION_MINOR 1 )

#Configuration
SET ( CMAKE_BUILD_TYPE Debug )
SET ( CMAKE_VERBOSE_MAKEFILE true )

SET ( OUTPUT_ELF
      "${CMAKE_PROJECT_NAME}-${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.out"
    )
SET ( SRC_FILES
#minimal-ws-server-echo.c
#      protocol_lws_minimal_server_echo.c
      main.c
    )

#common compiler
SET ( CMAKE_C_COMPILER "gcc" )

#common header files
INCLUDE_DIRECTORIES ( include /home/bear/libwebsockets/include )

#common compile options
ADD_COMPILE_OPTIONS ( -g -Wall )
#SET ( CMAKE_EXE_LINKER_FLAGS "-static -Wl, --gc-sections" )

#common link library
LINK_LIBRARIES ( pthread websockets )

#common link library directories
LINK_DIRECTORIES ( /home/bear/libwebsockets/lib )

#debug compile option
SET ( CMAKE_C_FLAGS_DEBUG "-DDEBUG -DC_FLAGS" )
SET ( CMAKE_EXE_LINKER_FLAGS_DEBUG "-DDEBUG -DLINKER_FLAGS" )

#output directory
SET ( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BUILD_TYPE} )
SET ( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BUILD_TYPE}/lib )
SET ( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BUILD_TYPE}/bin )
 
ADD_EXECUTABLE( ${OUTPUT_ELF} ${SRC_FILES} )




