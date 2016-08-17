CURRENT_DIR 	:= $(shell pwd)
TARGET_NAME 	:= $(target)
PRJ_ARCH 		:= x86_64
PRJ_BUILD		:= release


ifdef arch
	PRJ_ARCH := $(arch)
endif

ifdef build
	PRJ_BUILD := $(build)
endif



DEFINES := $(DEFINES)
CC_MISC := -std=c++11

ifeq ($(PRJ_BUILD),debug)
	DEFINES := $(DEFINES) DEBUG
	CC_MISC:=$(CC_MISC) -g -Wall -fexceptions -O0
else
	DEFINES := $(DEFINES) RELEASE
	CC_MISC := $(CC_MISC) -fexpensive-optimizations -O3
endif

ifeq ($(PRJ_ARCH),x86_64)
	CC_MISC := $(CC_MISC) -m64
else
	CC_MISC := $(CC_MISC) -m32
endif

LIBPREFIX 	= lib
LIBEXT		= a

include _libs-path.inc


DEFINES :=\
	$(foreach define,$(DEFINES), -D$(define))
INCLUDES:= \
	$(foreach include,$(LIB_INCLUDE_PATH_ALL_LIBS), -I"$(include)") \
	$(foreach include,$(APP_INCLUDE_PATH), -I"$(include)")

	
LINK_LIBS := -lrt -lpthread -ldl -Xlinker "-(" $(LIB_LINK_LIBS_ALL_LIBS) -Xlinker "-)"


include _module-libs.inc
include _module-app.inc

dumpinfo:
	@echo 'CC' $(CC)
	@echo ''
	@echo 'CXX' $(CXX)
	@echo ''
	@echo 'CC_MISC' $(CC_MISC)
	@echo ''
	@echo 'DEFINES' $(DEFINES)
	@echo ''
	@echo 'INCLUDES' $(INCLUDES)
	@echo ''
	@echo 'LIB_LINK_LIBS_ALL_LIBS' $(LIB_LINK_LIBS_ALL_LIBS)
	@echo ''
	@echo 'LIBS_NOTDIR_NAME' $(LIBS_NOTDIR_NAME)
	@echo ''
	@echo 'LINK_LIBS' $(LINK_LIBS)
	@echo ''
	@echo 'APP_BUILD_BIN_OBJECTS_PATH' $(APP_BUILD_BIN_OBJECTS_PATH)
	@echo ''
	@echo 'APP_BUILD_TARGET' $(APP_BUILD_TARGET)
	@echo ''
	@echo 'APP_ALL_O_FILES' $(APP_ALL_O_FILES)
	