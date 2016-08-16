APP_TARGET_NAME					:= tcell

APP_PATH						:= ../../../tcell
APP_SRC_PATH					:= $(APP_PATH)/src
APP_INCLUDE_PATH				:= $(APP_PATH)/src

APP_PROJECTS_PATH				:= $(APP_PATH)/projects
APP_BUILD_BIN_PATH				:= $(APP_PROJECTS_PATH)/build
APP_BUILD_TARGET_PATH			:= $(APP_BUILD_BIN_PATH)/$(PRJ_PLATFORM)_$(PRJ_CONFIG)
APP_BUILD_BIN_OBJECTS_PATH		:= $(APP_BUILD_TARGET_PATH)/objects/$(APP_TARGET_NAME)
APP_BUILD_TARGET				:= $(APP_BUILD_TARGET_PATH)/target/$(APP_TARGET_NAME)

APP_RESOURCE_PATH				:= $(APP_PATH)/resource
APP_RESOURCE_TARGET_PATH		:= $(APP_BUILD_TARGET_PATH)/target/resource

ifndef $(O_EXT)
	O_EXT=o
endif

APP_INCLUDES					:= \
	$(foreach path, $(APP_INCLUDE_PATH),-I"$(path)" )

INCLUDES					:= $(INCLUDES) $(APP_INCLUDES)


APP_ALL_CPP_FILES := \
	$(foreach path, $(APP_SRC_PATH), $(shell find $(path) -name *.cpp -not -name ".*") )

APP_ALL_O_FILES	:= $(APP_ALL_CPP_FILES:.cpp=.$(O_EXT))
APP_ALL_O_FILES 	:= $(foreach path, $(APP_ALL_O_FILES), $(subst $(APP_SRC_PATH)/,,$(path)))
APP_ALL_O_FILES	:= $(addprefix $(APP_BUILD_BIN_OBJECTS_PATH)/,$(APP_ALL_O_FILES) )

#custome for codeblock
#CC_MISC := $(CC_MISC) -finput-charset=GBK -fexec-charset=GBK

$(APP_TARGET_NAME): $(APP_TARGET_NAME)_precc $(APP_TARGET_NAME)_copy_res $(APP_BUILD_TARGET)

$(APP_TARGET_NAME)_precc : 
	@echo '---------------------'
	@echo 'CXX' $(CXX)
	@echo ''
	@echo 'APP_BUILD_TARGET' $(APP_BUILD_TARGET)
	@echo \*\* compiling -- precc ...
	@echo 'LINK_LIBS' $(LINK_LIBS)
	@echo ''
	@echo 'DEFINES' $(DEFINES)
	@echo ''
	@echo 'INCLUDES' $(INCLUDES)	
	@echo ''	
	@echo 'CC_MISC' $(CC_MISC)
	
	@echo '----------------------'

$(APP_BUILD_TARGET): $(APP_ALL_O_FILES)
	@if [ ! -d $(@D) ] ; then \
		mkdir -p $(@D) ; \
	fi
	
	@echo "---"
	@echo \*\* assembling...
	@echo $(CXX) $^ -o $@ $(LINK_LIBS)
	@$(CXX) $^ -o $@ $(LINK_LIBS) 
	@echo "---"

	
$(APP_BUILD_BIN_OBJECTS_PATH)/%.o : $(APP_SRC_PATH)/%.cpp
	@if [ ! -d $(@D) ] ; then \
		mkdir -p $(@D) ; \
	fi
	
	@echo 'compiling $$<F ' $(<F)
	@echo '$$@ '$@
	@echo ''
	@echo $(CXX) $(CC_MISC) $(DEFINES) $(INCLUDES) -c $< -o $@
	@$(CXX) $(CC_MISC) $(DEFINES) $(INCLUDES) -c $< -o $@
	
$(APP_TARGET_NAME)_copy_res:
	@if [ ! -d $(APP_RESOURCE_TARGET_PATH) ] ; then \
		mkdir -p $(APP_RESOURCE_TARGET_PATH) ; \
	fi
	
#	rsync -av $(APP_RESOURCE_PATH)/* $(APP_RESOURCE_TARGET_PATH)
	
$(APP_TARGET_NAME)_clean:
	rm -rf $(APP_BUILD_TARGET_PATH) 

$(APP_TARGET_NAME)_run: $(APP_TARGET_NAME)
	$(APP_BUILD_TARGET) --working-dir=./working_dir --discover-concurrency=1 --query-times=1
	
$(APP_TARGET_NAME)_debug:
	gdb $(APP_BUILD_TARGET)

$(APP_TARGET_NAME)_dump:
	@echo 'APP_INCLUDES' $(APP_INCLUDES)
	@echo ''
	@echo 'APP_ALL_CPP_FILES' $(APP_ALL_CPP_FILES)
	@echo ''
	@echo 'APP_ALL_O_FILES' $(APP_ALL_O_FILES)
	@echo ''
	@echo 'APP_BUILD_TARGET' $(APP_BUILD_TARGET)
	@echo 'BUILD_OBJECTS_TARGET' $(BUILD_OBJECTS_TARGET)	
