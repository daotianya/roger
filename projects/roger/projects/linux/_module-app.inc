APP_TARGET_NAME_SERVER			:= roger_server
APP_TARGET_NAME_CLIENT			:= roger_client

APP_PATH						:= ../..
APP_SRC_PATH					:= $(APP_PATH)/src/roger
APP_INCLUDE_PATH				:= $(APP_PATH)/src/roger

APP_PROJECTS_PATH				:= $(APP_PATH)/projects
APP_BUILD_BIN_PATH				:= $(APP_PROJECTS_PATH)/build
APP_BUILD_TARGET_PATH			:= $(APP_BUILD_BIN_PATH)/$(PRJ_ARCH)

SERVER_BIN_OBJECTS_PATH			:= $(APP_BUILD_TARGET_PATH)/objects/roger_server
SERVER_TARGET					:= $(APP_BUILD_TARGET_PATH)/roger_server.$(PRJ_ARCH)_$(PRJ_BUILD)

CLIENT_BIN_OBJECTS_PATH			:= $(APP_BUILD_TARGET_PATH)/objects/roger_client
CLIENT_TARGET					:= $(APP_BUILD_TARGET_PATH)/roger_client.$(PRJ_ARCH)_$(PRJ_BUILD)


ifndef $(O_EXT)
	O_EXT=o
endif

APP_INCLUDES					:= \
	$(foreach path, $(APP_INCLUDE_PATH),-I"$(path)" )

INCLUDES					:= $(INCLUDES) $(APP_INCLUDES)


APP_ALL_CPP_FILES_SERVER :=\
	$(foreach path, $(APP_SRC_PATH), $(shell find $(path) -name *.cpp -not -name ".*" -not -name "client.cpp") )

APP_ALL_CPP_FILES_CLIENT :=\
	$(foreach path, $(APP_SRC_PATH), $(shell find $(path) -name *.cpp -not -name ".*" -not -name "server.cpp") )

APP_ALL_O_FILES_SERVER	:= $(APP_ALL_CPP_FILES_SERVER:.cpp=.$(O_EXT))
APP_ALL_O_FILES_SERVER 	:= $(foreach path, $(APP_ALL_O_FILES_SERVER), $(subst $(APP_SRC_PATH)/,,$(path)))
APP_ALL_O_FILES_SERVER	:= $(addprefix $(SERVER_BIN_OBJECTS_PATH)/,$(APP_ALL_O_FILES_SERVER) )
	
APP_ALL_O_FILES_CLIENT	:= $(APP_ALL_CPP_FILES_CLIENT:.cpp=.$(O_EXT))
APP_ALL_O_FILES_CLIENT 	:= $(foreach path, $(APP_ALL_O_FILES_CLIENT), $(subst $(APP_SRC_PATH)/,,$(path)))
APP_ALL_O_FILES_CLIENT	:= $(addprefix $(CLIENT_BIN_OBJECTS_PATH)/,$(APP_ALL_O_FILES_CLIENT) )

#custome for codeblock
#CC_MISC := $(CC_MISC) -finput-charset=GBK -fexec-charset=GBK

CC_MISC := $(CC_MISC) -rdynamic
roger_server: wawo $(SERVER_TARGET)
roger_client: wawo $(CLIENT_TARGET)

$(SERVER_TARGET): $(APP_ALL_O_FILES_SERVER)
	@if [ ! -d $(@D) ] ; then \
		mkdir -p $(@D) ; \
	fi
	
	@echo "---"
	@echo \*\* assembling $(SERVER_TARGET)...
	@echo $(CXX) $^ -o $@ $(LINK_LIBS)
	@$(CXX) -rdynamic $^ -o $@ $(LINK_LIBS) 
	@echo "---"
	
$(CLIENT_TARGET): $(APP_ALL_O_FILES_CLIENT)
	@if [ ! -d $(@D) ] ; then \
		mkdir -p $(@D) ; \
	fi
	
	@echo "---"
	@echo \*\* assembling $(CLIENT_TARGET)...
	@echo $(CXX) $^ -o $@ $(LINK_LIBS)
	@$(CXX) $^ -o $@ $(LINK_LIBS)
	
	@cp -f $(APP_PATH)/config/proxy.pac $(APP_BUILD_TARGET_PATH)
	@echo "---"
	


$(SERVER_BIN_OBJECTS_PATH)/%.o : $(APP_SRC_PATH)/%.cpp
	@if [ ! -d $(@D) ] ; then \
		mkdir -p $(@D) ; \
	fi
	
	@echo 'compiling $$<F ' $(<F)
	@echo '$$@ '$@
	@echo ''
	@echo $(CXX) $(CC_MISC) $(DEFINES) $(INCLUDES) -c $< -o $@
	@$(CXX) $(CC_MISC) $(DEFINES) $(INCLUDES) -c $< -o $@
	
$(CLIENT_BIN_OBJECTS_PATH)/%.o : $(APP_SRC_PATH)/%.cpp
	@if [ ! -d $(@D) ] ; then \
		mkdir -p $(@D) ; \
	fi
	
	@echo 'compiling $$<F ' $(<F)
	@echo '$$@ '$@
	@echo ''
	@echo $(CXX) $(CC_MISC) $(DEFINES) $(INCLUDES) -c $< -o $@
	@$(CXX) $(CC_MISC) $(DEFINES) $(INCLUDES) -c $< -o $@
	
	
roger_server_clean:
	rm -rf $(SERVER_BIN_OBJECTS_PATH)/*
	rm -rf $(SERVER_TARGET)
	
roger_client_clean:
	rm -rf $(CLIENT_BIN_OBJECTS_PATH)/*
	rm -rf $(CLIENT_TARGET)