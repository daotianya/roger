
libs: wawo

libs_clean: wawo_clean

wawo:
	@echo "building chili begin"
	make -C$(LIB_WAWO_MAKEFILE_PATH) build=$(PRJ_CONFIG)
	@echo "building wawo finish"
	@echo 

wawo_clean:
	@echo "make -C$(LIB_WAWO_MAKEFILE_PATH) clean build=$(PRJ_CONFIG)"
	make -C$(LIB_WAWO_MAKEFILE_PATH) clean build=$(PRJ_CONFIG)