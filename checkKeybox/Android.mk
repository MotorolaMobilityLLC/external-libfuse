LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

ifeq ($(strip $(BOARD_TEE_CONFIG)), trusty)

#LOCAL_32_BIT_ONLY := true

LOCAL_SRC_FILES := sprd_check_keybox.c

LOCAL_MODULE := libcheckkeybox
LOCAL_MODULE_TAGS := optional
LOCAL_PROPRIETARY_MODULE := true
LOCAL_MODULE_RELATIVE_PATH := npidevice

LOCAL_C_INCLUDES:= \
	$(TOP)/vendor/sprd/proprietories-source/engpc/sprd_fts_inc \
	$(LOCAL_PATH)/../

LOCAL_SHARED_LIBRARIES:= liblog libc libcutils libteeproduction

ifeq ($(strip $(TARGET_ARCH)),arm64)
CHECKKEYBOX_NPI_FILE := /vendor/lib64/npidevice/libcheckkeybox.so
SYMLINK := $(TARGET_OUT_VENDOR)/lib64/libcheckkeybox.so

LOCAL_POST_INSTALL_CMD := $(hide) \
	mkdir -p $(TARGET_OUT_VENDOR)/lib/npidevice; \
	rm -rf $(SYMLINK) ;\
	ln -sf $(CHECKKEYBOX_NPI_FILE) $(SYMLINK);
else
ifeq ($(strip $(TARGET_ARCH)),x86_64)
CHECKKEYBOX_NPI_FILE := /vendor/lib64/npidevice/libcheckkeybox.so
SYMLINK := $(TARGET_OUT_VENDOR)/lib64/libcheckkeybox.so

LOCAL_POST_INSTALL_CMD := $(hide) \
	mkdir -p $(TARGET_OUT_VENDOR)/lib/npidevice; \
	rm -rf $(SYMLINK) ;\
	ln -sf $(CHECKKEYBOX_NPI_FILE) $(SYMLINK);
else
CHECKKEYBOX_NPI_FILE := /vendor/lib/npidevice/libcheckkeybox.so
SYMLINK := $(TARGET_OUT_VENDOR)/lib/libcheckkeybox.so

LOCAL_POST_INSTALL_CMD := $(hide) \
	mkdir -p $(TARGET_OUT_VENDOR)/lib/npidevice; \
	rm -rf $(SYMLINK) ;\
	ln -sf $(CHECKKEYBOX_NPI_FILE) $(SYMLINK);
endif
endif

include $(BUILD_SHARED_LIBRARY)
endif
