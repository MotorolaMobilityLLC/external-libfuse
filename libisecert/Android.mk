LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

ifeq ($(strip $(BOARD_ISE_CERT_CONFIG)), true)

$(warning "build libisecert for Commercial Cryptography Testing Center")

LOCAL_MODULE := libisecert

LOCAL_C_INCLUDES:= \
	$(TOP)/vendor/sprd/proprietories-source/engpc/sprd_fts_inc \
	$(LOCAL_PATH)

LOCAL_SRC_FILES := sprd_ise_cert.c

LOCAL_SHARED_LIBRARIES:= liblog

LOCAL_MODULE_TAGS := optional

LOCAL_PROPRIETARY_MODULE := true

LOCAL_MODULE_RELATIVE_PATH := npidevice

include $(BUILD_SHARED_LIBRARY)

endif

