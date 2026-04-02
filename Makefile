TARGET := iphone:clang:latest:14.0
ARCHS := arm64
SDKVERSION := 14.5

include $(THEOS)/makefiles/common.mk

TWEAK_NAME := PentestTweak

# v3 Triple Attack — ZERO external dependencies
PentestTweak_FILES := Tweak.xm
PentestTweak_FRAMEWORKS := Foundation
PentestTweak_CFLAGS := -fobjc-arc -Wno-deprecated-declarations

include $(THEOS_MAKE_PATH)/tweak.mk

after-stage::
	$(ECHO_NOTHING)echo "[v3] Stripping debug symbols..."$(END_ECHO)
	$(ECHO_NOTHING)$(STRIP) -x $(THEOS_STAGING_DIR)/.theos/obj/$(TWEAK_NAME).dylib$(END_ECHO)
