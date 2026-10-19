OBJ_USSE=p/usse/plugin.o
OBJ_USSE+=p/usse/usse.o

STATIC_OBJ+=$(OBJ_USSE)
TARGET_USSE=arch_usse.$(EXT_SO)

ifeq ($(WITHPIC),1)
ALL_TARGETS+=$(TARGET_USSE)

$(TARGET_USSE): $(OBJ_USSE)
	$(CC) $(call libname,arch_usse) $(LDFLAGS) \
		$(CFLAGS) -o arch_usse.$(EXT_SO) $(OBJ_USSE)
endif
