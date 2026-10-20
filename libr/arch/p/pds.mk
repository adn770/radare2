OBJ_PDS=p/pds/plugin.o
OBJ_PDS+=p/pds/pds.o

STATIC_OBJ+=$(OBJ_PDS)
TARGET_PDS=arch_pds.$(EXT_SO)

ifeq ($(WITHPIC),1)
ALL_TARGETS+=$(TARGET_PDS)

$(TARGET_PDS): $(OBJ_PDS)
	$(CC) $(call libname,arch_pds) $(LDFLAGS) \
		$(CFLAGS) -o arch_pds.$(EXT_SO) $(OBJ_PDS)
endif
