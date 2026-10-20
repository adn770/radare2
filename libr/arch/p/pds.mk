OBJ_PDS=p/pds/plugin.o
OBJ_PDS+=p/pds/pds.o
OBJ_PDS+=p/pds/pds_forms.o
# The PDS forms run on the USSE form engine, built once in the usse plugin;
# a standalone arch_pds links it in.
OBJ_PDS_ENGINE=p/usse/usse_form.o p/usse/usse.o

STATIC_OBJ+=$(OBJ_PDS)
TARGET_PDS=arch_pds.$(EXT_SO)

ifeq ($(WITHPIC),1)
ALL_TARGETS+=$(TARGET_PDS)

$(TARGET_PDS): $(OBJ_PDS) $(OBJ_PDS_ENGINE)
	$(CC) $(call libname,arch_pds) $(LDFLAGS) \
		$(CFLAGS) -o arch_pds.$(EXT_SO) $(OBJ_PDS) $(OBJ_PDS_ENGINE)
endif
