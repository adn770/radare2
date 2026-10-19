OBJ_USSEPSEUDO+=$(LIBR)/arch/p/usse/pseudo.o

TARGET_USSEPSEUDO=parse_usse_pseudo.${EXT_SO}
STATIC_OBJ+=${OBJ_USSEPSEUDO}
ifeq ($(CC),cccl)
LIBDEPS=-L../../util -llibr_util
LIBDEPS+=-L../../flag -llibr_flag
else
LIBDEPS=-L../../util -lr_util
LIBDEPS+=-L../../flag -lr_flag
endif

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_USSEPSEUDO}
${TARGET_USSEPSEUDO}: ${OBJ_USSEPSEUDO}
	${CC} $(call libname,parse_usse_pseudo) ${LIBDEPS} $(LDFLAGS) \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_USSEPSEUDO} ${OBJ_USSEPSEUDO}
endif
