include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_oob_shaken

mod_LTLIBRARIES = mod_oob_shaken.la
mod_oob_shaken_la_SOURCES  = mod_oob_shaken.c
mod_oob_shaken_la_CFLAGS   = $(AM_CFLAGS) $(AM_MOD_OOB_SHAKEN_CXXFLAGS)
mod_oob_shaken_la_LIBADD   = $(switch_builddir)/libfreeswitch.la -lstirshaken
mod_oob_shaken_la_LDFLAGS  = -avoid-version -module -no-undefined -shared
