MODULES = ip_blocker
EXTENSION = ip_blocker
DATA = ip_blocker--1.0.sql

# This part is the "magic" that finds your Ubuntu headers
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)