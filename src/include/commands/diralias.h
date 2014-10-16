/*-------------------------------------------------------------------------
 *
 * directory.h
 *	  prototypes for directory.c.
 *
 *
 * Portions Copyright (c) 1996-2014, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/commands/directory.h
 *
 *-------------------------------------------------------------------------
 */

#ifndef DIRECTORY_H
#define DIRECTORY_H

#include "nodes/parsenodes.h"

extern void RemoveDirAliasById(Oid dir_id);
extern void CreateDirAlias(CreateDirAliasStmt *stmt);
extern void AlterDirAlias(AlterDirAliasStmt *stmt);

extern char *get_diralias_name(Oid dir_id);
extern Oid get_diralias_oid(const char *name, bool missing_ok);
extern Oid get_diralias_owner(Oid dir_id);
extern Oid get_diralias_oid_by_path(const char *path);

#endif   /* DIRECTORY_H */