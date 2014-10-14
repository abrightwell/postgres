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

extern void RemoveDirectoryById(Oid dir_id);
extern void CreateDirectory(CreateDirectoryStmt *stmt);
extern void AlterDirectory(AlterDirectoryStmt *stmt);
extern Oid AlterDirectoryOwner(const char *alias, Oid new_owner);
extern void GrantDirectory(GrantDirectoryStmt *stmt);

extern char *get_directory_alias(Oid dir_id);
extern Oid get_directory_oid(const char *alias, bool missing_ok);
extern Oid get_directory_owner(Oid dir_id);
extern Oid get_directory_oid_by_path(const char *path);

// extern Oid rename_directory(RenameStmt *stmt);

#endif   /* DIRECTORY_H */