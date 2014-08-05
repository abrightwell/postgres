/*-------------------------------------------------------------------------
 *
 * permission.h
 *		prototypes for permission.c.
 *
 * Portions Copyright (c) 1996-2014, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/commands/permission.h
 *
 *-------------------------------------------------------------------------
 */

#ifndef PERMISSION_H
#define PERMISSION_H

#include "catalog/pg_permission.h"
#include "nodes/parsenodes.h"

extern void RemovePermissionById(Oid permission_id);

extern void GrantPermission(GrantPermissionStmt *stmt);

extern bool HasPermission(Oid role_id, Permission permission);

#endif   /* PERMISSION_H */

