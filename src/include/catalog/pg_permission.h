/*
 * pg_permission.h
 *   definition of the system catalog for role permissions (pg_permission)
 *
 * Portions Copyright (c) 1996-2012, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 */
#ifndef PG_PERMISSION_H
#define PG_PERMISSION_H

#include "catalog/genbki.h"

/* ----------------
 *		pg_permission definition.  cpp turns this into
 *		typedef struct FormData_pg_permission
 * ----------------
 */
#define PermissionRelationId	6000

CATALOG(pg_permission,6000)
{
	Oid		permroleid;
	int32	permpermission;
} FormData_pg_permission;

/* ----------------
 *		Form_pg_permission corresponds to a pointer to a tuple with
 *		the format of pg_permission relation.
 * ----------------
 */
typedef FormData_pg_permission *Form_pg_permission;

/*
 * ----------------
 * 		compiler constants for pg_permission
 * ----------------
 */
#define Natts_pg_permission						2
#define Anum_pg_permission_permroleid			1
#define Anum_pg_permission_permpermission		2

typedef enum Permission
{
	PERM_INVALID = -1,			/* Invalid Permission */
	PERM_CREATE_DATABASE = 0,	/* CREATE DATABASE */
	PERM_CREATE_ROLE,			/* CREATE ROLE */
	PERM_PROCSIGNAL,			/* PROCSIGNAL */
	PERM_BACKUP,				/* BACKUP */
	PERM_LOG_ROTATE				/* LOG ROTATE */
} Permission;

#endif   /* PG_PERMISSION_H */

