/*-------------------------------------------------------------------------
 *
 * user.h
 *	  Commands for manipulating roles (formerly called users).
 *
 *
 * src/include/commands/user.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef USER_H
#define USER_H

#include "nodes/parsenodes.h"


/* Hook to check passwords in CreateRole() and AlterRole() */
#define PASSWORD_TYPE_PLAINTEXT		0
#define PASSWORD_TYPE_MD5			1

#define ROLE_ATTR_SUPERUSER			0
#define ROLE_ATTR_CREATE_ROLE		1
#define ROLE_ATTR_CREATE_DB			2
#define ROLE_ATTR_INHERIT			3
#define ROLE_ATTR_REPLICATION		4
#define ROLE_ATTR_LOGIN				5
#define ROLE_ATTR_CATUPDATE			6
#define ROLE_ATTR_BYPASSRLS			7

typedef void (*check_password_hook_type) (const char *username, const char *password, int password_type, Datum validuntil_time, bool validuntil_null);

extern PGDLLIMPORT check_password_hook_type check_password_hook;

extern Oid	CreateRole(CreateRoleStmt *stmt);
extern Oid	AlterRole(AlterRoleStmt *stmt);
extern Oid	AlterRoleSet(AlterRoleSetStmt *stmt);
extern Oid	AlterRoleCapability(AlterRoleCapabilityStmt *stmt);
extern void DropRole(DropRoleStmt *stmt);
extern void GrantRole(GrantRoleStmt *stmt);
extern Oid	RenameRole(const char *oldname, const char *newname);
extern void DropOwnedObjects(DropOwnedStmt *stmt);
extern void ReassignOwnedObjects(ReassignOwnedStmt *stmt);
extern List *roleNamesToIds(List *memberNames);

#endif   /* USER_H */
