/*-------------------------------------------------------------------------
 *
 * permission.c
 *		Commands for manipulating permissions.
 *
 * Portions Copyright (c) 1996-2014, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California*
 *
 * src/backend/commands/permission.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "access/htup_details.h"
#include "access/sysattr.h"
#include "catalog/dependency.h"
#include "catalog/indexing.h"
#include "catalog/pg_authid.h"
#include "commands/permission.h"
#include "nodes/pg_list.h"
#include "parser/parse_node.h"
#include "utils/acl.h"
#include "utils/fmgroids.h"
#include "utils/rel.h"
#include "utils/syscache.h"

static void AddPermissionToRole(const char *role_name, Oid role_id,
			List *permissions);
static void RemovePermissionFromRole(const char *role_name, Oid role_id,
			List *permissions);

void
RemovePermissionById(Oid permission_id)
{
	Relation		catalog;
	ScanKeyData		skey;
	SysScanDesc		sscan;
	HeapTuple		tuple;

	/* Find permission. */
	catalog = heap_open(PermissionRelationId, RowExclusiveLock);

	ScanKeyInit(&skey,
				ObjectIdAttributeNumber,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(permission_id));

	sscan = systable_beginscan(catalog, PermissionRelationId, true,
							   NULL, 1,&skey);

	tuple = systable_getnext(sscan);

	/* If permission exists, then delete it. */
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "could not find tuple for permission %u", permission_id);

	simple_heap_delete(catalog, &tuple->t_self);

	/* Invalidate Cache */
	// CacheInvalidateRelcache(catalog);

	/* Clean up */
	heap_close(catalog, RowExclusiveLock);
}

/*
 * Grant/Revoke permissions to/from roles.
 */
void
GrantPermission(GrantPermissionStmt *stmt)
{
	Oid				role_id;
	char		   *role_name;
	ListCell	   *item;

	foreach(item, stmt->roles)
	{
		role_name = strVal(lfirst(item));
		role_id = get_role_oid(role_name, false);

		if (stmt->is_grant)
			AddPermissionToRole(role_name, role_id, stmt->permissions);
		else
			RemovePermissionFromRole(role_name, role_id, stmt->permissions);
	}
}

/*
 * HasPermission
 *    check if a user/role has a permission, true if role permission, otherwise
 *    false.
 *
 * role_id - the role to check.
 * permission - the permission to check.
 */
bool
HasPermission(Oid role_id, Permission permission)
{
	bool		result = false;
	HeapTuple	tuple;

	tuple = SearchSysCache2(PERMROLEIDPERMID, ObjectIdGetDatum(role_id),
							Int32GetDatum(permission));

	if (HeapTupleIsValid(tuple))
	{
		result = true;
		ReleaseSysCache(tuple);
	}

	return result;
}

/*
 * AddPermissionToRole - Add given permissions to the specified role
 *
 * role_name: name of role to add permissions to, only used for error messages.
 * role_id: OID of the role to add permissions to.
 * permissions: list of permissions to add to the role.
 *
 */
static void
AddPermissionToRole(const char *role_name, Oid role_id, List *permissions)
{
	Relation		pg_permission_rel;
	Oid				permission_id;
	ScanKeyData		skeys[2];
	SysScanDesc		sscan;
	HeapTuple		tuple;
	Datum			new_record[Natts_pg_permission];
	bool			new_record_nulls[Natts_pg_permission];
	ObjectAddress	role_dependency;
	ObjectAddress	permission_dependee;
	ListCell	   *item;

	pg_permission_rel = heap_open(PermissionRelationId, RowExclusiveLock);

	foreach(item, permissions)
	{
		int permission = lfirst_int(item);

		/* Determine if permission is already set. */
		ScanKeyInit(&skeys[0],
					Anum_pg_permission_permroleid,
					BTEqualStrategyNumber, F_OIDEQ,
					ObjectIdGetDatum(role_id));

		ScanKeyInit(&skeys[1],
					Anum_pg_permission_permpermission,
					BTEqualStrategyNumber, F_INT4EQ,
					Int32GetDatum(permission));

		sscan = systable_beginscan(pg_permission_rel, PermissionRoleIdPermIndexId,
								   true, NULL, 2, skeys);

		tuple = systable_getnext(sscan);

		if (!HeapTupleIsValid(tuple))
		{
			memset(new_record, 0, sizeof(new_record));
			memset(new_record_nulls, 0, sizeof(new_record_nulls));

			new_record[Anum_pg_permission_permroleid - 1]
					= ObjectIdGetDatum(role_id);
			new_record[Anum_pg_permission_permpermission - 1]
					= Int32GetDatum(permission);

			tuple = heap_form_tuple(RelationGetDescr(pg_permission_rel),
									new_record, new_record_nulls);

			permission_id = simple_heap_insert(pg_permission_rel, tuple);

			CatalogUpdateIndexes(pg_permission_rel, tuple);

			/* Record dependencies on role */
			role_dependency.classId = AuthIdRelationId;
			role_dependency.objectId = role_id;
			role_dependency.objectSubId = 0;

			permission_dependee.classId = PermissionRelationId;
			permission_dependee.objectId = permission_id;
			permission_dependee.objectSubId = 0;

			recordDependencyOn(&permission_dependee, &role_dependency, DEPENDENCY_AUTO);

			heap_freetuple(tuple);
		}
		else
			elog(NOTICE, "Permission already set for %s.", role_name);

		systable_endscan(sscan);
	}

	/* Clean up. */
	heap_close(pg_permission_rel, RowExclusiveLock);
}

/*
 * RemovePermissionFromRole - Remove given permissions from the specified role
 *
 * role_name: name of role to add permissions to, only used for error messages.
 * role_id: OID of the role to add permissions to.
 * permissions: list of permissions to add to the role.
 *
 */
static void
RemovePermissionFromRole(const char *role_name, Oid role_id, List *permissions)
{
	Relation		pg_permission_rel;
	ScanKeyData		skeys[2];
	SysScanDesc		sscan;
	HeapTuple		tuple;
	ListCell	   *item;

	pg_permission_rel = heap_open(PermissionRelationId, RowExclusiveLock);

	foreach(item, permissions)
	{
		int permission = lfirst_int(item);

		/* Determine if permission is already set. */
		ScanKeyInit(&skeys[0],
					Anum_pg_permission_permroleid,
					BTEqualStrategyNumber, F_OIDEQ,
					ObjectIdGetDatum(role_id));

		ScanKeyInit(&skeys[1],
					Anum_pg_permission_permpermission,
					BTEqualStrategyNumber, F_INT4EQ,
					Int32GetDatum(permission));

		sscan = systable_beginscan(pg_permission_rel, PermissionRoleIdPermIndexId,
								   true, NULL, 2, skeys);

		tuple = systable_getnext(sscan);

		/* If the permission exists, remove it. */
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "Permission is not set for %s.", role_name);

		simple_heap_delete(pg_permission_rel, &tuple->t_self);

		CatalogUpdateIndexes(pg_permission_rel, tuple);

		systable_endscan(sscan);
	}

	/* Clean up. */
	heap_close(pg_permission_rel, RowExclusiveLock);
}

