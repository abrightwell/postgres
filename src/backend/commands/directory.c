/*-------------------------------------------------------------------------
 *
 * directory.c
 *	  Commands for manipulating directories.
 *
 * Portions Copyright (c) 1996-2014, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/backend/commands/directory.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/htup_details.h"
#include "access/sysattr.h"
#include "catalog/dependency.h"
#include "catalog/indexing.h"
#include "catalog/objectaccess.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_directory.h"
#include "commands/directory.h"
#include "commands/user.h"
#include "miscadmin.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/rel.h"
#include "utils/syscache.h"

static AclMode string_to_permission(const char *permission);
static Acl *merge_acl_with_grant(Acl *old_acl, List *grantees, bool is_grant,
								AclMode permissions, Oid grantor, Oid owner);

/*
 * RemoveDirectoryById
 *   remove a directory by its OID.  If a directory does not exist with the
 *   provided oid, then an error is raised.
 *
 * dir_id - the oid of the directory.
 */
void
RemoveDirectoryById(Oid dir_id)
{
	Relation		pg_directory_rel;
	HeapTuple		tuple;

	pg_directory_rel = heap_open(DirectoryRelationId, RowExclusiveLock);

	/*
	 * Find the directory to delete.
	 */
	tuple = SearchSysCache1(DIRECTORYOID, ObjectIdGetDatum(dir_id));

	/* If the directory exists, then remove it, otherwise raise an error. */
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "could not find tuple for directory %u", dir_id);

	simple_heap_delete(pg_directory_rel, &tuple->t_self);

	ReleaseSysCache(tuple);
	heap_close(pg_directory_rel, RowExclusiveLock);
}

/*
 * CreateDirectory
 *   handles the execution of the CREATE DIRECTORY command.
 *
 * stmt - the CreateDirectoryStmt that describes the directory entry to create.
 */
void
CreateDirectory(CreateDirectoryStmt *stmt)
{
#ifdef HAVE_SYMLINK
	Relation		pg_directory_rel;
	Datum			values[Natts_pg_directory];
	bool			nulls[Natts_pg_directory];
	ScanKeyData		skey[1];
	HeapScanDesc	scandesc;
	HeapTuple		tuple;
	Oid				dir_id;
	char		   *path;
	Oid				owner_id;

	/* Unix-ify the path, and strip any trailing slashes */
	path = pstrdup(stmt->path);
	canonicalize_path(path);

	/*
	 * Need permission checks here.  Superuser is implied to be necessary, but
	 * perhaps this would also be allowed by an ADMIN role?
	 */

	/* However, the eventual owner does not have to be either. */
	if (stmt->owner != NULL)
		owner_id = get_role_oid(stmt->owner, false);
	else
		owner_id = GetUserId();

	/* Disallow quotes */
	if (strchr(path, '\''))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_NAME),
				 errmsg("directory path cannot contain single quotes")));

	/*
	 * Allowing relative paths seems risky and really a bad idea.  Therefore,
	 * if a relative path is provided then an error is raised.
	 *
	 * This also helps us ensure that directory path is not empty or whitespace.
	 */
	if (!is_absolute_path(path))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_OBJECT_DEFINITION),
				 errmsg("directory path must be an absolute path")));

	/* Open pg_directory catalog */
	pg_directory_rel = heap_open(DirectoryRelationId, RowExclusiveLock);

	/*
	 * Make sure duplicate do not exist.  Need to check both the alias and
	 * the path.  If either exists, then raise an error.
	 */

	/* Check alias does not already exist */
	ScanKeyInit(&skey[0],
				Anum_pg_directory_diralias,
				BTEqualStrategyNumber, F_NAMEEQ,
				CStringGetDatum(stmt->alias));

	/*
	 * We use a heapscan here even though there is an index on alias and path.
	 * We do this on the theory that pg_directory will usually have a
	 * relatively small number of entries and therefore it is safe to assume
	 * an index scan would be wasted effort.
	 */
	scandesc = heap_beginscan_catalog(pg_directory_rel, 1, skey);

	if (HeapTupleIsValid(heap_getnext(scandesc, ForwardScanDirection)))
		ereport(ERROR,
				(errcode(ERRCODE_DUPLICATE_OBJECT),
				 errmsg("directory \"%s\" already exists", stmt->alias)));

	heap_endscan(scandesc);

	ScanKeyInit(&skey[0],
				Anum_pg_directory_dirpath,
				BTEqualStrategyNumber, F_TEXTEQ,
				CStringGetTextDatum(path));

	scandesc = heap_beginscan_catalog(pg_directory_rel, 1, skey);

	/* Check that path does not already exist. */
	if (HeapTupleIsValid(heap_getnext(scandesc, ForwardScanDirection)))
		ereport(ERROR,
				(errcode(ERRCODE_DUPLICATE_OBJECT),
				 errmsg("directory path \"%s\" already exists", path)));

	heap_endscan(scandesc);

	/*
	 * All is well and safe to insert.
	 */

	/* zero-clear */
	memset(values, 0, sizeof(values));
	memset(nulls,  0, sizeof(nulls));

	values[Anum_pg_directory_diralias - 1] = CStringGetDatum(stmt->alias);
	values[Anum_pg_directory_dirpath - 1] = CStringGetTextDatum(path);
	values[Anum_pg_directory_dirowner - 1] = ObjectIdGetDatum(owner_id);

	/* No ACL items are set on the directory by default */
	nulls[Anum_pg_directory_diracl - 1] = true;

	tuple = heap_form_tuple(RelationGetDescr(pg_directory_rel), values, nulls);

	dir_id = simple_heap_insert(pg_directory_rel, tuple);

	/* Update Indexes */
	CatalogUpdateIndexes(pg_directory_rel, tuple);

	/* Record Dependency on owner*/
	recordDependencyOnOwner(DirectoryRelationId, dir_id, owner_id);

	/* Post creation hook for new directory */
	InvokeObjectPostCreateHook(DirectoryRelationId, dir_id, 0);

	/* Clean up */
	heap_close(pg_directory_rel, RowExclusiveLock);

#else    /* !HAVE_SYMLINK */
	ereport(ERROR,
			(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
			 errmsg("directories are not supported on this platform")));
#endif   /* HAVE_SYMLINK */
}

/*
 * AlterDirectory
 *   handles the execution of the ALTER DIRECTORY command.
 *
 * stmt - the AlterDirectoryStmt that describes the directory entry to alter.
 */
void
AlterDirectory(AlterDirectoryStmt *stmt)
{
	Relation		pg_directory_rel;
	ScanKeyData		skey[1];
	HeapScanDesc	scandesc;
	HeapTuple		tuple;
	Datum			values[Natts_pg_directory];
	bool			nulls[Natts_pg_directory];
	bool			replaces[Natts_pg_directory];
	HeapTuple		new_tuple;
	char		   *path;

	/* Unix-ify the new path, and strip any trailing slashes */
	path = pstrdup(stmt->path);
	canonicalize_path(path);

	/* Disallow quotes */
	if (strchr(path, '\''))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_NAME),
				 errmsg("directory path cannot contain single quotes")));

	/* Open pg_directory catalog */
	pg_directory_rel = heap_open(DirectoryRelationId, RowExclusiveLock);

	/* Search for directory by alias */
	ScanKeyInit(&skey[0],
				Anum_pg_directory_diralias,
				BTEqualStrategyNumber, F_NAMEEQ,
				CStringGetDatum(stmt->alias));

	/*
	 * We use a heapscan here even though there is an index on alias and path.
	 * We do this on the theory that pg_directory will usually have a
	 * relatively small number of entries and therefore it is safe to assume
	 * an index scan would be wasted effort.
	 */
	scandesc = heap_beginscan_catalog(pg_directory_rel, 1, skey);

	tuple = heap_getnext(scandesc, ForwardScanDirection);

	/* If directory does not exist then raise an error */
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("directory \"%s\" does not exist", stmt->alias)));

	/* Permission check - must be owner of the directory or superuser */
	if (!pg_directory_ownercheck(HeapTupleGetOid(tuple), GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_DIRECTORY,
					   stmt->alias);

	/* Build new tuple and update pg_directory */
	memset(nulls,    0, sizeof(nulls));
	memset(replaces, 0, sizeof(replaces));
	memset(values,   0, sizeof(values));

	values[Anum_pg_directory_dirpath - 1] = CStringGetTextDatum(path);
	replaces[Anum_pg_directory_dirpath - 1] = true;

	new_tuple = heap_modify_tuple(tuple, RelationGetDescr(pg_directory_rel),
								  values, nulls, replaces);

	simple_heap_update(pg_directory_rel, &new_tuple->t_self, new_tuple);

	/* Update Indexes */
	CatalogUpdateIndexes(pg_directory_rel, new_tuple);

	/* Post alter hook for directory */
	InvokeObjectPostAlterHook(DirectoryRelationId, HeapTupleGetOid(tuple), 0);

	/* Clean Up */
	heap_freetuple(new_tuple);
	heap_endscan(scandesc);
	heap_close(pg_directory_rel, RowExclusiveLock);
}

/*
 * GrantDirectory
 *   handles the execution of the GRANT/REVOKE ON DIRECTORY command.
 *
 * stmt - the GrantDirectoryStmt that describes the directories and permissions
 *        to be granted/revoked.
 */
void
GrantDirectory(GrantDirectoryStmt *stmt)
{
	Relation		pg_directory_rel;
	Oid				grantor;
	List		   *grantee_ids;
	AclMode			permissions;
	ListCell	   *item;

	/*
	 * Grantor is optional.  If it is not provided then set it to the current
	 * user.
	 */
	if (stmt->grantor)
		grantor = get_role_oid(stmt->grantor, false);
	else
		grantor = GetUserId();

	/* Convert grantee names to oids */
	grantee_ids = roleNamesToIds(stmt->grantees);

	permissions = ACL_NO_RIGHTS;

	/* Condense all permissions */
	foreach(item, stmt->permissions)
	{
		AccessPriv *priv = (AccessPriv *) lfirst(item);
		permissions |= string_to_permission(priv->priv_name);
	}

	/*
	 * Though it shouldn't be possible to provide permissions other than READ
	 * and WRITE, check to make sure no others have been set.  If they have,
	 * then warn the user and correct the permissions.
	 */
	if (permissions & !((AclMode) ACL_ALL_RIGHTS_DIRECTORY))
	{
		ereport(WARNING,
				(errcode(ERRCODE_INVALID_GRANT_OPERATION),
				 errmsg("directories only support READ and WRITE permissions")));

		permissions &= ACL_ALL_RIGHTS_DIRECTORY;
	}

	pg_directory_rel = heap_open(DirectoryRelationId, RowExclusiveLock);

	/* Grant/Revoke permissions on directories. */
	foreach(item, stmt->directories)
	{
		Datum			values[Natts_pg_directory];
		bool			replaces[Natts_pg_directory];
		bool			nulls[Natts_pg_directory];
		ScanKeyData		skey[1];
		HeapScanDesc	scandesc;
		HeapTuple		tuple;
		HeapTuple		new_tuple;
		Datum			datum;
		Oid				owner_id;
		Acl			   *dir_acl;
		Acl			   *new_acl;
		bool			is_null;
		int				num_old_members;
		int				num_new_members;
		Oid			   *old_members;
		Oid			   *new_members;
		Oid				dir_id;
		char		   *alias;

		alias = strVal(lfirst(item));

		ScanKeyInit(&skey[0],
					Anum_pg_directory_diralias,
					BTEqualStrategyNumber, F_NAMEEQ,
					CStringGetDatum(alias));

		scandesc = heap_beginscan_catalog(pg_directory_rel, 1, skey);

		tuple = heap_getnext(scandesc, ForwardScanDirection);

		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "could not find tuple for directory \"%s\"", alias);

		/* Get directory owner id */
		datum = heap_getattr(tuple, Anum_pg_directory_dirowner,
							 RelationGetDescr(pg_directory_rel), &is_null);
		owner_id = DatumGetObjectId(datum);

		/* Get directory ACL */
		datum = heap_getattr(tuple, Anum_pg_directory_diracl,
							 RelationGetDescr(pg_directory_rel), &is_null);

		/* Get the Directory Oid */
		dir_id = HeapTupleGetOid(tuple);

		/*
		 * If there are currently no permissions granted on the directory,
		 * then add default permissions, which should include the permssions
		 * granted to the owner of the table.
		 */
		if (is_null)
		{
			dir_acl = acldefault(ACL_OBJECT_DIRECTORY, owner_id);
			num_old_members = 0;
			old_members = NULL;
		}
		else
		{
			dir_acl = DatumGetAclPCopy(datum);

			/* Get the roles in the current ACL */
			num_old_members = aclmembers(dir_acl, &old_members);
		}

		/* Merge new ACL with current ACL */
		new_acl = merge_acl_with_grant(dir_acl, grantee_ids, stmt->is_grant,
									   permissions, grantor, owner_id);

		num_new_members = aclmembers(new_acl, &new_members);

		/* Insert new ACL value */
		memset(values,   0, sizeof(values));
		memset(nulls,    0, sizeof(nulls));
		memset(replaces, 0, sizeof(replaces));

		values[Anum_pg_directory_diracl - 1] = PointerGetDatum(new_acl);
		replaces[Anum_pg_directory_diracl - 1] = true;

		new_tuple = heap_modify_tuple(tuple, RelationGetDescr(pg_directory_rel),
									  values, nulls, replaces);

		simple_heap_update(pg_directory_rel, &new_tuple->t_self, new_tuple);

		/* Update Indexes */
		CatalogUpdateIndexes(pg_directory_rel, new_tuple);

		/* Update shared dependency ACL information */
		updateAclDependencies(DirectoryRelationId, dir_id, 0,
							  owner_id,
							  num_old_members, old_members,
							  num_new_members, new_members);

		/* Clean Up */
		pfree(new_acl);
		heap_endscan(scandesc);
	}

	heap_close(pg_directory_rel, RowExclusiveLock);
}

/*
 * Merge an existing ACL with the permissions specified by GRANT/REVOKE.
 */
static Acl *
merge_acl_with_grant(Acl *old_acl, List *grantees, bool is_grant,
					 AclMode permissions, Oid grantor, Oid owner)
{
	unsigned	modechg;
	Acl		   *acl;
	ListCell   *item;

	modechg = is_grant ? ACL_MODECHG_ADD : ACL_MODECHG_DEL;

	acl = old_acl;

	foreach(item, grantees)
	{
		AclItem		aclitem;
		Acl		   *new_acl;

		/*
		 * TODO - need to handle PUBLIC case if grant options are allowed.
		 * Grant options cannot be granted to PUBLIC only to individual roles.
		 */
		aclitem.ai_grantee = lfirst_oid(item);
		aclitem.ai_grantor = grantor;

		/* Set the permissions only, no grant options are allowed. */
		ACLITEM_SET_PRIVS_GOPTIONS(aclitem, permissions, ACL_NO_RIGHTS);

		/*
		 * Need to consider the DropBehavior - is it necessary to allow it to be
		 * passed in, if not, then what would be the appropriate default?
		 */
		new_acl = aclupdate(acl, &aclitem, modechg, owner, DROP_CASCADE);

		pfree(acl);
		acl = new_acl;
	}

	return acl;
}

/*
 * get_directory_alias
 *   given a directory OID, look up the alias.  If the directory does not exist
 *   then NULL is returned.
 *
 * dir_id - the OID of the directory entry in pg_directory.
 */
char *
get_directory_alias(Oid dir_id)
{
	char		   *alias = NULL;
	HeapTuple		tuple;

	tuple = SearchSysCache1(DIRECTORYOID, ObjectIdGetDatum(dir_id));
	if (HeapTupleIsValid(tuple))
	{
		alias = pstrdup(NameStr(((Form_pg_directory) GETSTRUCT(tuple))->diralias));
		ReleaseSysCache(tuple);
	}

	return alias;
}

/*
 * get_directory_oid_by_path
 *   given a directory path, look up the OID.  If the directory does not exist
 *   this InvalidOid is returned.
 *
 * path - the path of the directory
 */
Oid
get_directory_oid_by_path(const char *path)
{
	Oid				dir_id = InvalidOid;
	Relation		pg_directory_rel;
	HeapScanDesc	scandesc;
	HeapTuple		tuple;
	ScanKeyData		skey[1];

	/*
	 * Search pg_directory.  We use a heapscan here even though there is an index
	 * on alias.  We do this on the theory that pg_directory will usually have a
	 * relatively small number of entries and therefore it is safe to assume
	 * an index scan would be wasted effort.
	 */
	pg_directory_rel = heap_open(DirectoryRelationId, AccessShareLock);

	ScanKeyInit(&skey[0],
				Anum_pg_directory_dirpath,
				BTEqualStrategyNumber, F_TEXTEQ,
				CStringGetTextDatum(path));

	scandesc = heap_beginscan_catalog(pg_directory_rel, 1, skey);
	tuple = heap_getnext(scandesc, ForwardScanDirection);

	if (HeapTupleIsValid(tuple))
		dir_id = HeapTupleGetOid(tuple);

	heap_endscan(scandesc);
	heap_close(pg_directory_rel, AccessShareLock);

	return dir_id;
}

/*
 * get_directory_oid
 *   given a directory alias, look up the OID.  If a directory does not exist for
 *   the alias then if missing_ok is true InvalidOid is returned otherwise an
 *   error is raised.
 *
 * alias - the alias of the directory
 * missing_ok - false if an error should be raised if the directory does not
 *              exist.
 */
Oid
get_directory_oid(const char *alias, bool missing_ok)
{
	Oid				dir_id;
	Relation		pg_directory_rel;
	HeapScanDesc	scandesc;
	HeapTuple		tuple;
	ScanKeyData		skey[1];

	/*
	 * Search pg_directory.  We use a heapscan here even though there is an index
	 * on alias.  We do this on the theory that pg_directory will usually have a
	 * relatively small number of entries and therefore it is safe to assume
	 * an index scan would be wasted effort.
	 */
	pg_directory_rel = heap_open(DirectoryRelationId, AccessShareLock);

	ScanKeyInit(&skey[0],
				Anum_pg_directory_diralias,
				BTEqualStrategyNumber, F_NAMEEQ,
				CStringGetDatum(alias));

	scandesc = heap_beginscan_catalog(pg_directory_rel, 1, skey);
	tuple = heap_getnext(scandesc, ForwardScanDirection);

	if (HeapTupleIsValid(tuple))
		dir_id = HeapTupleGetOid(tuple);
	else
		dir_id = InvalidOid;

	heap_endscan(scandesc);
	heap_close(pg_directory_rel, AccessShareLock);

	if (!OidIsValid(dir_id) && !missing_ok)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("directory \"%s\" does not exist", alias)));

	return dir_id;
}

/*
 * get_directory_owner
 *   given a directory OID, look up the owner. If the directory does not exist
 *   then InvalidOid is returned.
 *
 * dir_id - the oid of the directory entry.
 */
Oid
get_directory_owner(Oid dir_id)
{
	Oid				owner = InvalidOid;
	HeapTuple		tuple;

	tuple = SearchSysCache1(DIRECTORYOID, ObjectIdGetDatum(dir_id));
	if (HeapTupleIsValid(tuple))
	{
		owner = ((Form_pg_directory) GETSTRUCT(tuple))->dirowner;
		ReleaseSysCache(tuple);
	}

	return owner;
}

/*
 * string_to_permission
 *   given a string representation of a permission, return its corresponding
 *   AclMode.  If an invalid value is provided then an error is raised.
 *
 * permission - the string representation of the permission.
 */
static AclMode
string_to_permission(const char *permission)
{
	if (strcmp(permission, "create") == 0)
		return ACL_CREATE;
	if (strcmp(permission, "select") == 0)
		return ACL_SELECT;
	if (strcmp(permission, "update") == 0)
		return ACL_UPDATE;
	ereport(ERROR,
			(errcode(ERRCODE_SYNTAX_ERROR),
			 errmsg("unrecognized permission type \"%s\"", permission)));
	return 0;					/* appease compiler */
}
