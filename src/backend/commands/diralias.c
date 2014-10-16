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
#include "catalog/pg_diralias.h"
#include "commands/diralias.h"
#include "commands/user.h"
#include "miscadmin.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/fmgroids.h"
#include "utils/rel.h"
#include "utils/syscache.h"

/*
 * RemoveDirAliasById
 *   remove a directory alias by its OID.  If a directory does not exist with
 *   the provided oid, then an error is raised.
 *
 * diralias_id - the oid of the directory alias.
 */
void
RemoveDirAliasById(Oid diralias_id)
{
	Relation		pg_diralias_rel;
	HeapTuple		tuple;

	pg_diralias_rel = heap_open(DirAliasRelationId, RowExclusiveLock);

	/*
	 * Find the directory alias to delete.
	 */
	tuple = SearchSysCache1(DIRALIASOID, ObjectIdGetDatum(diralias_id));

	/* If the directory alias exists, then remove it, otherwise raise an error. */
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "could not find tuple for directory alias %u", diralias_id);

	simple_heap_delete(pg_diralias_rel, &tuple->t_self);

	ReleaseSysCache(tuple);
	heap_close(pg_diralias_rel, RowExclusiveLock);
}

/*
 * CreateDirAlias
 *   handles the execution of the CREATE DIRALIAS command.
 *
 * stmt - the CreateDirAliasStmt that describes the directory alias entry to
 *        create.
 */
void
CreateDirAlias(CreateDirAliasStmt *stmt)
{
	Relation		pg_diralias_rel;
	Datum			values[Natts_pg_diralias];
	bool			nulls[Natts_pg_diralias];
	ScanKeyData		skey[1];
	HeapScanDesc	scandesc;
	HeapTuple		tuple;
	Oid				diralias_id;
	char		   *path;

	/* Must be superuser to create a directory alias entry. */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to create directory alias")));

	/* Unix-ify the path, and strip any trailing slashes */
	path = pstrdup(stmt->path);
	canonicalize_path(path);

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

	/* Open pg_diralias catalog */
	pg_diralias_rel = heap_open(DirAliasRelationId, RowExclusiveLock);

	/*
	 * Make sure a duplicate does not already exist. Need to check both the name
	 * and the path.  If either exists, then raise an error.
	 */

	/* Check alias name does not already exist */
	ScanKeyInit(&skey[0],
				Anum_pg_diralias_dirname,
				BTEqualStrategyNumber, F_NAMEEQ,
				CStringGetDatum(stmt->name));

	/*
	 * We use a heapscan here even though there is an index on alias and path.
	 * We do this on the theory that pg_diralias will usually have a
	 * relatively small number of entries and therefore it is safe to assume
	 * an index scan would be wasted effort.
	 */
	scandesc = heap_beginscan_catalog(pg_diralias_rel, 1, skey);

	if (HeapTupleIsValid(heap_getnext(scandesc, ForwardScanDirection)))
		ereport(ERROR,
				(errcode(ERRCODE_DUPLICATE_OBJECT),
				 errmsg("directory alias \"%s\" already exists", stmt->name)));

	heap_endscan(scandesc);

	ScanKeyInit(&skey[0],
				Anum_pg_diralias_dirpath,
				BTEqualStrategyNumber, F_TEXTEQ,
				CStringGetTextDatum(path));

	scandesc = heap_beginscan_catalog(pg_diralias_rel, 1, skey);

	/* Check that path does not already exist. */
	if (HeapTupleIsValid(heap_getnext(scandesc, ForwardScanDirection)))
		ereport(ERROR,
				(errcode(ERRCODE_DUPLICATE_OBJECT),
				 errmsg("directory alias with path \"%s\" already exists", path)));

	heap_endscan(scandesc);

	/*
	 * All is well and safe to insert.
	 */

	/* zero-clear */
	memset(values, 0, sizeof(values));
	memset(nulls,  0, sizeof(nulls));

	values[Anum_pg_diralias_dirname - 1] = CStringGetDatum(stmt->name);
	values[Anum_pg_diralias_dirpath - 1] = CStringGetTextDatum(path);

	/* No ACL items are set on the directory by default */
	nulls[Anum_pg_diralias_diracl - 1] = true;

	tuple = heap_form_tuple(RelationGetDescr(pg_diralias_rel), values, nulls);

	diralias_id = simple_heap_insert(pg_diralias_rel, tuple);

	/* Update Indexes */
	CatalogUpdateIndexes(pg_diralias_rel, tuple);

	/* Post creation hook for new directory alias */
	InvokeObjectPostCreateHook(DirAliasRelationId, diralias_id, 0);

	/* Clean up */
	heap_close(pg_diralias_rel, RowExclusiveLock);
}

/*
 * AlterDirAlias
 *   handles the execution of the ALTER DIRALIAS command.
 *
 * stmt - the AlterDirAliasStmt that describes the directory alias entry to alter.
 */
void
AlterDirAlias(AlterDirAliasStmt *stmt)
{
	Relation		pg_diralias_rel;
	ScanKeyData		skey[1];
	HeapScanDesc	scandesc;
	HeapTuple		tuple;
	Datum			values[Natts_pg_diralias];
	bool			nulls[Natts_pg_diralias];
	bool			replaces[Natts_pg_diralias];
	HeapTuple		new_tuple;
	char		   *path;

	/* Must be superuser to alter directory alias */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to alter directory alias")));

	/* Unix-ify the new path, and strip any trailing slashes */
	path = pstrdup(stmt->path);
	canonicalize_path(path);

	/* Disallow quotes */
	if (strchr(path, '\''))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_NAME),
				 errmsg("directory path cannot contain single quotes")));

	/* Open pg_diralias catalog */
	pg_diralias_rel = heap_open(DirAliasRelationId, RowExclusiveLock);

	/* Search for directory alias by name */
	ScanKeyInit(&skey[0],
				Anum_pg_diralias_dirname,
				BTEqualStrategyNumber, F_NAMEEQ,
				CStringGetDatum(stmt->name));

	/*
	 * We use a heapscan here even though there is an index on alias and path.
	 * We do this on the theory that pg_diralias will usually have a
	 * relatively small number of entries and therefore it is safe to assume
	 * an index scan would be wasted effort.
	 */
	scandesc = heap_beginscan_catalog(pg_diralias_rel, 1, skey);

	tuple = heap_getnext(scandesc, ForwardScanDirection);

	/* If directory alias does not exist then raise an error */
	if (!HeapTupleIsValid(tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("directory alias \"%s\" does not exist", stmt->name)));

	/* Build new tuple and update pg_diralias */
	memset(nulls,    0, sizeof(nulls));
	memset(replaces, 0, sizeof(replaces));
	memset(values,   0, sizeof(values));

	values[Anum_pg_diralias_dirpath - 1] = CStringGetTextDatum(path);
	replaces[Anum_pg_diralias_dirpath - 1] = true;

	new_tuple = heap_modify_tuple(tuple, RelationGetDescr(pg_diralias_rel),
								  values, nulls, replaces);

	simple_heap_update(pg_diralias_rel, &new_tuple->t_self, new_tuple);

	/* Update Indexes */
	CatalogUpdateIndexes(pg_diralias_rel, new_tuple);

	/* Post alter hook for directory alias */
	InvokeObjectPostAlterHook(DirAliasRelationId, HeapTupleGetOid(tuple), 0);

	/* Clean Up */
	heap_freetuple(new_tuple);
	heap_endscan(scandesc);
	heap_close(pg_diralias_rel, RowExclusiveLock);
}

/*
 * get_diralias_name
 *   given a directory alias OID, look up the name.  If the directory does not
 *   exist then NULL is returned.
 *
 * diralias_id - the OID of the directory alias entry in pg_diralias.
 */
char *
get_diralias_name(Oid diralias_id)
{
	char		   *name = NULL;
	HeapTuple		tuple;

	tuple = SearchSysCache1(DIRALIASOID, ObjectIdGetDatum(diralias_id));
	if (HeapTupleIsValid(tuple))
	{
		name = pstrdup(NameStr(((Form_pg_diralias) GETSTRUCT(tuple))->dirname));
		ReleaseSysCache(tuple);
	}

	return name;
}

/*
 * get_directory_oid_by_path
 *   given a directory path, look up the OID.  If the directory does not exist
 *   this InvalidOid is returned.
 *
 * path - the path of the directory
 */
Oid
get_diralias_oid_by_path(const char *path)
{
	Oid				dir_id = InvalidOid;
	Relation		pg_diralias_rel;
	HeapScanDesc	scandesc;
	HeapTuple		tuple;
	ScanKeyData		skey[1];

	/*
	 * Search pg_diralias.  We use a heapscan here even though there is an index
	 * on alias.  We do this on the theory that pg_diralias will usually have a
	 * relatively small number of entries and therefore it is safe to assume
	 * an index scan would be wasted effort.
	 */
	pg_diralias_rel = heap_open(DirAliasRelationId, AccessShareLock);

	ScanKeyInit(&skey[0],
				Anum_pg_diralias_dirpath,
				BTEqualStrategyNumber, F_TEXTEQ,
				CStringGetTextDatum(path));

	scandesc = heap_beginscan_catalog(pg_diralias_rel, 1, skey);
	tuple = heap_getnext(scandesc, ForwardScanDirection);

	if (HeapTupleIsValid(tuple))
		dir_id = HeapTupleGetOid(tuple);

	heap_endscan(scandesc);
	heap_close(pg_diralias_rel, AccessShareLock);

	return dir_id;
}

/*
 * get_directory_oid
 *   given a directory alias name, look up the OID.  If a directory alias does
 *   not exist for the given name then raise an error.  However, if missing_ok
 *   is true, then return InvalidOid.
 *
 * name - the name of the directory alias
 * missing_ok - false if an error should be raised if the directory alias does
 *              not exist.
 */
Oid
get_diralias_oid(const char *name, bool missing_ok)
{
	Oid				dir_id;
	Relation		pg_diralias_rel;
	ScanKeyData		skey[1];
	SysScanDesc		sscan;
	HeapTuple		tuple;

	/* Search pg_diralias for a directory alias entry with provided name */
	pg_diralias_rel = heap_open(DirAliasRelationId, AccessShareLock);

	ScanKeyInit(&skey[0],
				Anum_pg_diralias_dirname,
				BTEqualStrategyNumber, F_NAMEEQ,
				CStringGetDatum(name));

	sscan = systable_beginscan(pg_diralias_rel, DirAliasNameIndexId,
							   true, NULL, 1, skey);

	tuple = systable_getnext(sscan);

	if (HeapTupleIsValid(tuple))
		dir_id = HeapTupleGetOid(tuple);
	else
		dir_id = InvalidOid;

	systable_endscan(sscan);
	heap_close(pg_diralias_rel, AccessShareLock);

	if (!OidIsValid(dir_id) && !missing_ok)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("directory alias \"%s\" does not exist", name)));

	return dir_id;
}
