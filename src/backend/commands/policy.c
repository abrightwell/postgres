/*-------------------------------------------------------------------------
 *
 * policy.c
 *	  Commands for manipulating policies.
 *
 * Portions Copyright (c) 1996-2014, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/backend/commands/policy.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "access/htup.h"
#include "access/htup_details.h"
#include "access/sysattr.h"
#include "catalog/catalog.h"
#include "catalog/dependency.h"
#include "catalog/indexing.h"
#include "catalog/namespace.h"
#include "catalog/objectaccess.h"
#include "catalog/objectaddress.h"
#include "catalog/pg_class.h"
#include "catalog/pg_rowsecurity.h"
#include "catalog/pg_type.h"
#include "commands/policy.h"
#include "miscadmin.h"
#include "nodes/nodeFuncs.h"
#include "nodes/pg_list.h"
#include "optimizer/clauses.h"
#include "parser/parse_clause.h"
#include "parser/parse_node.h"
#include "parser/parse_relation.h"
#include "storage/lock.h"
#include "utils/acl.h"
#include "utils/array.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/inval.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/syscache.h"

static void RangeVarCallbackForPolicy(const RangeVar *rv,
				Oid relid, Oid oldrelid, void *arg);
static const char parse_row_security_command(const char *cmd_name);
static ArrayType* parse_role_ids(List *roles);

/*
 * Callback to RangeVarGetRelidExtended().
 *
 * Checks the following:
 *  - the relation specified is a table.
 *  - current user owns the table.
 *  - the table is not a system table.
 *
 * If any of these checks fails then an error is raised.
 */
static void
RangeVarCallbackForPolicy(const RangeVar *rv, Oid relid, Oid oldrelid,
								void *arg)
{
	HeapTuple		tuple;
	Form_pg_class	classform;
	char			relkind;

	tuple = SearchSysCache1(RELOID, ObjectIdGetDatum(relid));
	if (!HeapTupleIsValid(tuple))
		return;

	classform = (Form_pg_class) GETSTRUCT(tuple);
	relkind = classform->relkind;

	/* Must own relation. */
	if (!pg_class_ownercheck(relid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS, rv->relname);

	/* No system table modifications unless explicitly allowed. */
	if (!allowSystemTableMods && IsSystemClass(relid, classform))
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied: \"%s\" is a system catalog",
						rv->relname)));

	/* Relation type MUST be a table. */
	if (relkind != RELKIND_RELATION)
		ereport(ERROR,
				(errcode(ERRCODE_WRONG_OBJECT_TYPE),
				 errmsg("\"%s\" is not a table", rv->relname)));

	ReleaseSysCache(tuple);
}

/*
 * parse_row_security_command -
 *   helper function to convert full command strings to their char
 *   representation.
 *
 * cmd_name - full string command name. Valid values are 'all', 'select',
 *			  'insert', 'update' and 'delete'.
 *
 */
static const char
parse_row_security_command(const char *cmd_name)
{
	char cmd;

	if (!cmd_name)
		elog(ERROR, "Unregonized command.");

	if (strcmp(cmd_name, "all") == 0)
		cmd = 0;
	else if (strcmp(cmd_name, "select") == 0)
		cmd = ACL_SELECT_CHR;
	else if (strcmp(cmd_name, "insert") == 0)
		cmd = ACL_INSERT_CHR;
	else if (strcmp(cmd_name, "update") == 0)
		cmd = ACL_UPDATE_CHR;
	else if (strcmp(cmd_name, "delete") == 0)
		cmd = ACL_DELETE_CHR;
	else
		elog(ERROR, "Unregonized command.");
		/* error unrecognized command */

	return cmd;
}

/*
 * parse_role_ids
 *   helper function to convert a list of role names in to an array of
 *   role ids.
 *
 * Note: If PUBLIC is provided as a role name, then ACL_PUBLIC_ID is
 *       used as the role id.
 *
 * roles - the list of role names to convert.
 */
static ArrayType *
parse_role_ids(List *roles)
{
	ArrayType  *role_ids;
	Datum	   *temp_array;
	ListCell   *cell;
	int			num_roles;
	int			i = 0;

	/* Handle no roles being passed in as being for public */
	if (roles == NIL)
	{
		temp_array = (Datum *) palloc(sizeof(Datum));
		temp_array[0] = ObjectIdGetDatum(ACL_ID_PUBLIC);

		role_ids = construct_array(temp_array, 1, OIDOID, sizeof(Oid), true,
								   'i');
		return role_ids;
	}

	num_roles = list_length(roles);
	temp_array = (Datum *) palloc(num_roles * sizeof(Datum));

	foreach(cell, roles)
	{
		char	   *role_name = strVal(lfirst(cell));

		/*
		 * PUBLIC covers all roles, so it only makes sense alone.
		 */
		if (strcmp(role_name, "public") == 0)
		{
			if (num_roles != 1)
				ereport(WARNING,
						(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						 errmsg("ignoring roles specified other than public"),
						 errhint("All roles are members of the public role.")));

			temp_array[0] = ObjectIdGetDatum(ACL_ID_PUBLIC);
			num_roles = 1;
			break;
		}
		else
			temp_array[i++] = ObjectIdGetDatum(get_role_oid(role_name, false));
	}

	role_ids = construct_array(temp_array, num_roles, OIDOID, sizeof(Oid), true,
							   'i');

	return role_ids;
}

/*
 * Load row-security policy from the catalog, and keep it in
 * the relation cache.
 */
void
RelationBuildRowSecurity(Relation relation)
{
	Relation			catalog;
	ScanKeyData			skey;
	SysScanDesc			sscan;
	HeapTuple			tuple;
	MemoryContext		oldcxt;
	MemoryContext		rscxt = NULL;
	RowSecurityDesc	   *rsdesc = NULL;

	catalog = heap_open(RowSecurityRelationId, AccessShareLock);

	ScanKeyInit(&skey,
				Anum_pg_rowsecurity_rsecrelid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(RelationGetRelid(relation)));

	sscan = systable_beginscan(catalog, RowSecurityRelidPolnameIndexId, true,
							   NULL, 1, &skey);
	PG_TRY();
	{
		/*
		 * Loop through the row-level security entries for this relation, if
		 * any.
		 */
		while (HeapTupleIsValid(tuple = systable_getnext(sscan)))
		{
			Datum				value_datum;
			char				cmd_value;
			ArrayType		   *roles;
			char			   *qual_value;
			Expr			   *qual_expr;
			char			   *with_check_value;
			Expr			   *with_check_qual;
			char			   *policy_name_value;
			Oid					policy_id;
			bool				isnull;
			RowSecurityPolicy  *policy = NULL;

			/*
			 * Set up the memory context inside our loop to ensure we are only
			 * building it when we actually need it.
			 */
			if (!rsdesc)
			{
				rscxt = AllocSetContextCreate(CacheMemoryContext,
											  "Row-security descriptor",
											  ALLOCSET_SMALL_MINSIZE,
											  ALLOCSET_SMALL_INITSIZE,
											  ALLOCSET_SMALL_MAXSIZE);
				rsdesc = MemoryContextAllocZero(rscxt, sizeof(RowSecurityDesc));
				rsdesc->rscxt = rscxt;
			}

			oldcxt = MemoryContextSwitchTo(rscxt);

			/* Get policy command */
			value_datum = heap_getattr(tuple, Anum_pg_rowsecurity_rseccmd,
								 RelationGetDescr(catalog), &isnull);
			if (isnull)
				cmd_value = 0;
			else
				cmd_value = DatumGetChar(value_datum);

			/* Get policy name */
			value_datum = heap_getattr(tuple, Anum_pg_rowsecurity_rsecpolname,
										RelationGetDescr(catalog), &isnull);
			Assert(!isnull);
			policy_name_value = DatumGetCString(value_datum);

			/* Get policy roles */
			value_datum = heap_getattr(tuple, Anum_pg_rowsecurity_rsecroles,
										RelationGetDescr(catalog), &isnull);
			Assert(!isnull);
			roles = DatumGetArrayTypeP(value_datum);

			/* Get policy qual */
			value_datum = heap_getattr(tuple, Anum_pg_rowsecurity_rsecqual,
								 RelationGetDescr(catalog), &isnull);
			if (!isnull)
			{
				qual_value = TextDatumGetCString(value_datum);
				qual_expr = (Expr *) stringToNode(qual_value);
			}
			else
				qual_expr = NULL;

			/* Get WITH CHECK qual */
			value_datum = heap_getattr(tuple, Anum_pg_rowsecurity_rsecwithcheck,
										RelationGetDescr(catalog), &isnull);

			if (!isnull)
			{
				with_check_value = TextDatumGetCString(value_datum);
				with_check_qual = (Expr *) stringToNode(with_check_value);
			}
			else
				with_check_qual = NULL;

			policy_id = HeapTupleGetOid(tuple);

			policy = palloc0(sizeof(RowSecurityPolicy));
			policy->policy_name = policy_name_value;
			policy->rsecid = policy_id;
			policy->cmd = cmd_value;
			policy->roles = roles;
			policy->qual = copyObject(qual_expr);
			policy->with_check_qual = copyObject(with_check_qual);
			policy->hassublinks = contain_subplans((Node *) qual_expr);

			rsdesc->policies = lcons(policy, rsdesc->policies);

			MemoryContextSwitchTo(oldcxt);

			if (qual_expr != NULL)
				pfree(qual_expr);

			if (with_check_qual != NULL)
				pfree(with_check_qual);
		}
	}
	PG_CATCH();
	{
		if (rscxt != NULL)
			MemoryContextDelete(rscxt);
		PG_RE_THROW();
	}
	PG_END_TRY();

	systable_endscan(sscan);
	heap_close(catalog, AccessShareLock);

	relation->rsdesc = rsdesc;
}

/*
 * RemovePolicyById -
 *   remove a row-security policy by its OID.  If a policy does not exist with
 *   the provided oid, then an error is raised.
 *
 * policy_id - the oid of the row-security policy.
 */
void
RemovePolicyById(Oid policy_id)
{
	Relation 	pg_rowsecurity_rel;
	ScanKeyData skey;
	SysScanDesc sscan;
	HeapTuple	tuple;
	Relation	rel;
	Oid			relid;

	pg_rowsecurity_rel = heap_open(RowSecurityRelationId, RowExclusiveLock);

	ScanKeyInit(&skey,
				ObjectIdAttributeNumber,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(policy_id));

	sscan = systable_beginscan(pg_rowsecurity_rel, RowSecurityOidIndexId, true,
							   NULL, 1, &skey);

	tuple = systable_getnext(sscan);

	/* If the policy exists, then remove it, otherwise raise an error. */
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "could not find tuple for row-security %u", policy_id);

	relid = ((Form_pg_rowsecurity) GETSTRUCT(tuple))->rsecrelid;

	rel = heap_open(relid, AccessExclusiveLock);

	simple_heap_delete(pg_rowsecurity_rel, &tuple->t_self);

	CacheInvalidateRelcache(rel);

	/* Clean up */
	heap_close(rel, AccessExclusiveLock);
	systable_endscan(sscan);
	heap_close(pg_rowsecurity_rel, RowExclusiveLock);
}

/*
 * CreatePolicy -
 *   handles the execution of the CREATE POLICY command.
 *
 * stmt - the CreatePolicyStmt that describes the policy to create.
 */
Oid
CreatePolicy(CreatePolicyStmt *stmt)
{
	Relation		pg_rowsecurity_rel;
	Oid				rowsec_id;
	Relation		target_table;
	Oid				table_id;
	char			rseccmd;
	ArrayType	   *role_ids;
	ParseState	   *qual_pstate;
	ParseState	   *with_check_pstate;
	RangeTblEntry  *rte;
	Node		   *qual;
	Node		   *with_check_qual;
	ScanKeyData		skeys[2];
	SysScanDesc		sscan;
	HeapTuple		rsec_tuple;
	Datum			values[Natts_pg_rowsecurity];
	bool			isnull[Natts_pg_rowsecurity];
	ObjectAddress	target;
	ObjectAddress	myself;

	/*
	 * If the command is SELECT or DELETE then WITH CHECK should be NULL.
	 */
	if (((strcmp(stmt->cmd, "select") == 0)
		|| (strcmp(stmt->cmd, "delete") == 0))
		&& stmt->with_check != NULL)
		ereport(ERROR,
				(errcode(ERRCODE_SYNTAX_ERROR),
				 errmsg("WITH CHECK cannot be applied to SELECT or DELETE")));

	/*
	 * If the command is INSERT then WITH CHECK should be the only expression
	 * provided.
	 */
	if ((strcmp(stmt->cmd, "insert") == 0)
		&& stmt->qual != NULL)
		ereport(ERROR,
				(errcode(ERRCODE_SYNTAX_ERROR),
				 errmsg("INSERT must only have a WITH CHECK expression")));


	/* Parse command */
	rseccmd = parse_row_security_command(stmt->cmd);

	/* Collect role ids */
	role_ids = parse_role_ids(stmt->roles);

	/* Parse the supplied clause */
	qual_pstate = make_parsestate(NULL);
	with_check_pstate = make_parsestate(NULL);

	/* zero-clear */
	memset(values,   0, sizeof(values));
	memset(isnull,   0, sizeof(isnull));

	/* Get id of table.  Also handles permissions checks. */
	table_id = RangeVarGetRelidExtended(stmt->table, AccessExclusiveLock,
										false, false,
										RangeVarCallbackForPolicy,
										(void *) stmt);

	/* Open target_table to build qual. No lock is necessary.*/
	target_table = relation_open(table_id, NoLock);

	rte = addRangeTableEntryForRelation(qual_pstate, target_table,
										NULL, false, false);
	addRTEtoQuery(qual_pstate, rte, false, true, true);

	rte = addRangeTableEntryForRelation(with_check_pstate, target_table,
										NULL, false, false);
	addRTEtoQuery(with_check_pstate, rte, false, true, true);

	qual = transformWhereClause(qual_pstate, copyObject(stmt->qual),
								EXPR_KIND_ROW_SECURITY,
								"ROW SECURITY");

	with_check_qual = transformWhereClause(with_check_pstate,
								copyObject(stmt->with_check),
								EXPR_KIND_ROW_SECURITY,
								"ROW SECURITY");

	/* Open pg_rowsecurity catalog */
	pg_rowsecurity_rel = heap_open(RowSecurityRelationId, RowExclusiveLock);

	/* Set key - row security relation id. */
	ScanKeyInit(&skeys[0],
				Anum_pg_rowsecurity_rsecrelid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(table_id));

	/* Set key - row security policy name. */
	ScanKeyInit(&skeys[1],
				Anum_pg_rowsecurity_rsecpolname,
				BTEqualStrategyNumber, F_NAMEEQ,
				CStringGetDatum(stmt->policy_name));

	sscan = systable_beginscan(pg_rowsecurity_rel,
							   RowSecurityRelidPolnameIndexId, true, NULL, 2,
							   skeys);

	rsec_tuple = systable_getnext(sscan);

	/*
	 * If the policy does not already exist, then create it.  Otherwise, raise
	 * an error notifying that the policy already exists.
	 */
	if (!HeapTupleIsValid(rsec_tuple))
	{
		values[Anum_pg_rowsecurity_rsecrelid - 1]
			= ObjectIdGetDatum(table_id);
		values[Anum_pg_rowsecurity_rsecpolname - 1]
			= CStringGetDatum(stmt->policy_name);

		if (rseccmd)
			values[Anum_pg_rowsecurity_rseccmd - 1]
				= CharGetDatum(rseccmd);
		else
			isnull[Anum_pg_rowsecurity_rseccmd - 1] = true;

		values[Anum_pg_rowsecurity_rsecroles - 1]
			= PointerGetDatum(role_ids);

		/* Add qual if present. */
		if (qual)
			values[Anum_pg_rowsecurity_rsecqual - 1]
				= CStringGetTextDatum(nodeToString(qual));
		else
			isnull[Anum_pg_rowsecurity_rsecqual - 1] = true;

		/* Add WITH CHECK qual if present */
		if (with_check_qual)
			values[Anum_pg_rowsecurity_rsecwithcheck - 1]
				= CStringGetTextDatum(nodeToString(with_check_qual));
		else
			isnull[Anum_pg_rowsecurity_rsecwithcheck - 1] = true;

		rsec_tuple = heap_form_tuple(RelationGetDescr(pg_rowsecurity_rel),
									 values, isnull);
		rowsec_id = simple_heap_insert(pg_rowsecurity_rel, rsec_tuple);
	}
	else
		ereport(ERROR,
				(errcode(ERRCODE_DUPLICATE_OBJECT),
		  errmsg("policy \"%s\" for relation \"%s\" already exists",
				 stmt->policy_name, RelationGetRelationName(target_table))));

	/* Update Indexes */
	CatalogUpdateIndexes(pg_rowsecurity_rel, rsec_tuple);

	/* Record Dependencies */
	target.classId = RelationRelationId;
	target.objectId = table_id;
	target.objectSubId = 0;

	myself.classId = RowSecurityRelationId;
	myself.objectId = rowsec_id;
	myself.objectSubId = 0;

	recordDependencyOn(&myself, &target, DEPENDENCY_AUTO);

	recordDependencyOnExpr(&myself, qual, qual_pstate->p_rtable,
						   DEPENDENCY_NORMAL);

	recordDependencyOnExpr(&myself, with_check_qual,
						   with_check_pstate->p_rtable, DEPENDENCY_NORMAL);

	/* Turn on relhasrowsecurity on table. */
	if (!RelationGetForm(target_table)->relhasrowsecurity)
	{
		Relation class_rel = heap_open(RelationRelationId, RowExclusiveLock);

		HeapTuple tuple;

		tuple = SearchSysCacheCopy1(RELOID, ObjectIdGetDatum(table_id));

		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache look up failed for relation %u", table_id);

		((Form_pg_class) GETSTRUCT(tuple))->relhasrowsecurity = true;

		simple_heap_update(class_rel, &tuple->t_self, tuple);
		CatalogUpdateIndexes(class_rel, tuple);

		heap_freetuple(tuple);
		heap_close(class_rel, RowExclusiveLock);
	}

	/* Invalidate Relation Cache */
	CacheInvalidateRelcache(target_table);

	/* Clean up. */
	heap_freetuple(rsec_tuple);
	free_parsestate(qual_pstate);
	free_parsestate(with_check_pstate);
	systable_endscan(sscan);
	relation_close(target_table, NoLock);
	heap_close(pg_rowsecurity_rel, RowExclusiveLock);

	return rowsec_id;
}

/*
 * AlterPolicy -
 *   handles the execution of the ALTER POLICY command.
 *
 * stmt - the AlterPolicyStmt that describes the policy and how to alter it.
 */
Oid
AlterPolicy(AlterPolicyStmt *stmt)
{
	Relation		pg_rowsecurity_rel;
	Oid				rowsec_id;
	Relation		target_table;
	Oid				table_id;
	ArrayType	   *role_ids = NULL;
	ParseState	   *qual_pstate;
	ParseState	   *with_check_pstate;
	List		   *qual_parse_rtable = NIL;
	List		   *with_check_parse_rtable = NIL;
	RangeTblEntry  *rte;
	Node		   *qual;
	Node		   *with_check_qual;
	ScanKeyData		skeys[2];
	SysScanDesc		sscan;
	HeapTuple		rsec_tuple;
	HeapTuple		new_tuple;
	Datum	values[Natts_pg_rowsecurity];
	bool	isnull[Natts_pg_rowsecurity];
	bool	replaces[Natts_pg_rowsecurity];
	ObjectAddress target;
	ObjectAddress myself;
	Datum			 cmd_datum;
	char			rseccmd;
	bool			rseccmd_isnull;


	/* Parse role_ids */
	if (stmt->roles != NULL)
		role_ids = parse_role_ids(stmt->roles);

	/* Get id of table.  Also handles permissions checks. */
	table_id = RangeVarGetRelidExtended(stmt->table, AccessExclusiveLock,
										false, false,
										RangeVarCallbackForPolicy,
										(void *) stmt);

	target_table = relation_open(table_id, NoLock);

	/* Parse the row-security clause */
	if (stmt->qual)
	{
		qual_pstate = make_parsestate(NULL);

		rte = addRangeTableEntryForRelation(qual_pstate, target_table,
											NULL, false, false);

		addRTEtoQuery(qual_pstate, rte, false, true, true);

		qual = transformWhereClause(qual_pstate, copyObject(stmt->qual),
									EXPR_KIND_ROW_SECURITY,
									"ROW SECURITY");

		qual_parse_rtable = qual_pstate->p_rtable;
		free_parsestate(qual_pstate);
	}
	else
		qual = NULL;

	if (stmt->with_check)
	{
		with_check_pstate = make_parsestate(NULL);

		rte = addRangeTableEntryForRelation(with_check_pstate, target_table,
											NULL, false, false);

		addRTEtoQuery(with_check_pstate, rte, false, true, true);

		with_check_qual = transformWhereClause(with_check_pstate,
											   copyObject(stmt->with_check),
											   EXPR_KIND_ROW_SECURITY,
											   "ROW SECURITY");

		with_check_parse_rtable = with_check_pstate->p_rtable;

		free_parsestate(with_check_pstate);
	}
	else
		with_check_qual = NULL;

	/* zero-clear */
	memset(values,   0, sizeof(values));
	memset(replaces, 0, sizeof(replaces));
	memset(isnull,   0, sizeof(isnull));

	/* Find policy to update. */
	pg_rowsecurity_rel = heap_open(RowSecurityRelationId, RowExclusiveLock);

	/* Set key - row security relation id. */
	ScanKeyInit(&skeys[0],
				Anum_pg_rowsecurity_rsecrelid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(table_id));

	/* Set key - row security policy name. */
	ScanKeyInit(&skeys[1],
				Anum_pg_rowsecurity_rsecpolname,
				BTEqualStrategyNumber, F_NAMEEQ,
				CStringGetDatum(stmt->policy_name));

	sscan = systable_beginscan(pg_rowsecurity_rel,
							   RowSecurityRelidPolnameIndexId, true, NULL, 2,
							   skeys);

	rsec_tuple = systable_getnext(sscan);

	/* Check that the policy is found, raise an error if not. */
	if (!HeapTupleIsValid(rsec_tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("policy '%s' for does not exist on table %s",
						stmt->policy_name,
						RelationGetRelationName(target_table))));

	/* Get policy command */
	cmd_datum = heap_getattr(rsec_tuple, Anum_pg_rowsecurity_rseccmd,
							 RelationGetDescr(pg_rowsecurity_rel),
							 &rseccmd_isnull);
	if (rseccmd_isnull)
		rseccmd = 0;
	else
		rseccmd = DatumGetChar(cmd_datum);

	/*
	 * If the command is SELECT or DELETE then WITH CHECK should be NULL.
	 */
	if ((rseccmd == ACL_SELECT_CHR || rseccmd == ACL_DELETE_CHR)
		&& stmt->with_check != NULL)
		ereport(ERROR,
				(errcode(ERRCODE_SYNTAX_ERROR),
				 errmsg("only USING expression allowed for SELECT, DELETE")));

	/*
	 * If the command is INSERT then WITH CHECK should be the only
	 * expression provided.
	 */
	if ((rseccmd == ACL_INSERT_CHR)
		&& stmt->qual != NULL)
		ereport(ERROR,
				(errcode(ERRCODE_SYNTAX_ERROR),
				 errmsg("only WITH CHECK expression allowed for INSERT")));

	rowsec_id = HeapTupleGetOid(rsec_tuple);

	if (role_ids != NULL)
	{
		replaces[Anum_pg_rowsecurity_rsecroles - 1] = true;
		values[Anum_pg_rowsecurity_rsecroles - 1]
			= PointerGetDatum(role_ids);
	}

	if (qual != NULL)
	{
		replaces[Anum_pg_rowsecurity_rsecqual - 1] = true;
		values[Anum_pg_rowsecurity_rsecqual - 1]
			= CStringGetTextDatum(nodeToString(qual));
	}

	if (with_check_qual != NULL)
	{
		replaces[Anum_pg_rowsecurity_rsecwithcheck - 1] = true;
		values[Anum_pg_rowsecurity_rsecwithcheck - 1]
			= CStringGetTextDatum(nodeToString(with_check_qual));
	}

	new_tuple = heap_modify_tuple(rsec_tuple,
								  RelationGetDescr(pg_rowsecurity_rel),
								  values, isnull, replaces);
	simple_heap_update(pg_rowsecurity_rel, &new_tuple->t_self, new_tuple);

	/* Update Catalog Indexes */
	CatalogUpdateIndexes(pg_rowsecurity_rel, new_tuple);

	/* Update Dependencies. */
	deleteDependencyRecordsFor(RowSecurityRelationId, rowsec_id, false);

	/* Record Dependencies */
	target.classId = RelationRelationId;
	target.objectId = table_id;
	target.objectSubId = 0;

	myself.classId = RowSecurityRelationId;
	myself.objectId = rowsec_id;
	myself.objectSubId = 0;


	recordDependencyOn(&myself, &target, DEPENDENCY_AUTO);

	recordDependencyOnExpr(&myself, qual, qual_parse_rtable, DEPENDENCY_NORMAL);

	recordDependencyOnExpr(&myself, with_check_qual, with_check_parse_rtable,
						   DEPENDENCY_NORMAL);

	heap_freetuple(new_tuple);

	/* Invalidate Relation Cache */
	CacheInvalidateRelcache(target_table);

	/* Clean up. */
	systable_endscan(sscan);
	relation_close(target_table, NoLock);
	heap_close(pg_rowsecurity_rel, RowExclusiveLock);

	return rowsec_id;
}

/*
 * rename_policy -
 *   change the name of a policy on a relation
 */
Oid
rename_policy(RenameStmt *stmt)
{
	Relation		pg_rowsecurity_rel;
	Relation		target_table;
	Oid				table_id;
	Oid				opoloid;
	ScanKeyData		skeys[2];
	SysScanDesc		sscan;
	HeapTuple		rsec_tuple;

	/* Get id of table.  Also handles permissions checks. */
	table_id = RangeVarGetRelidExtended(stmt->relation, AccessExclusiveLock,
										false, false,
										RangeVarCallbackForPolicy,
										(void *) stmt);

	target_table = relation_open(table_id, NoLock);

	pg_rowsecurity_rel = heap_open(RowSecurityRelationId, RowExclusiveLock);

	/* First pass- check for conflict */

	/* Add key - row security relation id. */
	ScanKeyInit(&skeys[0],
				Anum_pg_rowsecurity_rsecrelid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(table_id));

	/* Add key - row security policy name. */
	ScanKeyInit(&skeys[1],
				Anum_pg_rowsecurity_rsecpolname,
				BTEqualStrategyNumber, F_NAMEEQ,
				CStringGetDatum(stmt->newname));

	sscan = systable_beginscan(pg_rowsecurity_rel,
							   RowSecurityRelidPolnameIndexId, true, NULL, 2,
							   skeys);

	if (HeapTupleIsValid(rsec_tuple = systable_getnext(sscan)))
		ereport(ERROR,
				(errcode(ERRCODE_DUPLICATE_OBJECT),
				 errmsg("row-policy \"%s\" for table \"%s\" already exists",
						stmt->newname, RelationGetRelationName(target_table))));

	systable_endscan(sscan);

	/* Second pass -- find existing policy and update */
	/* Add key - row security relation id. */
	ScanKeyInit(&skeys[0],
				Anum_pg_rowsecurity_rsecrelid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(table_id));

	/* Add key - row security policy name. */
	ScanKeyInit(&skeys[1],
				Anum_pg_rowsecurity_rsecpolname,
				BTEqualStrategyNumber, F_NAMEEQ,
				CStringGetDatum(stmt->subname));

	sscan = systable_beginscan(pg_rowsecurity_rel,
							   RowSecurityRelidPolnameIndexId, true, NULL, 2,
							   skeys);

	if (HeapTupleIsValid(rsec_tuple = systable_getnext(sscan)))
	{
		opoloid = HeapTupleGetOid(rsec_tuple);

		rsec_tuple = heap_copytuple(rsec_tuple);

		namestrcpy(&((Form_pg_rowsecurity) GETSTRUCT(rsec_tuple))->rsecpolname,
				   stmt->newname);

		simple_heap_update(pg_rowsecurity_rel, &rsec_tuple->t_self, rsec_tuple);

		/* keep system catalog indexes current */
		CatalogUpdateIndexes(pg_rowsecurity_rel, rsec_tuple);

		InvokeObjectPostAlterHook(RowSecurityRelationId,
								  HeapTupleGetOid(rsec_tuple), 0);

		/*
		 * Invalidate relation's relcache entry so that other backends (and
		 * this one too!) are sent SI message to make them rebuild relcache
		 * entries.  (Ideally this should happen automatically...)
		 */
		CacheInvalidateRelcache(target_table);
	}
	else
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("row-policy \"%s\" for table \"%s\" does not exist",
						stmt->subname, RelationGetRelationName(target_table))));

	/* Clean up. */
	systable_endscan(sscan);
	heap_close(pg_rowsecurity_rel, RowExclusiveLock);
	relation_close(target_table, NoLock);

	return opoloid;
}

/*
 * DropPolicy -
 *   handle the execution of the DROP POLICY command.
 *
 * stmt - the DropPolicyStmt that describes the policy to drop.
 */
void
DropPolicy(DropPolicyStmt *stmt)
{
	Relation		pg_rowsecurity_rel;
	Relation		target_table;
	Oid				table_id;
	ScanKeyData		skeys[2];
	SysScanDesc		sscan;
	HeapTuple		rsec_tuple;

	/* Get id of table.  Also handles permissions checks. */
	table_id = RangeVarGetRelidExtended(stmt->table, AccessExclusiveLock,
										false, false,
										RangeVarCallbackForPolicy,
										(void *) stmt);

	target_table = relation_open(table_id, NoLock);

	pg_rowsecurity_rel = heap_open(RowSecurityRelationId, RowExclusiveLock);

	/* Add key - row security relation id. */
	ScanKeyInit(&skeys[0],
				Anum_pg_rowsecurity_rsecrelid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(table_id));

	/* Add key - row security policy name. */
	ScanKeyInit(&skeys[1],
				Anum_pg_rowsecurity_rsecpolname,
				BTEqualStrategyNumber, F_NAMEEQ,
				CStringGetDatum(stmt->policy_name));

	sscan = systable_beginscan(pg_rowsecurity_rel,
							   RowSecurityRelidPolnameIndexId, true, NULL, 2,
							   skeys);

	rsec_tuple = systable_getnext(sscan);

	/*
	 * If the policy exists, then remove it.  If policy does not exists and
	 * the statment uses IF EXISTS, then raise a notice.  If policy does not
	 * exist and the statment does not use IF EXISTS, then raise an error.
	 */
	if (HeapTupleIsValid(rsec_tuple))
	{
		ObjectAddress address;

		address.classId = RowSecurityRelationId;
		address.objectId = HeapTupleHeaderGetOid(rsec_tuple->t_data);
		address.objectSubId = 0;

		performDeletion(&address, DROP_RESTRICT, 0);
	}
	else
	{
		if (!stmt->missing_ok)
			ereport(ERROR,
					(errcode(ERRCODE_UNDEFINED_OBJECT),
					 errmsg("row-security policy \"%s\" does not exist on table"
							" \"%s\"",
							stmt->policy_name, stmt->table->relname)));
		else
			ereport(NOTICE,
					(errmsg("row-security policy \"%s\" does not exist on table"
							" \"%s\", skipping",
						   stmt->policy_name, stmt->table->relname)));
	}

	/* Clean up. */
	systable_endscan(sscan);
	relation_close(target_table, NoLock);
	heap_close(pg_rowsecurity_rel, RowExclusiveLock);
}

/*
 * get_relation_policy_oid - Look up a policy by name to find its OID
 *
 * If missing_ok is false, throw an error if policy not found.  If
 * true, just return InvalidOid.
 */
Oid
get_relation_policy_oid(Oid relid, const char *policy_name, bool missing_ok)
{
	Relation		pg_rowsecurity_rel;
	ScanKeyData		skeys[2];
	SysScanDesc		sscan;
	HeapTuple		rsec_tuple;
	Oid				policy_oid;

	pg_rowsecurity_rel = heap_open(RowSecurityRelationId, AccessShareLock);

	/* Add key - row security relation id. */
	ScanKeyInit(&skeys[0],
				Anum_pg_rowsecurity_rsecrelid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(relid));

	/* Add key - row security policy name. */
	ScanKeyInit(&skeys[1],
				Anum_pg_rowsecurity_rsecpolname,
				BTEqualStrategyNumber, F_NAMEEQ,
				CStringGetDatum(policy_name));

	sscan = systable_beginscan(pg_rowsecurity_rel,
							   RowSecurityRelidPolnameIndexId, true, NULL, 2,
							   skeys);

	rsec_tuple = systable_getnext(sscan);

	if (!HeapTupleIsValid(rsec_tuple))
	{
		if (!missing_ok)
			ereport(ERROR,
					(errcode(ERRCODE_UNDEFINED_OBJECT),
					 errmsg("row-security policy \"%s\" for table  \"%s\" does not exist",
							policy_name, get_rel_name(relid))));

		policy_oid = InvalidOid;
	}
	else
		policy_oid = HeapTupleGetOid(rsec_tuple);

	/* Clean up. */
	systable_endscan(sscan);
	heap_close(pg_rowsecurity_rel, RowExclusiveLock);

	return policy_oid;
}
