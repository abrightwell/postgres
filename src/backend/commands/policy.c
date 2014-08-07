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
#include "access/htup_details.h"
#include "access/sysattr.h"
#include "catalog/catalog.h"
#include "catalog/dependency.h"
#include "catalog/indexing.h"
#include "catalog/namespace.h"
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
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/inval.h"
#include "utils/rel.h"
#include "utils/syscache.h"

static void
RangeVarCallbackForCreatePolicy(const RangeVar *rv, Oid relid, Oid oldrelid,
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

static const char
parse_row_security_command(const char *cmd_name)
{
	char cmd;

	if (strcmp(cmd_name, "all") == 0)
		cmd = ROWSECURITY_CMD_ALL;
	else if (strcmp(cmd_name, "select") == 0)
		cmd = ROWSECURITY_CMD_SELECT;
	else if (strcmp(cmd_name, "insert") == 0)
		cmd = ROWSECURITY_CMD_INSERT;
	else if (strcmp(cmd_name, "update") == 0)
		cmd = ROWSECURITY_CMD_UPDATE;
	else if (strcmp(cmd_name, "delete") == 0)
		cmd = ROWSECURITY_CMD_DELETE;
	else
		elog(ERROR, "Unregonized command.");
		/* error unrecognized command */

	return cmd;
}

static RowSecurityEntry *
create_row_security_entry(Oid id, Expr *qual, MemoryContext context)
{
	RowSecurityEntry *entry;

	entry = MemoryContextAllocZero(context, sizeof(RowSecurityEntry));
	entry->rsecid = id;
	entry->qual = copyObject(qual);
	entry->hassublinks = contain_subplans((Node *) entry->qual);

	return entry;
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

	sscan = systable_beginscan(catalog, RowSecurityRelidIndexId, true,
							   NULL, 1, &skey);
	PG_TRY();
	{
		/*
		 * Loop through the row-level security entries for this relation, if
		 * any.  While we currently only support one command type for row-level
		 * security, eventually we will support multiple types and we will
		 * need to find the correct one (or possibly merge them?).
		 */
		while (HeapTupleIsValid(tuple = systable_getnext(sscan)))
		{
			Datum		value_datum;
			char		cmd_value;
			char	   *qual_value;
			Expr	   *qual_expr;
			char	   *policy_name_value;
			Oid			policy_id;
			ListCell   *item;
			bool		isnull;
			RowSecurityPolicy *policy = NULL;
			RowSecurityPolicy *temp_policy;

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

			/* Get policy command */
			value_datum = heap_getattr(tuple, Anum_pg_rowsecurity_rseccmd,
								 RelationGetDescr(catalog), &isnull);
			Assert(!isnull);
			cmd_value = DatumGetChar(value_datum);

			/* Get policy name */
			value_datum = heap_getattr(tuple, Anum_pg_rowsecurity_rsecpolname,
										RelationGetDescr(catalog), &isnull);
			Assert(!isnull);
			policy_name_value = DatumGetCString(value_datum);

			/* Get policy qual */
			value_datum = heap_getattr(tuple, Anum_pg_rowsecurity_rsecqual,
								 RelationGetDescr(catalog), &isnull);
			Assert(!isnull);
			qual_value = TextDatumGetCString(value_datum);
			qual_expr = (Expr *) stringToNode(qual_value);

			policy_id = HeapTupleGetOid(tuple);

			/* Currently only support ALL command.  Ignore all other policies. */
			if (DatumGetChar(cmd_value) != ROWSECURITY_CMD_ALL)
			{
				ereport(WARNING,
						(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
						 errmsg("Per-command row-security not implemented")));
				continue;
			}

			/* Find policy description for policy based on policy name.*/
			foreach(item, rsdesc->policies)
			{
				temp_policy = (RowSecurityPolicy *) lfirst(item);

				if (strcmp(temp_policy->policy_name, policy_name_value) == 0)
				{
					policy = temp_policy;
					break;
				}
			}

			oldcxt = MemoryContextSwitchTo(rscxt);

			/*
			 * If no policy was found in the list, create a new one and add it
			 * to the list.
			 */
			if (!policy)
			{
				policy = MemoryContextAllocZero(rscxt, sizeof(RowSecurityPolicy));
				policy->policy_name = policy_name_value;
				rsdesc->policies = lcons(policy, rsdesc->policies);
			}

			/* Set policy information by command */
			switch (cmd_value)
			{
				case ROWSECURITY_CMD_ALL:
					policy->rsall = create_row_security_entry(policy_id,
											qual_expr, rscxt);
					break;
				case ROWSECURITY_CMD_SELECT:
					policy->rsselect = create_row_security_entry(policy_id,
											qual_expr, rscxt);
					break;
				case ROWSECURITY_CMD_INSERT:
					policy->rsinsert = create_row_security_entry(policy_id,
											qual_expr, rscxt);
					break;
				case ROWSECURITY_CMD_UPDATE:
					policy->rsupdate = create_row_security_entry(policy_id,
											qual_expr, rscxt);
					break;
				case ROWSECURITY_CMD_DELETE:
					policy->rsdelete = create_row_security_entry(policy_id,
											qual_expr, rscxt);
					break;
				default:
					elog(ERROR, "Unregonized command for row-security policy");
			}

			MemoryContextSwitchTo(oldcxt);

			pfree(qual_expr);
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

	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "could not find tuple for row-security %u", policy_id);

	/*
	 * Open an exclusive-lock on the relation the row-security belongs to.
	 */
	relid = ((Form_pg_rowsecurity) GETSTRUCT(tuple))->rsecrelid;

	rel = heap_open(relid, AccessExclusiveLock);

	simple_heap_delete(pg_rowsecurity_rel, &tuple->t_self);

	CacheInvalidateRelcache(rel);

	heap_close(rel, AccessExclusiveLock);

	systable_endscan(sscan);
	heap_close(pg_rowsecurity_rel, RowExclusiveLock);
}

/*
 * CREATE POLICY
 */
Oid
CreatePolicy(CreatePolicyStmt *stmt)
{
	Relation		pg_rowsecurity_rel;
	Oid				rowsec_id;
	Relation		target_table;
	Oid				table_id;
	char			rseccmd;
	ParseState	   *pstate;
	RangeTblEntry  *rte;
	Node		   *qual;
	ScanKeyData		skeys[3];
	SysScanDesc		sscan;
	HeapTuple		rsec_tuple;
	Datum			values[Natts_pg_rowsecurity];
	bool			isnull[Natts_pg_rowsecurity];
	ObjectAddress	target;
	ObjectAddress	myself;

	/* Parse command */
	rseccmd = parse_row_security_command(stmt->cmd);

	/* Parse the supplied clause */
	pstate = make_parsestate(NULL);

	/* zero-clear */
	memset(values,   0, sizeof(values));
	memset(isnull,   0, sizeof(isnull));

	/* Get id of table. */
	table_id = RangeVarGetRelidExtended(stmt->table, AccessExclusiveLock,
										false, false,
										RangeVarCallbackForCreatePolicy,
										(void *) stmt);

	/* Open target_table to build qual. No lock is necessary.*/
	target_table = relation_open(table_id, NoLock);


	rte = addRangeTableEntryForRelation(pstate, target_table,
										NULL, false, false);
	addRTEtoQuery(pstate, rte, false, true, true);

	qual = transformWhereClause(pstate, copyObject(stmt->qual),
								EXPR_KIND_ROW_SECURITY,
								"ROW SECURITY");

	/* Open pg_rowsecurity catalog */
	pg_rowsecurity_rel = heap_open(RowSecurityRelationId, RowExclusiveLock);

	/* Set key - row security policy name. */
	ScanKeyInit(&skeys[0],
				Anum_pg_rowsecurity_rsecpolname,
				BTEqualStrategyNumber, F_NAMEEQ,
				CStringGetDatum(stmt->policy_name));

		/* Set key - row security relation id. */
	ScanKeyInit(&skeys[1],
				Anum_pg_rowsecurity_rsecrelid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(table_id));

	/* Set key - row security command. */
	ScanKeyInit(&skeys[2],
				Anum_pg_rowsecurity_rseccmd,
				BTEqualStrategyNumber, F_CHAREQ,
				CharGetDatum(rseccmd));

	sscan = systable_beginscan(pg_rowsecurity_rel, RowSecurityRelidIndexId,
							   true, NULL, 3, skeys);

	rsec_tuple = systable_getnext(sscan);

	if (!HeapTupleIsValid(rsec_tuple))
	{
		values[Anum_pg_rowsecurity_rsecrelid - 1]
			= ObjectIdGetDatum(table_id);
		values[Anum_pg_rowsecurity_rsecpolname - 1]
			= CStringGetDatum(stmt->policy_name);
		values[Anum_pg_rowsecurity_rseccmd - 1]
			= CharGetDatum(rseccmd);
		values[Anum_pg_rowsecurity_rsecqual -1]
			= CStringGetTextDatum(nodeToString(qual));
		rsec_tuple = heap_form_tuple(RelationGetDescr(pg_rowsecurity_rel),
									 values, isnull);
		rowsec_id = simple_heap_insert(pg_rowsecurity_rel, rsec_tuple);
	}
	else
	{
		elog(ERROR, "Table \"%s\" already has a policy named \"%s\"."
			" Use a different name for the policy or to modify this policy"
			" use ALTER POLICY %s ON %s USING (qual)",
			RelationGetRelationName(target_table), stmt->policy_name,
			RelationGetRelationName(target_table), stmt->policy_name);
	}

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

	recordDependencyOnExpr(&myself, qual, pstate->p_rtable,
						   DEPENDENCY_NORMAL);

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
	free_parsestate(pstate);
	systable_endscan(sscan);
	relation_close(target_table, NoLock);
	heap_close(pg_rowsecurity_rel, RowExclusiveLock);

	return rowsec_id;
}

/*
 * ALTER POLICY
 */
Oid
AlterPolicy(AlterPolicyStmt *stmt)
{
	Relation		pg_rowsecurity_rel;
	Oid				rowsec_id;
	Relation		target_table;
	Oid				table_id;
	char			rseccmd;
	ParseState	   *pstate;
	RangeTblEntry  *rte;
	Node		   *qual;
	ScanKeyData		skeys[3];
	SysScanDesc		sscan;
	HeapTuple		rsec_tuple;
	HeapTuple		new_tuple;
	Datum	values[Natts_pg_rowsecurity];
	bool	isnull[Natts_pg_rowsecurity];
	bool	replaces[Natts_pg_rowsecurity];
	ObjectAddress target;
	ObjectAddress myself;

	/* Parse command */
	rseccmd = parse_row_security_command(stmt->cmd);

	/* Get id of table. */
	table_id = RangeVarGetRelidExtended(stmt->table, AccessExclusiveLock,
										false, false,
										RangeVarCallbackForCreatePolicy,
										(void *) stmt);

	target_table = relation_open(table_id, NoLock);

	/* Parse the row-security clause */
	pstate = make_parsestate(NULL);

	rte = addRangeTableEntryForRelation(pstate, target_table,
										NULL, false, false);

	addRTEtoQuery(pstate, rte, false, true, true);

	qual = transformWhereClause(pstate, copyObject(stmt->qual),
								EXPR_KIND_ROW_SECURITY,
								"ROW SECURITY");

	/* zero-clear */
	memset(values,   0, sizeof(values));
	memset(replaces, 0, sizeof(replaces));
	memset(isnull,   0, sizeof(isnull));

	/* Find policy to update. */
	pg_rowsecurity_rel = heap_open(RowSecurityRelationId, RowExclusiveLock);

	/* Set key - row security policy name. */
	ScanKeyInit(&skeys[0],
				Anum_pg_rowsecurity_rsecpolname,
				BTEqualStrategyNumber, F_NAMEEQ,
				CStringGetDatum(stmt->policy_name));

	/* Set key - row security relation id. */
	ScanKeyInit(&skeys[1],
				Anum_pg_rowsecurity_rsecrelid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(table_id));

	/* Set key - row security command. */
	ScanKeyInit(&skeys[2],
				Anum_pg_rowsecurity_rseccmd,
				BTEqualStrategyNumber, F_CHAREQ,
				CharGetDatum(rseccmd));

	sscan = systable_beginscan(pg_rowsecurity_rel, RowSecurityRelidIndexId,
							   true, NULL, 3, skeys);

	rsec_tuple = systable_getnext(sscan);

	if (HeapTupleIsValid(rsec_tuple))
	{
		rowsec_id = HeapTupleGetOid(rsec_tuple);

		replaces[Anum_pg_rowsecurity_rsecqual - 1] = true;

		values[Anum_pg_rowsecurity_rsecqual -1]
			= CStringGetTextDatum(nodeToString(qual));

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

		recordDependencyOnExpr(&myself, qual, pstate->p_rtable,
							   DEPENDENCY_NORMAL);

		heap_freetuple(new_tuple);
	} else {
		elog(ERROR, "policy %s for %s does not exist on table %s",
			 stmt->policy_name, stmt->cmd,
			 RelationGetRelationName(target_table));
	}

	/* Invalidate Relation Cache */
	CacheInvalidateRelcache(target_table);

	/* Clean up. */
	free_parsestate(pstate);
	systable_endscan(sscan);
	relation_close(target_table, NoLock);
	heap_close(pg_rowsecurity_rel, RowExclusiveLock);

	return rowsec_id;
}

/*
 * DROP POLICY
 */
void
DropPolicy(DropPolicyStmt *stmt)
{
	Relation		pg_rowsecurity_rel;
	Relation		target_table;
	Oid				table_id;
	char			rseccmd;
	ScanKeyData		skeys[3];
	SysScanDesc		sscan;
	HeapTuple		rsec_tuple;

	/* Parse command */
	rseccmd = parse_row_security_command(stmt->cmd);

	/* Get id of target table. */
	table_id = RangeVarGetRelidExtended(stmt->table, AccessExclusiveLock,
										false, false,
										RangeVarCallbackForCreatePolicy,
										(void *) stmt);

	pg_rowsecurity_rel = heap_open(RowSecurityRelationId, RowExclusiveLock);

	/* Add key - row security policy name. */
	ScanKeyInit(&skeys[0],
				Anum_pg_rowsecurity_rsecpolname,
				BTEqualStrategyNumber, F_NAMEEQ,
				CStringGetDatum(stmt->policy_name));

	/* Add key - row security relation id. */
	ScanKeyInit(&skeys[1],
				Anum_pg_rowsecurity_rsecrelid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(table_id));

	ScanKeyInit(&skeys[2],
				Anum_pg_rowsecurity_rseccmd,
				BTEqualStrategyNumber, F_CHAREQ,
				CharGetDatum(rseccmd));

	sscan = systable_beginscan(pg_rowsecurity_rel, RowSecurityRelidIndexId,
							   true, NULL, 3, skeys);

	rsec_tuple = systable_getnext(sscan);

	if (HeapTupleIsValid(rsec_tuple))
	{
		ObjectAddress address;

		address.classId = RowSecurityRelationId;
		address.objectId = HeapTupleHeaderGetOid(rsec_tuple->t_data);
		address.objectSubId = 0;

		performDeletion(&address, DROP_RESTRICT, 0);
	}
	else
		elog(NOTICE, "Relation \"%s\" has no row-security policy named \"%s\" for %s, skipped",
			 stmt->table->relname, stmt->policy_name, stmt->cmd);

	systable_endscan(sscan);
	heap_close(pg_rowsecurity_rel, RowExclusiveLock);
}
