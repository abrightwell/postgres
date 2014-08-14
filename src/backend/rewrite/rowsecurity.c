/*
 * rewrite/rowsecurity.c
 *    Routines to support row-security feature
 *
 * Portions Copyright (c) 1996-2012, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/heapam.h"
#include "access/htup_details.h"
#include "access/sysattr.h"
#include "catalog/pg_class.h"
#include "catalog/pg_inherits_fn.h"
#include "catalog/pg_rowsecurity.h"
#include "catalog/pg_type.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "nodes/nodeFuncs.h"
#include "nodes/pg_list.h"
#include "nodes/plannodes.h"
#include "parser/parsetree.h"
#include "rewrite/rewriteHandler.h"
#include "rewrite/rewriteManip.h"
#include "rewrite/rowsecurity.h"
#include "utils/acl.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/syscache.h"
#include "tcop/utility.h"

/* hook to allow extensions to apply their own security policy */
row_security_policy_hook_type	row_security_policy_hook = NULL;

/*
 * Check the given RTE to see whether it's already had row-security quals
 * expanded and, if not, prepend any row-security rules from built-in or
 * plug-in sources to the securityQuals. The security quals are rewritten (for
 * view expansion, etc) before being added to the RTE.
 *
 * Returns true if any quals were added. Note that quals may have been found
 * but not added if user rights make the user exempt from row security.
 */
bool
prepend_row_security_quals(Query* root, RangeTblEntry* rte, int rt_index)
{
	List		   *rowsecquals;
	Relation 		rel;
	Oid				userid;
	int				sec_context;
	bool			qualsAdded = false;

	GetUserIdAndSecContext(&userid, &sec_context);
	
	if (rte->relid >= FirstNormalObjectId
		&& rte->relkind == RELKIND_RELATION
		&& !(sec_context & SECURITY_ROW_LEVEL_DISABLED))
	{
		/*
		 * Fetch the row-security qual and add it to the list of quals
		 * to be expanded by expand_security_quals.
		 */
		rel = heap_open(rte->relid, NoLock);
		rowsecquals = pull_row_security_policy(root->commandType, rel);
		if (rowsecquals)
		{
			/* 
			 * Row security quals always have the target table as varno 1, as no
			 * joins are permitted in row security expressions. We must walk
			 * the expression, updating any references to varno 1 to the varno
			 * the table has in the outer query.
			 *
			 * We rewrite the expression in-place.
			 */
			qualsAdded = true;
			ChangeVarNodes(rowsecquals, 1, rt_index, 0);
			rte->securityQuals = list_concat(rowsecquals, rte->securityQuals);
		}
		heap_close(rel, NoLock);
	}

	return qualsAdded;
}

/*
 * pull_row_security_policy
 *
 * Fetches the configured row-security policy of both built-in catalogs and any
 * extensions. If any policy is found a list of qualifier expressions is
 * returned, where each is treated as a securityQual.
 *
 * Vars must use varno 1 to refer to the table with row security.
 *
 * The returned expression trees will be modified in-place, so return copies if
 * you're not generating the expression tree each time.
 */
List *
pull_row_security_policy(CmdType cmd, Relation relation)
{
	List   *quals = NIL;
	Expr   *qual = NULL;
	char   *row_security_option;

	/*
	 * Pull the row-security policy configured with built-in features,
	 * if unprivileged users. Please note that superuser can bypass it.
	 */
	if (relation->rsdesc)
	{
		/*
		 * If Row Security is enabled, then it is applied to all queries on the
		 * relation.  If Row Security is disabled, then we must check that the
		 * current user has the privilege to bypass.  If the current user does
		 * not have the ability to bypass, then an error is thrown.
		 */
		if (is_rls_enabled())
		{
			ListCell *item;
			RowSecurityPolicy *policy;

			foreach(item, relation->rsdesc->policies)
			{
				policy = (RowSecurityPolicy *) lfirst(item);

				/* Always add ALL policy if exists. */
				if (policy->rsall != NULL)
					quals = lcons(copyObject(policy->rsall->qual), quals);

				/* Build list of quals, merging when appropriate. */
				switch(cmd)
				{
					case CMD_SELECT:
						if (policy->rsselect != NULL)
							quals = lcons(copyObject(policy->rsselect->qual), quals);
						break;
					case CMD_INSERT:
						if (policy->rsinsert != NULL)
							quals = lcons(copyObject(policy->rsinsert->qual), quals);
						break;
					case CMD_UPDATE:
						if (policy->rsselect != NULL)
							quals = lcons(copyObject(policy->rsselect->qual), quals);
						if (policy->rsupdate != NULL)
							quals = lcons(copyObject(policy->rsupdate->qual), quals);
						break;
					case CMD_DELETE:
						if (policy->rsselect != NULL)
							quals = lcons(copyObject(policy->rsselect->qual), quals);
						if (policy->rsdelete != NULL)
							quals = lcons(copyObject(policy->rsdelete->qual), quals);
						break;
					default:
						elog(ERROR, "unrecognized command type.");
						break;
				}
			}
		}
		else if (!has_bypassrls_privilege(GetUserId()))
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("Insufficient privilege to bypass row security.")));
	}


	/*
	 * Also, ask extensions whether they want to apply their own
	 * row-security policy. If both built-in and extension has
	 * their own policy they're applied as nested qualifiers.
	 */
	if (row_security_policy_hook)
	{
		List   *temp;

		temp = (*row_security_policy_hook)(cmd, relation);
		if (temp != NIL)
			quals = lcons(temp, quals);
	}

	return quals;
}

/*
 * is_rls_enabled -
 *   determines if row-security is enabled by checking the value of the system
 *   configuration "row_security".
 */
bool
is_rls_enabled()
{
	char *rls_option;

	rls_option = GetConfigOption("row_security", true, false);

	return (strcmp(rls_option, "on") == 0);
}