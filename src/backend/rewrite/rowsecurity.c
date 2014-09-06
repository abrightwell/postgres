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

static bool check_role_for_policy(RowSecurityPolicy *policy);
static List *pull_row_security_policies(CmdType cmd, Relation relation);

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
prepend_row_security_policies(Query* root, RangeTblEntry* rte, int rt_index)
{
	List			   *rowsec_policies;
	WithCheckOption	   *wco;
	Relation 			rel;
	Oid					userid;
	int					sec_context;
	bool				qualsAdded = false;

	GetUserIdAndSecContext(&userid, &sec_context);

	if (rte->relid >= FirstNormalObjectId
		&& rte->relkind == RELKIND_RELATION
		&& !(sec_context & SECURITY_ROW_LEVEL_DISABLED))
	{
		/*
		 * Fetch any row-security policies and add the quals to the list of
		 * quals to be expanded by expand_security_quals.  For with-check
		 * quals, add them to the Query's with-check-options list.
		 */
		rel = heap_open(rte->relid, NoLock);

		rowsec_policies = pull_row_security_policies(root->commandType, rel);

		if (rowsec_policies)
		{
			List	   *sec_quals = NIL;
			List	   *with_check_quals = NIL;
			ListCell   *item;

			/*
			 * Extract the USING and WITH CHECK quals from each of the policies
			 * and add them to our lists.
			 */
			foreach(item, rowsec_policies)
			{
				RowSecurityPolicy *policy = (RowSecurityPolicy *) lfirst(item);

				if (policy->qual != NULL)
					sec_quals = lcons(copyObject(policy->qual), sec_quals);

				if (policy->with_check_qual != NULL)
					with_check_quals =
						lcons(copyObject(policy->with_check_qual),
											 with_check_quals);
			}

			/*
			 * If we end up with only sec_quals, then use those for
			 * with_check_quals also.
			 */
			if (with_check_quals == NIL)
				with_check_quals = sec_quals;

			/*
			 * Row security quals always have the target table as varno 1, as no
			 * joins are permitted in row security expressions. We must walk the
			 * expression, updating any references to varno 1 to the varno
			 * the table has in the outer query.
			 *
			 * We rewrite the expression in-place.
			 */
			qualsAdded = true;
			ChangeVarNodes((Node *) sec_quals, 1, rt_index, 0);
			ChangeVarNodes((Node *) with_check_quals, 1, rt_index, 0);

			/*
			 * If more than one security qual is returned, then they need to be
			 * OR'ed together.
			 */
			if (list_length(sec_quals) > 1)
				sec_quals = list_make1(makeBoolExpr(OR_EXPR, sec_quals, -1));

			/*
			 * If more than one WITH CHECK qual is returned, then they need to
			 * be OR'ed together.
			 */
			if (list_length(with_check_quals) > 1)
				with_check_quals =
					list_make1(makeBoolExpr(OR_EXPR, with_check_quals, -1));

			/*
			 * For INSERT or UPDATE, we need to add the WITH CHECK quals to
			 * Query's withCheckOptions to verify the any new records pass the
			 * WITH CHECK policy (or USING policy, if no WITH CHECK policy
			 * exists).
			 */
			if ((root->commandType == CMD_INSERT
				|| root->commandType == CMD_UPDATE)
				&& with_check_quals != NIL)
			{
				wco = (WithCheckOption *) makeNode(WithCheckOption);
				wco->viewname = RelationGetRelationName(rel);
				wco->qual = (Node *) lfirst(list_head(with_check_quals));
				wco->cascaded = false;
				root->withCheckOptions = lcons(wco, root->withCheckOptions);
			}

			/* For SELECT, UPDATE, and DELETE, set the security quals */
			if (sec_quals != NIL && (root->commandType == CMD_SELECT
									 || root->commandType == CMD_UPDATE
									 || root->commandType == CMD_DELETE))
				rte->securityQuals = list_concat(sec_quals, rte->securityQuals);
		}

		heap_close(rel, NoLock);
	}

	/*
	 * Mark this query as having row security, so plancache can invalidate it
	 * when necessary (eg: role changes)
	 */
	root->hasRowSecurity = qualsAdded;

	return qualsAdded;
}

/*
 * pull_row_security_policies
 *
 * Returns the list of policies to be added for this relation, if any, based on
 * the type of command, the user executing the query, and the row_security GUC.
 *
 * Handles permissions checking related to row security policies and BYPASSRLS.
 *
 * Also provides a hook for extensions to add their own policies.
 *
 * If RLS is enabled for the relation, row security is 'on' or 'force', and
 * no policies are found, then a single 'default deny' policy is returned which
 * consists of just 'false'.
 */
static List *
pull_row_security_policies(CmdType cmd, Relation relation)
{
	List		   *policies = NIL;

	/* Nothing to do if the relation does not have RLS */
	if (!RelationGetForm(relation)->relhasrowsecurity)
		return NIL;

	/*
	 * Check permissions
	 *
	 * If the relation has row level security enabled and the row_security GUC
	 * is off, then check if the user has rights to bypass RLS for this
	 * relation.  Table owners can always bypass, as can any role with the
	 * BYPASSRLS capability.
	 */

	/*
	 * If the role is the table owner or a superuser, then we bypass RLS
	 * unless row_security is set to 'force'.
	 */
	if (row_security != ROW_SECURITY_FORCE
		&& (GetUserId() == RelationGetForm(relation)->relowner || superuser()))
		return NIL;

	/*
	 * If the row_security GUC is 'off' then check if the user has permission
	 * to bypass it.  Note that we have already handled the case where the user
	 * is the table owner above.
	 */
	if (row_security == ROW_SECURITY_OFF)
	{
		if (has_bypassrls_privilege(GetUserId()))
			/* OK to bypass */
			return NIL;
		else
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("insufficient privilege to bypass row security.")));
	}

	/*
	 * Row security is enabled for the relation and the row security GUC is
	 * either 'on' or 'force' here, so go ahead and add in any policies which
	 * exist on the table or which are pulled in from an extension.  If no
	 * policies are discovered, then we will create a single 'default deny'
	 * policy.
	 *
	 * First pull any row-security policies defined in the PG catalog, which
	 * have been populated into relation->rsdesc for us already.  We provide a
	 * hook below for extensions to add their own policies.
	 */
	if (relation->rsdesc)
	{
		ListCell		   *item;
		RowSecurityPolicy  *policy;

		foreach(item, relation->rsdesc->policies)
		{
			policy = (RowSecurityPolicy *) lfirst(item);

			/* Always add ALL policy if they exist. */
			if (policy->cmd == 0 && check_role_for_policy(policy))
				policies = lcons(policy, policies);

			/* Build the list of policies to return. */
			switch(cmd)
			{
				case CMD_SELECT:
					if (policy->cmd == ACL_SELECT_CHR
						&& check_role_for_policy(policy))
						policies = lcons(policy, policies);
					break;
				case CMD_INSERT:
					/* If INSERT then only need to add the WITH CHECK qual */
					if (policy->cmd == ACL_INSERT_CHR
						&& check_role_for_policy(policy))
						policies = lcons(policy, policies);
					break;
				case CMD_UPDATE:
					if (policy->cmd == ACL_UPDATE_CHR
						&& check_role_for_policy(policy))
						policies = lcons(policy, policies);
					break;
				case CMD_DELETE:
					if (policy->cmd == ACL_DELETE_CHR
						&& check_role_for_policy(policy))
						policies = lcons(policy, policies);
					break;
				default:
					elog(ERROR, "unrecognized command type.");
					break;
			}
		}
	}

	/*
	 * Also, ask extensions whether they want to apply their own
	 * row-security policies.
	 */
	if (row_security_policy_hook)
	{
		List   *temp;

		temp = (*row_security_policy_hook)(cmd, relation);
		if (temp != NIL)
			policies = lcons(temp, policies);
	}

	/*
	 * There should always be a policy applied.  If there are none defined then
	 * RelationBuildRowSecurity should have created a single default-deny
	 * policy.
	 */
	Assert (policies != NIL);

	return policies;
}

/*
 * check_role_for_policy -
 *   determines if the policy should be applied for the current role
 */
bool
check_role_for_policy(RowSecurityPolicy *policy)
{
	int			i;
	Oid		   *roles = (Oid *) ARR_DATA_PTR(policy->roles);

	/* Quick fall-thru for policies applied to all roles */
	if (roles[0] == ACL_ID_PUBLIC)
		return true;

	for (i = 0; i < ARR_DIMS(policy->roles)[0]; i++)
	{
		if (is_member_of_role(GetUserId(), roles[i]))
			return true;
	}

	return false;
}
