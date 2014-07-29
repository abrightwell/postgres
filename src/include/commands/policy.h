/*-------------------------------------------------------------------------
 *
 * policy.h
 *	  prototypes for policy.c.
 *
 *
 * Portions Copyright (c) 1996-2014, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/commands/policy.h
 *
 *-------------------------------------------------------------------------
 */

#ifndef POLICY_H
#define POLICY_H

#include "nodes/parsenodes.h"

extern void RelationBuildRowSecurity(Relation relation);

extern void RemovePolicyById(Oid policy_id);

extern Oid CreatePolicy(CreatePolicyStmt *stmt);
extern Oid AlterPolicy(AlterPolicyStmt *stmt);
extern void DropPolicy(DropPolicyStmt *stmt);

#endif   /* POLICY_H */
