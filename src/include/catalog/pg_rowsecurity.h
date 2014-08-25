/*
 * pg_rowsecurity.h
 *   definition of the system catalog for row-security policy (pg_rowsecurity)
 *
 * Portions Copyright (c) 1996-2012, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 */
#ifndef PG_ROWSECURITY_H
#define PG_ROWSECURITY_H

#include "catalog/genbki.h"
#include "nodes/primnodes.h"
#include "utils/array.h"
#include "utils/memutils.h"
#include "utils/relcache.h"

/* ----------------
 *		pg_rowsecurity definition. cpp turns this into
 *		typedef struct FormData_pg_rowsecurity
 * ----------------
 */
#define RowSecurityRelationId	5000

CATALOG(pg_rowsecurity,5000)
{
	NameData		rsecpolname;	/* Policy name. */
	Oid				rsecrelid;		/* Oid of the relation with policy. */
	char			rseccmd;		/* One of ROWSECURITY_CMD_* below */

#ifdef CATALOG_VARLEN
	Oid				rsecroles[1]	/* Roles associated with policy */
	pg_node_tree	rsecqual;		/* Policy quals. */
#endif
} FormData_pg_rowsecurity;

/* ----------------
 *		Form_pg_rowsecurity corresponds to a pointer to a row with
 *		the format of pg_rowsecurity relation.
 * ----------------
 */
typedef FormData_pg_rowsecurity *Form_pg_rowsecurity;

/* ----------------
 * 		compiler constants for pg_rowsecurity
 * ----------------
 */
#define Natts_pg_rowsecurity				5
#define Anum_pg_rowsecurity_rsecpolname		1
#define Anum_pg_rowsecurity_rsecrelid		2
#define Anum_pg_rowsecurity_rseccmd			3
#define Anum_pg_rowsecurity_rsecroles		4
#define Anum_pg_rowsecurity_rsecqual		5

#define ROWSECURITY_CMD_ALL			'a'
#define ROWSECURITY_CMD_SELECT		's'
#define ROWSECURITY_CMD_INSERT		'i'
#define ROWSECURITY_CMD_UPDATE		'u'
#define ROWSECURITY_CMD_DELETE		'd'

typedef struct
{
	Oid				rsecid;
	ArrayType	   *roles;
	Expr		   *qual;
	bool			hassublinks;
} RowSecurityEntry;

typedef struct
{
	char			   *policy_name;
	RowSecurityEntry   *rsall;		/* row-security policy for ALL */
	RowSecurityEntry   *rsselect;	/* row-security policy for SELECT */
	RowSecurityEntry   *rsinsert;	/* row-security policy for INSERT */
	RowSecurityEntry   *rsupdate;	/* row-security policy for UPDATE */
	RowSecurityEntry   *rsdelete;	/* row-security policy for DELETE */
} RowSecurityPolicy;

typedef struct
{
	MemoryContext		rscxt;		/* row-security memory context */
	List			   *policies;	/* list of row-security policies */
} RowSecurityDesc;

/* GUC variable */
extern int row_security;

/* Possible values for row_security GUC */
typedef enum
{
	ROW_SECURITY_OFF,
	ROW_SECURITY_ON
} RowSecurityType;

#endif  /* PG_ROWSECURITY_H */
