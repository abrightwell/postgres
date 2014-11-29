/*-------------------------------------------------------------------------
 *
 * pg_authid.h
 *	  definition of the system "authorization identifier" relation (pg_authid)
 *	  along with the relation's initial contents.
 *
 *	  pg_shadow and pg_group are now publicly accessible views on pg_authid.
 *
 *
 * Portions Copyright (c) 1996-2014, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/catalog/pg_authid.h
 *
 * NOTES
 *	  the genbki.pl script reads this file and generates .bki
 *	  information from the DATA() statements.
 *
 *-------------------------------------------------------------------------
 */
#ifndef PG_AUTHID_H
#define PG_AUTHID_H

#include "catalog/genbki.h"
#include "nodes/parsenodes.h"

/*
 * The CATALOG definition has to refer to the type of rolvaliduntil as
 * "timestamptz" (lower case) so that bootstrap mode recognizes it.  But
 * the C header files define this type as TimestampTz.  Since the field is
 * potentially-null and therefore can't be accessed directly from C code,
 * there is no particular need for the C struct definition to show the
 * field type as TimestampTz --- instead we just make it int.
 */
#define timestamptz int


/* ----------------
 *		pg_authid definition.  cpp turns this into
 *		typedef struct FormData_pg_authid
 * ----------------
 */
#define AuthIdRelationId	1260
#define AuthIdRelation_Rowtype_Id	2842

CATALOG(pg_authid,1260) BKI_SHARED_RELATION BKI_ROWTYPE_OID(2842) BKI_SCHEMA_MACRO
{
	NameData	rolname;		/* name of role */
	int64		rolattr;		/* role attribute bitmask */
	int32		rolconnlimit;	/* max connections allowed (-1=no limit) */
	/* remaining fields may be null; use heap_getattr to read them! */
	text		rolpassword;	/* password, if any */
	timestamptz rolvaliduntil;	/* password expiration time, if any */
} FormData_pg_authid;

#undef timestamptz


/* ----------------
 *		Form_pg_authid corresponds to a pointer to a tuple with
 *		the format of pg_authid relation.
 * ----------------
 */
typedef FormData_pg_authid *Form_pg_authid;

/* ----------------
 *		compiler constants for pg_authid
 * ----------------
 */
#define Natts_pg_authid					5
#define Anum_pg_authid_rolname			1
#define Anum_pg_authid_rolattr			2
#define Anum_pg_authid_rolconnlimit		3
#define Anum_pg_authid_rolpassword		4
#define Anum_pg_authid_rolvaliduntil	5

/* ----------------
 * Role attributes are encoded so that we can OR them together in a bitmask.
 * The present representation of RoleAttr (defined in acl.h) limits us to 64
 * distinct rights.
 * ----------------
 */
#define ROLE_ATTR_SUPERUSER		(1<<0)
#define ROLE_ATTR_INHERIT		(1<<1)
#define ROLE_ATTR_CREATEROLE	(1<<2)
#define ROLE_ATTR_CREATEDB		(1<<3)
#define ROLE_ATTR_CATUPDATE		(1<<4)
#define ROLE_ATTR_CANLOGIN		(1<<5)
#define ROLE_ATTR_REPLICATION	(1<<6)
#define ROLE_ATTR_BYPASSRLS		(1<<7)
#define N_ROLE_ATTRIBUTES		8		/* 1 plus the last 1<<x */
#define ROLE_ATTR_NONE			0
#define ROLE_ATTR_ALL			255		/* All currently available attributes. */

/* ----------------
 *		initial contents of pg_authid
 *
 * The uppercase quantities will be replaced at initdb time with
 * user choices.
 *
 * PGROLATTRALL is substituted by genbki.pl to use the value defined by
 * ROLE_ATTR_ALL.
 * ----------------
 */
DATA(insert OID = 10 ( "POSTGRES" PGROLATTRALL -1 _null_ _null_));

#define BOOTSTRAP_SUPERUSERID 10

#endif   /* PG_AUTHID_H */
