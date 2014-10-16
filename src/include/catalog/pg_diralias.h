/*
 * pg_diralias.h
 *   definition of the system catalog for directory permissions (pg_diralias)
 *
 * Portions Copyright (c) 1996-2012, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 */
#ifndef PG_DIRALIAS_H
#define PG_DIRALIAS_H

#include "catalog/genbki.h"

/* ----------------
 *		pg_diralias definition.  cpp turns this into
 *		typedef struct FormData_pg_diralias
 * ----------------
 */
#define DirAliasRelationId		6100

CATALOG(pg_diralias,6100)
{
	NameData		dirname;	/* directory alias name */
	text			dirpath;	/* directory path */
#ifdef CATALOG_VARLEN
	aclitem			diracl[1];	/* directory permissions */
#endif
} FormData_pg_diralias;

/* ----------------
 *		Form_pg_diralias corresponds to a pointer to a row with
 *		the format of pg_diralias relation.
 * ----------------
 */
typedef FormData_pg_diralias *Form_pg_diralias;

/* ----------------
 * 		compiler constants for pg_diralias
 * ----------------
 */
#define Natts_pg_diralias				3
#define Anum_pg_diralias_dirname		1
#define Anum_pg_diralias_dirpath		2
#define Anum_pg_diralias_diracl			3

#endif   /* PG_DIRALIAS_H */