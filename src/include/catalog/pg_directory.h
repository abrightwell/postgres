/*
 * pg_directory.h
 *   definition of the system catalog for directory permissions (pg_directory)
 *
 * Portions Copyright (c) 1996-2012, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 */
#ifndef PG_DIRECTORY_H
#define PG_DIRECTORY_H

#include "catalog/genbki.h"

/* ----------------
 *		pg_directory definition.  cpp turns this into
 *		typedef struct FormData_pg_directory
 * ----------------
 */
#define DirectoryRelationId		6100

CATALOG(pg_directory,6100)
{
	NameData		diralias;	/* directory alias */
	text			dirpath;	/* directory path */
	Oid				dirowner;	/* directory owner */
#ifdef CATALOG_VARLEN
	aclitem			diracl[1];	/* directory permissions */
#endif
} FormData_pg_directory;

/* ----------------
 *		Form_pg_directory corresponds to a pointer to a row with
 *		the format of pg_directory relation.
 * ----------------
 */
typedef FormData_pg_directory *Form_pg_directory;

/* ----------------
 * 		compiler constants for pg_directory
 * ----------------
 */
#define Natts_pg_directory				4
#define Anum_pg_directory_diralias		1
#define Anum_pg_directory_dirpath		2
#define Anum_pg_directory_dirowner		3
#define Anum_pg_directory_diracl		4

#endif   /* PG_DIRECTORY_H */