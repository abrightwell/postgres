/*-------------------------------------------------------------------------
 *
 * genfile.c
 *		Functions for direct access to files
 *
 *
 * Copyright (c) 2004-2014, PostgreSQL Global Development Group
 *
 * Author: Andreas Pflug <pgadmin@pse-consulting.de>
 *
 * IDENTIFICATION
 *	  src/backend/utils/adt/genfile.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

#include "access/htup_details.h"
#include "catalog/pg_type.h"
#include "commands/directory.h"
#include "funcapi.h"
#include "mb/pg_wchar.h"
#include "miscadmin.h"
#include "postmaster/syslogger.h"
#include "storage/fd.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#include "utils/timestamp.h"

typedef struct
{
	char	   *location;
	DIR		   *dirdesc;
} directory_fctx;

/*
 * Check the directory permissions for the provided filename/path.
 *
 * The filename must be an absolute path to the file.
 */
static void
check_directory_permissions(char *directory)
{
	Oid			dir_id;
	AclResult	aclresult;

	/* Do not allow relative paths */
	if (!is_absolute_path(directory))
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("relative path not allowed")));

	/* Search for directory in pg_directory */
	dir_id = get_directory_oid_by_path(directory);

	/*
	 * If an entry does not exist for the path in pg_directory then raise
	 * an error.
	 */
	if (!OidIsValid(dir_id))
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("directory entry for \"%s\" does not exist",
						directory)));

	/* Check directory entry permissions */
	aclresult = pg_directory_aclcheck(dir_id, GetUserId(), ACL_SELECT);

	/* If the current user has insufficient privileges then raise an error */
	if (aclresult != ACLCHECK_OK)
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must have read permissions on parent directory")));
}


/*
 * Read a section of a file, returning it as bytea
 *
 * Caller is responsible for all permissions checking.
 *
 * We read the whole of the file when bytes_to_read is negative.
 */
bytea *
read_binary_file(const char *filename, int64 seek_offset, int64 bytes_to_read)
{
	bytea	   *buf;
	size_t		nbytes;
	FILE	   *file;

	if (bytes_to_read < 0)
	{
		if (seek_offset < 0)
			bytes_to_read = -seek_offset;
		else
		{
			struct stat fst;

			if (stat(filename, &fst) < 0)
				ereport(ERROR,
						(errcode_for_file_access(),
						 errmsg("could not stat file \"%s\": %m", filename)));

			bytes_to_read = fst.st_size - seek_offset;
		}
	}

	/* not sure why anyone thought that int64 length was a good idea */
	if (bytes_to_read > (MaxAllocSize - VARHDRSZ))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("requested length too large")));

	if ((file = AllocateFile(filename, PG_BINARY_R)) == NULL)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not open file \"%s\" for reading: %m",
						filename)));

	if (fseeko(file, (off_t) seek_offset,
			   (seek_offset >= 0) ? SEEK_SET : SEEK_END) != 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not seek in file \"%s\": %m", filename)));

	buf = (bytea *) palloc((Size) bytes_to_read + VARHDRSZ);

	nbytes = fread(VARDATA(buf), 1, (size_t) bytes_to_read, file);

	if (ferror(file))
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not read file \"%s\": %m", filename)));

	SET_VARSIZE(buf, nbytes + VARHDRSZ);

	FreeFile(file);

	return buf;
}

/*
 * Similar to read_binary_file, but we verify that the contents are valid
 * in the database encoding.
 */
static text *
read_text_file(const char *filename, int64 seek_offset, int64 bytes_to_read)
{
	bytea	   *buf;

	buf = read_binary_file(filename, seek_offset, bytes_to_read);

	/* Make sure the input is valid */
	pg_verifymbstr(VARDATA(buf), VARSIZE(buf) - VARHDRSZ, false);

	/* OK, we can cast it to text safely */
	return (text *) buf;
}

/*
 * Read a section of a file, returning it as text
 */
Datum
pg_read_file(PG_FUNCTION_ARGS)
{
	text	   *filename_t = PG_GETARG_TEXT_P(0);
	int64		seek_offset = PG_GETARG_INT64(1);
	int64		bytes_to_read = PG_GETARG_INT64(2);
	char	   *filename;
	char	   *directory;

	/* Convert and cleanup the filename */
	filename = text_to_cstring(filename_t);
	canonicalize_path(filename);

	/* Superuser is always allowed to bypass directory permissions */
	if (!superuser())
	{
		directory = pstrdup(filename);
		get_parent_directory(directory);
		check_directory_permissions(directory);
	}

	if (bytes_to_read < 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("requested length cannot be negative")));

	PG_RETURN_TEXT_P(read_text_file(filename, seek_offset, bytes_to_read));
}

/*
 * Read the whole of a file, returning it as text
 */
Datum
pg_read_file_all(PG_FUNCTION_ARGS)
{
	text	   *filename_t = PG_GETARG_TEXT_P(0);
	char	   *filename;
	char	   *directory;

	/* Convert and cleanup the filename */
	filename = text_to_cstring(filename_t);
	canonicalize_path(filename);

	/* Superuser is always allowed to bypass directory permissions */
	if (!superuser())
	{
		directory = pstrdup(filename);
		get_parent_directory(directory);
		check_directory_permissions(directory);
	}

	PG_RETURN_TEXT_P(read_text_file(filename, 0, -1));
}

/*
 * Read a section of a file, returning it as bytea
 */
Datum
pg_read_binary_file(PG_FUNCTION_ARGS)
{
	text	   *filename_t = PG_GETARG_TEXT_P(0);
	int64		seek_offset = PG_GETARG_INT64(1);
	int64		bytes_to_read = PG_GETARG_INT64(2);
	char	   *filename;
	char	   *directory;

	/* Convert and cleanup the filename */
	filename = text_to_cstring(filename_t);
	canonicalize_path(filename);

	/* Superuser is always allowed to bypass directory permissions */
	if (!superuser())
	{
		directory = pstrdup(filename);
		get_parent_directory(directory);
		check_directory_permissions(directory);
	}

	if (bytes_to_read < 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("requested length cannot be negative")));

	PG_RETURN_BYTEA_P(read_binary_file(filename, seek_offset, bytes_to_read));
}

/*
 * Read the whole of a file, returning it as bytea
 */
Datum
pg_read_binary_file_all(PG_FUNCTION_ARGS)
{
	text	   *filename_t = PG_GETARG_TEXT_P(0);
	char	   *filename;
	char	   *directory;

	/* Convert and cleanup the filename */
	filename = text_to_cstring(filename_t);
	canonicalize_path(filename);

	/* Superuser is always allowed to bypass directory permissions */
	if (!superuser())
	{
		directory = pstrdup(filename);
		get_parent_directory(directory);
		check_directory_permissions(directory);
	}

	PG_RETURN_BYTEA_P(read_binary_file(filename, 0, -1));
}

/*
 * stat a file
 */
Datum
pg_stat_file(PG_FUNCTION_ARGS)
{
	text	   *filename_t = PG_GETARG_TEXT_P(0);
	char	   *filename;
	char	   *directory;
	struct stat fst;
	Datum		values[6];
	bool		isnull[6];
	HeapTuple	tuple;
	TupleDesc	tupdesc;

	filename = text_to_cstring(filename_t);
	canonicalize_path(filename);

	/* Superuser is always allowed to bypass directory permissions */
	if (!superuser())
	{
		directory = pstrdup(filename);
		get_parent_directory(directory);
		check_directory_permissions(directory);
	}

	if (stat(filename, &fst) < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not stat file \"%s\": %m", filename)));

	/*
	 * This record type had better match the output parameters declared for me
	 * in pg_proc.h.
	 */
	tupdesc = CreateTemplateTupleDesc(6, false);
	TupleDescInitEntry(tupdesc, (AttrNumber) 1,
					   "size", INT8OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 2,
					   "access", TIMESTAMPTZOID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 3,
					   "modification", TIMESTAMPTZOID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 4,
					   "change", TIMESTAMPTZOID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 5,
					   "creation", TIMESTAMPTZOID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 6,
					   "isdir", BOOLOID, -1, 0);
	BlessTupleDesc(tupdesc);

	memset(isnull, false, sizeof(isnull));

	values[0] = Int64GetDatum((int64) fst.st_size);
	values[1] = TimestampTzGetDatum(time_t_to_timestamptz(fst.st_atime));
	values[2] = TimestampTzGetDatum(time_t_to_timestamptz(fst.st_mtime));
	/* Unix has file status change time, while Win32 has creation time */
#if !defined(WIN32) && !defined(__CYGWIN__)
	values[3] = TimestampTzGetDatum(time_t_to_timestamptz(fst.st_ctime));
	isnull[4] = true;
#else
	isnull[3] = true;
	values[4] = TimestampTzGetDatum(time_t_to_timestamptz(fst.st_ctime));
#endif
	values[5] = BoolGetDatum(S_ISDIR(fst.st_mode));

	tuple = heap_form_tuple(tupdesc, values, isnull);

	pfree(filename);

	PG_RETURN_DATUM(HeapTupleGetDatum(tuple));
}


/*
 * List a directory (returns the filenames only)
 */
Datum
pg_ls_dir(PG_FUNCTION_ARGS)
{
	FuncCallContext *funcctx;
	struct dirent *de;
	directory_fctx *fctx;

	if (SRF_IS_FIRSTCALL())
	{
		MemoryContext oldcontext;

		funcctx = SRF_FIRSTCALL_INIT();
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		fctx = palloc(sizeof(directory_fctx));
		fctx->location = text_to_cstring(PG_GETARG_TEXT_P(0));
		canonicalize_path(fctx->location);

		/* Superuser is always allowed to bypass directory permissions */
		if (!superuser())
			check_directory_permissions(fctx->location);

		fctx->dirdesc = AllocateDir(fctx->location);

		if (!fctx->dirdesc)
			ereport(ERROR,
					(errcode_for_file_access(),
					 errmsg("could not open directory \"%s\": %m",
							fctx->location)));

		funcctx->user_fctx = fctx;
		MemoryContextSwitchTo(oldcontext);
	}

	funcctx = SRF_PERCALL_SETUP();
	fctx = (directory_fctx *) funcctx->user_fctx;

	while ((de = ReadDir(fctx->dirdesc, fctx->location)) != NULL)
	{
		if (strcmp(de->d_name, ".") == 0 ||
			strcmp(de->d_name, "..") == 0)
			continue;

		SRF_RETURN_NEXT(funcctx, CStringGetTextDatum(de->d_name));
	}

	FreeDir(fctx->dirdesc);

	SRF_RETURN_DONE(funcctx);
}
