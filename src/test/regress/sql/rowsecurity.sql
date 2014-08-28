--
-- Test of Row-level security feature
--

-- Clean up in case a prior regression run failed

-- Suppress NOTICE messages when users/groups don't exist
SET client_min_messages TO 'warning';

DROP USER IF EXISTS rls_regress_user0;
DROP USER IF EXISTS rls_regress_user1;
DROP USER IF EXISTS rls_regress_user2;
DROP USER IF EXISTS rls_regress_exempt_user;
DROP ROLE IF EXISTS rls_regress_group1;
DROP ROLE IF EXISTS rls_regress_group2;

DROP SCHEMA IF EXISTS rls_regress_schema CASCADE;

RESET client_min_messages;

-- initial setup
CREATE USER rls_regress_user0;
CREATE USER rls_regress_user1;
CREATE USER rls_regress_user2;
CREATE USER rls_regress_exempt_user BYPASSRLS;
CREATE ROLE rls_regress_group1 NOLOGIN;
CREATE ROLE rls_regress_group2 NOLOGIN;

GRANT rls_regress_group1 TO rls_regress_user1;
GRANT rls_regress_group2 TO rls_regress_user2;

CREATE SCHEMA rls_regress_schema;
GRANT ALL ON SCHEMA rls_regress_schema to public;
SET search_path = rls_regress_schema;

-- setup of malicious function
CREATE OR REPLACE FUNCTION f_leak(text) RETURNS bool
    COST 0.0000001 LANGUAGE plpgsql
    AS 'BEGIN RAISE NOTICE ''f_leak => %'', $1; RETURN true; END';
GRANT EXECUTE ON FUNCTION f_leak(text) TO public;

-- BASIC Row-Level Security Scenario

SET SESSION AUTHORIZATION rls_regress_user0;
CREATE TABLE uaccount (
    pguser      name primary key,
    seclv       int
);
GRANT SELECT ON uaccount TO public;
INSERT INTO uaccount VALUES
    ('rls_regress_user0', 99),
    ('rls_regress_user1', 1),
    ('rls_regress_user2', 2),
    ('rls_regress_user3', 3);

CREATE TABLE category (
    cid        int primary key,
    cname      text
);
GRANT ALL ON category TO public;
INSERT INTO category VALUES
    (11, 'novel'),
    (22, 'science fiction'),
    (33, 'technology'),
    (44, 'manga');

CREATE TABLE document (
    did         int primary key,
    cid         int references category(cid),
    dlevel      int not null,
    dauthor     name,
    dtitle      text
);
GRANT ALL ON document TO public;
INSERT INTO document VALUES
    ( 1, 11, 1, 'rls_regress_user1', 'my first novel'),
    ( 2, 11, 2, 'rls_regress_user1', 'my second novel'),
    ( 3, 22, 2, 'rls_regress_user1', 'my science fiction'),
    ( 4, 44, 1, 'rls_regress_user1', 'my first manga'),
    ( 5, 44, 2, 'rls_regress_user1', 'my second manga'),
    ( 6, 22, 1, 'rls_regress_user2', 'great science fiction'),
    ( 7, 33, 2, 'rls_regress_user2', 'great technology book'),
    ( 8, 44, 1, 'rls_regress_user2', 'great manga');

-- user's security level must be higher that or equal to document's
CREATE POLICY p1 ON document
    USING (dlevel <= (SELECT seclv FROM uaccount WHERE pguser = current_user));

-- viewpoint from rls_regress_user1
SET SESSION AUTHORIZATION rls_regress_user1;
SELECT * FROM document WHERE f_leak(dtitle) ORDER BY did;
SELECT * FROM document NATURAL JOIN category WHERE f_leak(dtitle) ORDER BY did;

-- viewpoint from rls_regress_user2
SET SESSION AUTHORIZATION rls_regress_user2;
SELECT * FROM document WHERE f_leak(dtitle) ORDER BY did;
SELECT * FROM document NATURAL JOIN category WHERE f_leak(dtitle) ORDER BY did;

EXPLAIN (COSTS OFF) SELECT * FROM document WHERE f_leak(dtitle);
EXPLAIN (COSTS OFF) SELECT * FROM document NATURAL JOIN category WHERE f_leak(dtitle);

-- only owner can change row-level security
ALTER POLICY p1 ON document FOR ALL TO PUBLIC USING (true);    --fail
DROP POLICY p1 ON document;                  --fail

SET SESSION AUTHORIZATION rls_regress_user0;
ALTER POLICY p1 ON document FOR ALL TO PUBLIC USING (dauthor = current_user);

-- viewpoint from rls_regress_user1 again
SET SESSION AUTHORIZATION rls_regress_user1;
SELECT * FROM document WHERE f_leak(dtitle) ORDER BY did;
SELECT * FROM document NATURAL JOIN category WHERE f_leak(dtitle) ORDER by did;

-- viewpoint from rls_regres_user2 again
SET SESSION AUTHORIZATION rls_regress_user2;
SELECT * FROM document WHERE f_leak(dtitle) ORDER BY did;
SELECT * FROM document NATURAL JOIN category WHERE f_leak(dtitle) ORDER by did;

EXPLAIN (COSTS OFF) SELECT * FROM document WHERE f_leak(dtitle);
EXPLAIN (COSTS OFF) SELECT * FROM document NATURAL JOIN category WHERE f_leak(dtitle);

-- interaction of FK/PK constraints
SET SESSION AUTHORIZATION rls_regress_user0;
CREATE POLICY p2 ON category FOR ALL
    TO PUBLIC
    USING (CASE WHEN current_user = 'rls_regress_user1' THEN cid IN (11, 33)
           WHEN current_user = 'rls_regress_user2' THEN cid IN (22, 44)
           ELSE false END);

-- cannot delete PK referenced by invisible FK
SET SESSION AUTHORIZATION rls_regress_user1;
SELECT * FROM document d FULL OUTER JOIN category c on d.cid = c.cid;
DELETE FROM category WHERE cid = 33;    -- fails with FK violation

-- cannot insert FK referencing invisible PK
SET SESSION AUTHORIZATION rls_regress_user2;
SELECT * FROM document d FULL OUTER JOIN category c on d.cid = c.cid;
INSERT INTO document VALUES (10, 33, 1, current_user, 'hoge'); -- fail wil FK violation

-- UNIQUE or PRIMARY KEY constraint violation DOES reveal presence of row
SET SESSION AUTHORIZATION rls_regress_user1;
INSERT INTO document VALUES (8, 44, 1, 'rls_regress_user1', 'my third manga'); -- Must fail with unique violation, revealing presence of did we can't see
SELECT * FROM document WHERE did = 8; -- and confirm we can't see it

-- database superuser cannot bypass RLS policy when enabled
RESET SESSION AUTHORIZATION;
SET row_security TO ON;
SELECT * FROM document;
SELECT * FROM category;

-- database superuser can bypass RLS policy when disabled
RESET SESSION AUTHORIZATION;
SET row_security TO OFF;
SELECT * FROM document;
SELECT * FROM category;

-- database non-superuser with bypass privilege can bypass RLS policy when disabled
SET SESSION AUTHORIZATION rls_regress_exempt_user;
SET row_security TO OFF;
SELECT * FROM document;
SELECT * FROM category;

--
-- Table inheritance and RLS policy
--
SET SESSION AUTHORIZATION rls_regress_user0;

SET row_security TO ON;

CREATE TABLE t1 (a int, junk1 text, b text) WITH OIDS;
ALTER TABLE t1 DROP COLUMN junk1;    -- just a disturbing factor
GRANT ALL ON t1 TO public;

COPY t1 FROM stdin WITH (oids);
101	1	aaa
102	2	bbb
103	3	ccc
104	4	ddd
\.

CREATE TABLE t2 (c float) INHERITS (t1);
COPY t2 FROM stdin WITH (oids);
201	1	abc	1.1
202	2	bcd	2.2
203	3	cde	3.3
204	4	def	4.4
\.

CREATE TABLE t3 (c text, b text, a int) WITH OIDS;
ALTER TABLE t3 INHERIT t1;
COPY t3(a,b,c) FROM stdin WITH (oids);
301	1	xxx	X
302	2	yyy	Y
303	3	zzz	Z
\.

CREATE POLICY p1 ON t1 FOR ALL TO PUBLIC USING (a % 2 = 0); -- be even number
CREATE POLICY p2 ON t2 FOR ALL TO PUBLIC USING (a % 2 = 1); -- be odd number

SELECT * FROM t1;
EXPLAIN (COSTS OFF) SELECT * FROM t1;

SELECT * FROM t1 WHERE f_leak(b);
EXPLAIN (COSTS OFF) SELECT * FROM t1 WHERE f_leak(b);

-- reference to system column
SELECT oid, * FROM t1;
EXPLAIN (COSTS OFF) SELECT *, t1 FROM t1;

-- reference to whole-row reference
SELECT *, t1 FROM t1;
EXPLAIN (COSTS OFF) SELECT *, t1 FROM t1;

-- for share/update lock
SELECT * FROM t1 FOR SHARE;
EXPLAIN (COSTS OFF) SELECT * FROM t1 FOR SHARE;

SELECT * FROM t1 WHERE f_leak(b) FOR SHARE;
EXPLAIN (COSTS OFF) SELECT * FROM t1 WHERE f_leak(b) FOR SHARE;

-- superuser is allowed to bypass RLS checks
RESET SESSION AUTHORIZATION;
SET row_security TO OFF;
SELECT * FROM t1 WHERE f_leak(b);
EXPLAIN (COSTS OFF) SELECT * FROM t1 WHERE f_leak(b);

-- non-superuser with bypass privilege can bypass RLS policy when disabled
SET SESSION AUTHORIZATION rls_regress_exempt_user;
SET row_security TO OFF;
SELECT * FROM t1 WHERE f_leak(b);
EXPLAIN (COSTS OFF) SELECT * FROM t1 WHERE f_leak(b);

----- Dependencies -----
SET SESSION AUTHORIZATION rls_regress_user0;
SET row_security TO ON;

CREATE TABLE dependee (x integer, y integer);

CREATE TABLE dependent (x integer, y integer);
CREATE POLICY d1 ON dependent FOR ALL
    TO PUBLIC
    USING (x = (SELECT d.x FROM dependee d WHERE d.y = y));

DROP TABLE dependee; -- Should fail without CASCADE due to dependency on row-security qual?

DROP TABLE dependee CASCADE;

EXPLAIN (COSTS OFF) SELECT * FROM dependent; -- After drop, should be unqualified

-----   RECURSION    ----

--
-- Simple recursion
--
CREATE TABLE rec1 (x integer, y integer);
CREATE POLICY r1 ON rec1 FOR ALL
    TO PUBLIC
    USING (x = (SELECT r.x FROM rec1 r WHERE y = r.y));

SELECT * FROM rec1; -- fail, direct recursion

--
-- Mutual recursion
--
CREATE TABLE rec2 (a integer, b integer);
ALTER POLICY r1 ON rec1 FOR ALL
    TO PUBLIC
    USING (x = (SELECT a FROM rec2 WHERE b = y));
CREATE POLICY r2 ON rec2 FOR ALL
    TO PUBLIC
    USING (a = (SELECT x FROM rec1 WHERE y = b));

SELECT * FROM rec1;    -- fail, mutual recursion

--
-- Mutual recursion via views
--
CREATE VIEW rec1v AS SELECT * FROM rec1;
CREATE VIEW rec2v AS SELECT * FROM rec2;
ALTER POLICY r1 ON rec1 FOR ALL
    TO PUBLIC
    USING (x = (SELECT a FROM rec2v WHERE b = y));
ALTER POLICY r2 ON rec2 FOR ALL
    TO PUBLIC
    USING (a = (SELECT x FROM rec1v WHERE y = b));

SELECT * FROM rec1;    -- fail, mutual recursion via views

--
-- Mutual recursion via .s.b views
-- 

DROP VIEW rec1v, rec2v CASCADE;
CREATE VIEW rec1v WITH (security_barrier) AS SELECT * FROM rec1;
CREATE VIEW rec2v WITH (security_barrier) AS SELECT * FROM rec2;
CREATE POLICY r1 ON rec1 FOR ALL
    TO PUBLIC
    USING (x = (SELECT a FROM rec2v WHERE b = y));
CREATE POLICY r2 ON rec2 FOR ALL
    TO PUBLIC
    USING (a = (SELECT x FROM rec1v WHERE y = b));

SELECT * FROM rec1;    -- fail, mutual recursion via s.b. views

--
-- recursive RLS and VIEWs in policy
--
CREATE TABLE s1 (a int, b text);
INSERT INTO s1 (SELECT x, md5(x::text) FROM generate_series(-10,10) x);

CREATE TABLE s2 (x int, y text);
INSERT INTO s2 (SELECT x, md5(x::text) FROM generate_series(-6,6) x);
CREATE VIEW v2 AS SELECT * FROM s2 WHERE y like '%af%';

CREATE POLICY p1 ON s1 FOR ALL
    TO PUBLIC
    USING (a in (select x from s2 where y like '%2f%'));

CREATE POLICY p2 ON s2 FOR ALL
    TO PUBLIC
    USING (x in (select a from s1 where b like '%22%'));

SELECT * FROM s1 WHERE f_leak(b);	-- fail (infinite recursion)

ALTER POLICY p2 ON s2 FOR ALL TO PUBLIC USING (x % 2 = 0);

SELECT * FROM s1 WHERE f_leak(b);	-- OK
EXPLAIN (COSTS OFF) SELECT * FROM only s1 WHERE f_leak(b);

ALTER POLICY p1 ON s1 FOR ALL
    TO PUBLIC
    USING (a in (select x from v2));		-- using VIEW in RLS policy
SELECT * FROM s1 WHERE f_leak(b);	-- OK
EXPLAIN (COSTS OFF) SELECT * FROM s1 WHERE f_leak(b);

SELECT (SELECT x FROM s1 LIMIT 1) xx, * FROM s2 WHERE y like '%28%';
EXPLAIN (COSTS OFF) SELECT (SELECT x FROM s1 LIMIT 1) xx, * FROM s2 WHERE y like '%28%';

ALTER POLICY p2 ON s2 FOR ALL
    TO PUBLIC
    USING (x in (select a from s1 where b like '%d2%'));
SELECT * FROM s1 WHERE f_leak(b);	-- fail (infinite recursion via view)

-- prepared statement with rls_regress_user0 privilege
PREPARE p1(int) AS SELECT * FROM t1 WHERE a <= $1;
EXECUTE p1(2);
EXPLAIN (COSTS OFF) EXECUTE p1(2);

-- superuser is allowed to bypass RLS checks
RESET SESSION AUTHORIZATION;
SET row_security TO OFF;
SELECT * FROM t1 WHERE f_leak(b);
EXPLAIN (COSTS OFF) SELECT * FROM t1 WHERE f_leak(b);

-- plan cache should be invalidated
EXECUTE p1(2);
EXPLAIN (COSTS OFF) EXECUTE p1(2);

PREPARE p2(int) AS SELECT * FROM t1 WHERE a = $1;
EXECUTE p2(2);
EXPLAIN (COSTS OFF) EXECUTE p2(2);

-- also, case when privilege switch from superuser
SET SESSION AUTHORIZATION rls_regress_user0;
SET row_security TO ON;
EXECUTE p2(2);
EXPLAIN (COSTS OFF) EXECUTE p2(2);

--
-- UPDATE / DELETE and Row-level security
--
SET SESSION AUTHORIZATION rls_regress_user0;
EXPLAIN (COSTS OFF) UPDATE t1 SET b = b || b WHERE f_leak(b);
UPDATE t1 SET b = b || b WHERE f_leak(b);

EXPLAIN (COSTS OFF) UPDATE only t1 SET b = b || '_updt' WHERE f_leak(b);
UPDATE only t1 SET b = b || '_updt' WHERE f_leak(b);

-- returning clause with system column
UPDATE only t1 SET b = b WHERE f_leak(b) RETURNING oid, *, t1;
UPDATE t1 SET b = b WHERE f_leak(b) RETURNING *;
UPDATE t1 SET b = b WHERE f_leak(b) RETURNING oid, *, t1;

RESET SESSION AUTHORIZATION;
SET ROW SECURITY OFF;
SELECT * FROM t1;

SET SESSION AUTHORIZATION rls_regress_user0;
SET ROW SECURITY ON;
EXPLAIN (COSTS OFF) DELETE FROM only t1 WHERE f_leak(b);
EXPLAIN (COSTS OFF) DELETE FROM t1 WHERE f_leak(b);

DELETE FROM only t1 WHERE f_leak(b) RETURNING oid, *, t1;
DELETE FROM t1 WHERE f_leak(b) RETURNING oid, *, t1;

--
-- ROLE/GROUP
--
SET SESSION AUTHORIZATION rls_regress_user0;

CREATE TABLE z1 (a int, b text) WITH OIDS;
GRANT ALL ON z1 TO PUBLIC;

COPY z1 FROM STDIN WITH (OIDS);
101	1	aaa
102	2	bbb
103	3	ccc
104	4	ddd
\.

CREATE POLICY p1 ON z1 TO rls_regress_group1
    USING (a % 2 = 0);
CREATE POLICY p2 ON z1 TO rls_regress_group2
    USING (a % 2 = 1);

SET SESSION AUTHORIZATION rls_regress_user1;
SELECT * FROM z1 WHERE f_leak(b);

SET ROLE rls_regress_group1;
SELECT * FROM z1 WHERE f_leak(b);

SET SESSION AUTHORIZATION rls_regress_user2;
SELECT * FROM z1 WHERE f_leak(b);

SET ROLE rls_regress_group2;
SELECT * FROM z1 WHERE f_leak(b);

--
-- Command specific
--
SET SESSION AUTHORIZATION rls_regress_user0;

CREATE TABLE x1 (a int, b text, c text);
GRANT ALL ON x1 TO PUBLIC;

INSERT INTO x1 VALUES
    (1, 'abc', 'rls_regress_user1'),
    (2, 'bcd', 'rls_regress_user1'),
    (3, 'cde', 'rls_regress_user2'),
    (4, 'def', 'rls_regress_user2'),
    (5, 'efg', 'rls_regress_user1'),
    (6, 'fgh', 'rls_regress_user1'),
    (7, 'fgh', 'rls_regress_user2'),
    (8, 'fgh', 'rls_regress_user2');

CREATE POLICY p0 ON x1 FOR ALL USING (c = current_user);
CREATE POLICY p1 ON x1 FOR SELECT USING (a % 2 = 0);
CREATE POLICY p2 ON x1 FOR INSERT USING (a % 2 = 1);
CREATE POLICY p3 ON x1 FOR UPDATE USING (a > 0);
CREATE POLICY p4 ON x1 FOR DELETE USING (a < COUNT(x1));

SET SESSION AUTHORIZATION rls_regress_user1;
SELECT * FROM x1;
UPDATE x1 SET b = b || '_updt' RETURNING *;
DELETE FROM x1 WHERE f_leak(b) RETURNING *;

SET SESSION AUTHORIZATION rls_regress_user2;
SELECT * FROM x1;
UPDATE x1 SET b = b || '_updt' RETURNING *;
DELETE FROM x1 WHERE f_leak(b) RETURNING *;

--
-- Duplicate Policy Names
--
SET SESSION AUTHORIZATION rls_regress_user0;
CREATE TABLE y1 (a int, b int);
CREATE TABLE y2 (a int, b int);

CREATE POLICY p1 ON y1 FOR ALL USING (a % 2 = 0);
CREATE POLICY p1 ON y1 FOR SELECT USING (a % 2 = 1);  --fail
CREATE POLICY p1 ON y2 FOR ALL USING (a % 2 = 0);  --OK

--
-- Test psql \dt+ command
--
SET SESSION AUTHORIZATION rls_regress_user0;
DROP POLICY p2 ON category;  -- too long qual
\dt+

--
-- Clean up objects
--
RESET SESSION AUTHORIZATION;

DROP SCHEMA rls_regress_schema CASCADE;

DROP USER rls_regress_user0;
DROP USER rls_regress_user1;
DROP USER rls_regress_user2;
