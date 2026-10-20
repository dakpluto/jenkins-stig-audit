-- Read-only access inventory. Keep defaults (NULL ACLs) distinct from empty ACLs.
WITH objects(kind, schema_name, object_name, owner_oid, acl, acl_kind) AS (
  SELECT 'databases', '', datname::text, datdba, datacl, 'd'::"char"
    FROM pg_database WHERE datname = current_database()
  UNION ALL
  SELECT 'schemas', '', nspname::text, nspowner, nspacl, 'n'::"char"
    FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname <> 'information_schema'
  UNION ALL
  SELECT CASE WHEN c.relkind = 'S' THEN 'sequences' ELSE 'tables' END,
         n.nspname::text, c.relname::text, c.relowner, c.relacl,
         CASE WHEN c.relkind = 'S' THEN 'S' ELSE 'r' END::"char"
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
      AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
  UNION ALL
  SELECT 'columns', n.nspname::text, quote_ident(c.relname) || '.' || quote_ident(a.attname),
         c.relowner, COALESCE(a.attacl, '{}'::aclitem[]), 'c'::"char"
    FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
      AND a.attnum > 0 AND NOT a.attisdropped AND a.attacl IS NOT NULL
  UNION ALL
  SELECT 'functions', n.nspname::text,
         quote_ident(p.proname) || '(' || pg_get_function_identity_arguments(p.oid) || ')',
         p.proowner, p.proacl, 'f'::"char"
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
  UNION ALL
  SELECT 'types', n.nspname::text, t.typname::text, t.typowner, t.typacl, 'T'::"char"
    FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
    WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
  UNION ALL
  SELECT 'languages', '', lanname::text, lanowner, lanacl, 'l'::"char"
    FROM pg_language WHERE lanpltrusted
  UNION ALL
  SELECT 'foreign_data_wrappers', '', fdwname::text, fdwowner, fdwacl, 'F'::"char"
    FROM pg_foreign_data_wrapper
  UNION ALL
  SELECT 'foreign_servers', '', srvname::text, srvowner, srvacl, 's'::"char"
    FROM pg_foreign_server
  UNION ALL
  SELECT 'large_objects', '', oid::text, lomowner, lomacl, 'L'::"char"
    FROM pg_largeobject_metadata
), access_rows AS (
  SELECT o.kind AS objects, o.schema_name AS schema, o.object_name AS object,
         CASE WHEN a.grantee = 0 THEN 'PUBLIC'
              WHEN a.grantee = 'pg_database_owner'::regrole::oid
                THEN (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database())
              ELSE pg_get_userbyid(a.grantee) END AS role,
         a.privilege_type AS privilege, a.is_grantable AS grant_option, ''::text AS creator
    FROM objects o CROSS JOIN LATERAL aclexplode(COALESCE(o.acl, acldefault(o.acl_kind, o.owner_oid))) a
  UNION ALL
  SELECT kind, schema_name, object_name,
         CASE WHEN owner_oid = 'pg_database_owner'::regrole::oid
           THEN (SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database())
           ELSE pg_get_userbyid(owner_oid) END, 'OWNER', false, ''
    FROM objects WHERE kind <> 'columns'
  UNION ALL
  SELECT 'default_' || CASE d.defaclobjtype WHEN 'r' THEN 'tables' WHEN 'S' THEN 'sequences'
           WHEN 'f' THEN 'functions' WHEN 'T' THEN 'types' WHEN 'n' THEN 'schemas'
           ELSE d.defaclobjtype::text END,
         COALESCE(n.nspname::text, ''), '*',
         CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
         a.privilege_type, a.is_grantable, pg_get_userbyid(d.defaclrole)
    FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace
      CROSS JOIN LATERAL aclexplode(d.defaclacl) a
)
SELECT json_build_object(
  'db', current_database(), 'version', 1,
  'access', COALESCE((SELECT json_agg(access_rows) FROM access_rows), '[]'::json),
  'roles', (SELECT json_agg(json_build_object('name', rolname, 'super', rolsuper,
              'createrole', rolcreaterole, 'createdb', rolcreatedb,
              'replication', rolreplication, 'bypassrls', rolbypassrls)) FROM pg_roles),
  'memberships', COALESCE((SELECT json_agg(json_build_object(
      'role', pg_get_userbyid(member), 'object', pg_get_userbyid(roleid),
      'admin', admin_option, 'inherit', inherit_option, 'set', set_option))
      FROM pg_auth_members), '[]'::json)
);
