CREATE TABLE nikto_table (
  id serial NOT NULL,
  scanid varchar(32) DEFAULT NULL,
  testid varchar(6) NOT NULL,
  ip varchar(15) DEFAULT NULL,
  hostname text DEFAULT NULL,
  port integer DEFAULT NULL,
  tls smallint DEFAULT NULL,
  refs text DEFAULT NULL,
  httpmethod text DEFAULT NULL,
  uri text DEFAULT NULL,
  message text DEFAULT NULL,
  request bytea DEFAULT NULL,
  response bytea DEFAULT NULL,
  PRIMARY KEY (id)
);

-- PostgreSQL specific column types:
--   request: bytea (theoretical limit ~1GB, practical limits apply)
--   response: bytea (theoretical limit ~1GB, practical limits apply)
-- The plugin automatically truncates data for performance and cross-DB compatibility:
--   request: 48KB raw (matches MySQL BLOB limit)
--   response: 12MB raw (matches MySQL MEDIUMBLOB limit)
-- PostgreSQL bytea can store much larger data, but these limits ensure consistent
-- behavior across database types and prevent performance issues with very large responses

