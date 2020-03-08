CREATE TABLE 'nikto_table' (
  'testid' varchar(6) NOT NULL,
  'ip' varchar(15) DEFAULT NULL,
  'hostname' text DEFAULT NULL,
  'port' int(5) DEFAULT NULL,
  'usessl' tinyint(1) DEFAULT NULL,
  'references' text DEFAULT NULL,
  'httpmethod' text DEFAULT NULL,
  'uri' text DEFAULT NULL,
  'message' text DEFAULT NULL,
  'request' blob DEFAULT NULL,
  'response' blob DEFAULT NULL
);
