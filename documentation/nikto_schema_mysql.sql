CREATE TABLE `nikto_table` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `scanid` varchar(32) DEFAULT NULL,
  `testid` varchar(6) NOT NULL,
  `ip` varchar(15) DEFAULT NULL,
  `hostname` text DEFAULT NULL,
  `port` int(5) DEFAULT NULL,
  `tls` tinyint(1) DEFAULT NULL,
  `refs` text DEFAULT NULL,
  `httpmethod` text DEFAULT NULL,
  `uri` text DEFAULT NULL,
  `message` text DEFAULT NULL,
  `request` blob DEFAULT NULL,
  `response` mediumblob DEFAULT NULL,
  PRIMARY KEY (`id`)
);

-- MySQL/MariaDB specific column types:
--   request: BLOB (64KB limit)
--   response: MEDIUMBLOB (16MB limit)
-- The plugin automatically truncates data to fit within these limits:
--   request: 48KB raw (fits in 64KB BLOB after base64 encoding)
--   response: 12MB raw (fits in 16MB MEDIUMBLOB after base64 encoding)
