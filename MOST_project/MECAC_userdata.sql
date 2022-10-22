CREATE TABLE `app_server_userdata`.`app_userdata` (
  `ppk` TEXT NULL DEFAULT NULL,
  `username` CHAR(200) NULL DEFAULT NULL,
  `email` CHAR(200) NULL DEFAULT NULL,
  `mUid` CHAR(200) NOT NULL,
  `autho_level` CHAR(10) NULL DEFAULT NULL,
  `data_stored_time` CHAR(30) NULL DEFAULT NULL,
  PRIMARY KEY (`mUid`));