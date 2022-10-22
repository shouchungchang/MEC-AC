CREATE TABLE `user_pairing_server`.`parameters` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `eventnumber` TEXT NULL DEFAULT NULL,
  `hash_m` TEXT NULL DEFAULT NULL,
  `CT` TEXT NULL DEFAULT NULL,
  `time` VARCHAR(45) NULL DEFAULT NULL,
  PRIMARY KEY (`id`)); 
