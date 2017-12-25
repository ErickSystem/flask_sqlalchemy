CREATE DATABASE api_study;

USE api_study;

CREATE TABLE IF NOT EXISTS `api_study`.`users` (
  `id` MEDIUMINT NOT NULL AUTO_INCREMENT,
  `public_id` VARCHAR(50),
  `name` VARCHAR(50) NOT NULL,
  `password` VARCHAR(80) NOT NULL,
  `admin`   boolean,	
   PRIMARY KEY (`id`),
   UNIQUE INDEX `public_id_UNIQUE` (`public_id` ASC))
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;   

CREATE TABLE IF NOT EXISTS `api_study`.`conteudo` (
	`id` MEDIUMINT NOT NULL AUTO_INCREMENT,
    `texto` VARCHAR(50),
    `complete` boolean,
    `user_id` MEDIUMINT,
    PRIMARY KEY (`id`))
ENGINE = InnoDB
DEFAULT CHARACTER SET = utf8;
    
show tables;

SELECT * FROM users;
DELETE FROM conteudo WHERE id > 0;
SELECT * FROM conteudo;
DESC users;




                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               