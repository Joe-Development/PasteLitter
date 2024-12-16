CREATE TABLE IF NOT EXISTS `users` (
	`id` INT(11) NOT NULL AUTO_INCREMENT,
	`avatar` VARCHAR(255) NULL DEFAULT 'https://i2.wp.com/ui-avatars.com/api//Paste+Litter/128?ssl=1',
	`username` VARCHAR(255) NOT NULL COLLATE 'utf8mb4_general_ci',
	`email` VARCHAR(255) NOT NULL DEFAULT 'anonymous@litter.com' COLLATE 'utf8mb4_general_ci',
	`password` VARCHAR(255) NOT NULL COLLATE 'utf8mb4_general_ci',
	`rank` ENUM('owner','admin','user') NOT NULL DEFAULT 'user' COLLATE 'utf8mb4_general_ci',
	`created` DATE NULL DEFAULT current_timestamp(),
	`banned` TINYINT(1) NOT NULL DEFAULT 0,
	`banned_reason` VARCHAR(255) NULL DEFAULT NULL,
	`last_logins` JSON DEFAULT '[]' NULL,
	PRIMARY KEY (`id`) USING BTREE
)
COLLATE='utf8mb4_general_ci'
ENGINE=InnoDB
AUTO_INCREMENT=8
;

CREATE TABLE IF NOT EXISTS pastes (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    title VARCHAR(255) NOT NULL DEFAULT 'Untitled',
    content TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    pinned BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(id)
)

CREATE TABLE IF NOT EXISTS logs (
	id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
	user_id INT NOT NULL,
	username VARCHAR(255) NOT NULL,
	action_desc VARCHAR(255) NOT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (user_id) REFERENCES users(id)
)

