CREATE DATABASE xraylab;
use xraylab;


CREATE TABLE Roles (
id integer not null Primary Key,
name varchar(100) not null
);

CREATE TABLE Users (
id integer AUTO_INCREMENT NOT NULL Primary Key,
username varchar(100) NOT NULL,
password varchar(200) NOT NULL,
e_mail varchar(100) NOT NULL,
role_id integer NOT NULL,
FOREIGN KEY (role_id) REFERENCES Roles(id)
);

CREATE TABLE Snapshots (
id integer not null Primary Key,
note varchar(500),
status varchar(100),
image_path varchar(500),
mask_path varchar(500),
conclusion varchar(500),
created_at datetime,
user_id integer NOT NULL,
favorite boolean,
FOREIGN KEY (user_id) REFERENCES Users(id)
);

INSERT INTO Roles(id, name) VALUES (1, 'admin');
INSERT INTO Roles(id, name) VALUES (2, 'doctor');
INSERT INTO Roles(id, name) VALUES (3, 'user');