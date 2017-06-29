-- User
INSERT INTO User(id, email) 
VALUES	(1, 'ruben.jimenez@gft.com');

-- Authority
INSERT INTO Authority(id, name, description) 
VALUES	(1, 'EMPLOYEE_READ', 'Employee read'),
		(2, 'EMPLOYEE_WRITE', 'Employee write'),
		(3, 'EMPLOYEE_ADMIN', 'Employee admin'),
		(4, 'APPRAISAL_READ', 'Appraisal read'),
		(5, 'APPRAISAL_WRITE', 'Appraisal write'),
		(6, 'APPRAISAL_ADMIN', 'Appraisal admin');

-- UserXAuthority
INSERT INTO UserXAuthority(userId, authorityId) 
VALUES	(1, 1),
		(1, 2),
		(1, 3),
		(1, 4),
		(1, 5),
		(1, 6);
