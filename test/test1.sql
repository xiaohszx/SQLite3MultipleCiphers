.open test1.db3
pragma cipher='sqlcipher';
pragma legacy=4;
pragma key='test1';
create table t1 (c1 int, c2 char);
insert into t1 values (1,'Alf');
insert into t1 values (2,'Bert');
insert into t1 values (3,'Cecil');
insert into t1 values (5,'Donald');
select * from t1;
.q
