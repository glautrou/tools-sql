--Auteur :	Gilles Lautrou
--Date :	06/09/2023
--Versions :- 1.0 : Création initiale

--Ce script va classifier comme 'Public' (donc sans anonymisation) l'ensemble des colonnes de la base de données active qui ne sont pas déjà classifiées.
--Il est possible au'après exécution de ce script 100% des colonnes ne soient pas classifiées.
--C'est normal dans la mesure où des colonnes de type computed sont calculées, si les champs sources sont anonymisés alors le computed le sera aussi.

USE [MaTable]
GO

DECLARE @valeurSchema AS nvarchar(255)
DECLARE @valeurTable AS nvarchar(255)
DECLARE @valeurColumn AS nvarchar(255)
DECLARE @sql AS nvarchar(2000)
DECLARE cur_ForEachColumn CURSOR LOCAL FAST_FORWARD FOR
	(select SCHEMA_NAME(ao.schema_id) SchemaName, ao.name TableName, ac.name ColumnName--, ac.is_computed IsComputed
	from  sys.all_objects ao
	inner join sys.all_columns ac on ac.object_id = ao.object_id
	where SCHEMA_NAME(ao.schema_id) = 'dbo'
	and type = 'U' --Table utilisateur seulement
	and ac.is_computed = 0

	except

	select 
		SCHEMA_NAME(ao.schema_id) [TableSchema]
		,ao.name [TableName]
		,ac.name [ColumnName]
	from sys.sensitivity_classifications sc
	inner join sys.all_objects ao on sc.major_id = ao.object_id
	inner join sys.all_columns ac on sc.major_id = ac.object_id and sc.minor_id = ac.column_id
	inner join information_schema.columns co ON co.TABLE_SCHEMA = SCHEMA_NAME(ao.schema_id) AND co.TABLE_NAME = ao.name AND co.COLUMN_NAME = ac.name
	where co.TABLE_CATALOG = DB_NAME())

OPEN    cur_ForEachColumn 
	FETCH NEXT  FROM cur_ForEachColumn INTO @valeurSchema, @valeurTable, @valeurColumn
WHILE @@FETCH_STATUS = 0 
BEGIN 

	SET @sql = 'ADD SENSITIVITY CLASSIFICATION TO [' + @valeurSchema + '].[' + @valeurTable + '].[' + @valeurColumn + '] WITH (label = ''Public'', label_id = ''1866ca45-1973-4c28-9d12-04d407f147ad'', rank = None);'
	PRINT @sql
	EXEC sp_executesql @sql

FETCH NEXT FROM cur_ForEachColumn INTO @valeurSchema, @valeurTable, @valeurColumn
END
CLOSE cur_ForEachColumn
DEALLOCATE cur_ForEachColumn
