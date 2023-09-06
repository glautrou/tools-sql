--Auteur :	Gilles Lautrou
--Date :	30/08/2023
--Versions :- 1.0 : Création initiale

--Ce script va créer ou remplacer la procédure stockée d'anonymisation

--Suppression de la procédure si déjà existante
IF OBJECT_ID ('sp_AnonymiseDonnees') IS NOT NULL
   DROP PROCEDURE [dbo].[sp_AnonymiseDonnees]
GO

-- Création de la procédure
CREATE PROCEDURE [dbo].[sp_AnonymiseDonnees]
	@originalDbName nvarchar(255)
	, @targetDbName nvarchar(255)
	, @executeSql bit = 1
AS
BEGIN

	--Script d'anonymisation des données
	--Principe : Le script va anonymiser toutes les colonnes qui sont marquées dans @originalDbName comme classifiées
	--Input :
	--	- @originalDbName : Base de données à anonymiser
	--	- @targetDbName : Base de données anonymisée
	--	- @executeSql : 1 = exécution du SQL d'anonymisation, 0 = ignorer les modifications a des fins de debug
	--Output :
	--	- Aucun, seulement des logs
	--Gardes-fou :
	--	- exécution du script si @originalDbName et @targetDbName sont différentes, afin d'éviter une exécution par mégarde sur la base origine
	--	- au moins une PK est classifiée
	--	- L'anonymisation réalisée sur certains types de colonnes de type pertinent est vérifiée, seulement pour la première ligne (perf)
	--Règles :
	--	- En cas d'erreur, le script s'arrête et une exception est renvoyée
	--	- Pas de gestion transactionelle
	--	- Les chaînes de caractères sont une concaténation de nom de colonne avec, soit la valeur de la PK si unique existe, soit une valeur aléatoire inférieure à @maxRandomInt
	--	- Les chaînes de caractères anonymisées sont tronquées si elles étaient amenées à dépasser la longueur max
	--	- Les valeurs NULL ne sont pas laissées à NULL mais utilisent une valeur de base par défaut (@defaultDate et @defaultNumber)
	--	- Les types non-gérés renvoient une erreur
	--	- Champs spécifiques gérés :
	--		- Email : [PK]@test.com, ou [Random]test.com si pas de valeur PK réutilisable
	--		- Téléphone : Valeur aléatoire au format local FR
	--		- CodePostal : Entier 5 chiffres
	--Limites :
	--	- Les PK ne sont pas anonymisables car trop complexe et probablement inutile. Si des PK sont classifiées alors ce script renverra une erreur sans la moindre exécution
	--	- Pas de vérification de longueur des nombres, les valeurs max étant souvent hautes et possibilité d'affiner avec @NumberVariancePercentage
	--	- Pas d'utilisation des valeurs PK composite dans la chaîne de caractère, assez simple à ajouter si des composites existent, ce script ne le gère pas volontairement pour ne pas inutilement surcomplexifier
	--	- Les suffixes aléatoires aux chaînes sans PK peuvent êtyre en doublon entre des lignes, et ne sont pas identiques entre les différentes colonnes d'une même ligne

	SET NOCOUNT ON;

	DECLARE @NumberVariancePercentage AS decimal = 0.5	--Pourcentage de variance avec la valeur d'origine pour l'aléatoire des nombres
	DECLARE @DateVarianceDays AS int = 60				--Nombre de jours de variance avec la valeur d'origine pour l'aléatoire des dates
	DECLARE @defaultDate as date = GETDATE()			--Date par défaut si valeur NULL
	DECLARE @defaultNumber as int = 100					--Nombre par défaut si valeur NULL
	DECLARE @maxRandomInt as int = 10000000				--Nombre maximum
	DECLARE @nbColonnes as int							--Nombre de colonnes à anonymiser
	-- ****************************************************************
	PRINT 'Parametres :'
		+ CHAR(13) + CHAR(10) + CHAR(9) + '- DB_NAME()=' + DB_NAME()
		+ CHAR(13) + CHAR(10) + CHAR(9) + '- @originalDbName=' + @originalDbName
		+ CHAR(13) + CHAR(10) + CHAR(9) + '- @targetDbName=' + @targetDbName
		+ CHAR(13) + CHAR(10) + CHAR(9) + '- @executeSql=' + CAST(@executeSql AS varchar(12))
		+ CHAR(13) + CHAR(10) + CHAR(9) + '- @NumberVariancePercentage=' + CAST(@NumberVariancePercentage AS varchar(12))
		+ CHAR(13) + CHAR(10) + CHAR(9) + '- @DateVarianceDays=' + CAST(@DateVarianceDays AS varchar(12))
		+ CHAR(13) + CHAR(10) + CHAR(9) + '- @defaultDate=' + CAST(@defaultDate AS varchar(12))
		+ CHAR(13) + CHAR(10) + CHAR(9) + '- @defaultNumber=' + CAST(@defaultNumber AS varchar(12))
		+ CHAR(13) + CHAR(10) + CHAR(9) + '- @maxRandomInt=' + CAST(@maxRandomInt AS varchar(12))
	-- ****************************************************************

	--Vérification que @originalDbName et @targetDbName sont différents
	IF @originalDbName = @targetDbName OR @originalDbName = '[' + @targetDbName + ']'
	BEGIN
		;THROW 51000, 'ERREUR ! L''execution ne peut pas etre effectuee sur la base originale pour eviter toute perte d''information', 1;
	END;

	--Création table contenant l'ensemble des colonnes à anonymiser
    IF NOT EXISTS ( SELECT name FROM tempdb.sys.tables WHERE name LIKE '%#sensitiveColumns%' ) 
	   CREATE TABLE #sensitiveColumns
	   ( 
		  [TableCatalog] nvarchar(255),
		  [TableSchema] nvarchar(255), 
		  [TableName] nvarchar(255), 
		  [TableFullNameOrigin] nvarchar(500),
		  [TableFullNameTarget] nvarchar(500),		  
		  [ColumnName] nvarchar(255), 
		  [SensitiveLabel] nvarchar(255), 
		  [SensitiveLabelId] uniqueidentifier, 
		  [SensitiveType] nvarchar(255),
		  [SensitiveTypeId] uniqueidentifier,
		  [ColumnPosition] smallint, 
		  [ColumnType] nvarchar(255),
		  [ColumnMaxLength] smallint,
		  [ColumnNumberPrecision] smallint,
		  [ColumnScale] smallint,
		  [ColumnDatePrecision] smallint,
		  [ColumnIsNullable] bit
		);
	TRUNCATE TABLE #sensitiveColumns;
	
	--Récupération de l'ensemble des colonnes à anonymiser
	INSERT INTO #sensitiveColumns
	SELECT 
		co.TABLE_CATALOG [TableCatalog]
		,SCHEMA_NAME(ao.schema_id) [TableSchema]
		,ao.name [TableName]
		,@originalDbName + '.' + SCHEMA_NAME(ao.schema_id)  + '.' + ao.name AS [TableFullNameOrigin]
		,@targetDbName + '.' + SCHEMA_NAME(ao.schema_id)  + '.' + ao.name AS [TableFullNameTarget]
		,ac.name [ColumnName]
		,[Label] SensitiveLabel, [Label_ID] SensitiveLabelId
		,[Information_Type] SensitiveType, [Information_Type_ID] SensitiveTypeId
		--,[Rank], [Rank_Desc]
		,co.ORDINAL_POSITION ColumnPosition
		,co.DATA_TYPE ColumnType
		,co.CHARACTER_MAXIMUM_LENGTH ColumnMaxLength
		,co.NUMERIC_PRECISION ColumnNumberPrecision
		,co.NUMERIC_SCALE ColumnScale
		,co.DATETIME_PRECISION ColumnDatePrecision
		,CASE WHEN co.IS_NULLABLE = 'NO' THEN 0 ELSE 1 END ColumnIsNullable
	FROM sys.sensitivity_classifications sc
	inner join sys.all_objects ao on sc.major_id = ao.object_id
	inner join sys.all_columns ac on sc.major_id = ac.object_id and sc.minor_id = ac.column_id
	inner join information_schema.columns co ON co.TABLE_SCHEMA = SCHEMA_NAME(ao.schema_id) AND co.TABLE_NAME = ao.name AND co.COLUMN_NAME = ac.name
	where co.TABLE_CATALOG = @targetDbName --Se baser sur target et non pas original (ou encore DB_NAME()) pour gérer le cas où certaines tables sont supprimées en amont de l'anonymisation
	and [Label] <> 'Public' --Champ revu mais autorisé en public donc exclu de l'anonymisation
	order by TableFullNameOrigin, ColumnName;

	--Vérificaton qu'il y a au moins une colonne à anonymiser, le cas échéant c'est probablement une erreur
	SELECT @nbColonnes = COUNT(*) FROM #sensitiveColumns
	IF @nbColonnes > 0
	BEGIN
		PRINT 'Nombre de colonnes a anonymiser : ' + CAST(@nbColonnes AS varchar(12))
	END
	ELSE
	BEGIN
		;THROW 51000, 'ERREUR ! Aucune colonne a anonymiser. Pour marquer une colonne a anonymiser il faut utiliser la fonction de classification des donnees dans SQL Server', 1;
	END;


	--Vérification qu'il n'y a pas de PK à anonymiser
	DECLARE @erreursPk TABLE(
		ColumnFullName nvarchar(500) NOT NULL
	);
	INSERT INTO @erreursPk (ColumnFullName)
		SELECT ss.TableFullNameOrigin + '.' + ss.ColumnName
		FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE kcu
		INNER JOIN #sensitiveColumns ss
			ON ss.TableCatalog = kcu.TABLE_CATALOG
			AND ss.TableSchema = kcu.TABLE_SCHEMA
			AND ss.TableName = kcu.TABLE_NAME
			AND ss.ColumnName = kcu.COLUMN_NAME
		WHERE OBJECTPROPERTY(OBJECT_ID(CONSTRAINT_SCHEMA + '.' + QUOTENAME(CONSTRAINT_NAME)), 'IsPrimaryKey') = 1;
	IF EXISTS (SELECT 1 FROM @erreursPk)
	BEGIN
		DECLARE @pkError VARCHAR(MAX) 
		SELECT @pkError = COALESCE(@pkError + ', ', '') + CHAR(13) + CHAR(10) + CHAR(9) + '- ' + ColumnFullName from @erreursPk;
		SET @pkError = 'Les cles primaires ne peuvent pas etre anonymisees : ' + @pkError;
		THROW 51000, @pkError, 1;
	END

	-- Exécution de l'anonymisation table par table, puis colonne par colonne en créant un script par table
	DECLARE @thisTableCatalog nvarchar(255)					--Catalog de table
	DECLARE @thisTableSchema nvarchar(255)					--Schéma de table
	DECLARE @thisTableName nvarchar(255)					--Nom de table
	DECLARE @thisTableFullNameOrigin nvarchar(500)			--Nom complet de table origine
	DECLARE @thisTableFullNameTarget nvarchar(500)			--Nom complet de table cible
	DECLARE @thisTableScript nvarchar(max)					--Script d'anonymisation de la table
	DECLARE @thisCheckScript nvarchar(max)					--Script de vérification des données
	DECLARE @thisCheckSelectScript nvarchar(max)			--Portion de script concernant les colonnes à vérifier
	DECLARE @thisCheckJoinScript nvarchar(max)				--Portion de script concernant les vérifications de données colonne à colonne
	DECLARE @thisCheckScriptResult int						--Résultat de vérification. 0 = succès
	DECLARE @thisTablePkSingleColumnName nvarchar(255) 		--La table a-t-elle une unique colonne qui sert de PK
	DECLARE cur_ForEachTable CURSOR LOCAL FAST_FORWARD FOR 	--Curseur itération table
		SELECT DISTINCT
			s.[TableCatalog]
			,s.[TableSchema]
			,s.[TableName]
			,s.[TableFullNameOrigin]
			,s.[TableFullNameTarget]
		FROM #sensitiveColumns s
	OPEN    cur_ForEachTable 
		FETCH NEXT  FROM cur_ForEachTable INTO @thisTableCatalog, @thisTableSchema, @thisTableName, @thisTableFullNameOrigin, @thisTableFullNameTarget
	WHILE @@FETCH_STATUS = 0 
	BEGIN 
		--Traitement d'une table
		PRINT 'Table = ' + @thisTableFullNameTarget

		SET @thisTableScript = 'UPDATE ' + @thisTableFullNameTarget+ ' SET '
		SET @thisCheckScript = ''
		SET @thisCheckSelectScript = ''
		SET @thisCheckJoinScript = ''
		
		--Vérification présence PK
		SELECT @thisTablePkSingleColumnName = COLUMN_NAME
			FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE
			WHERE OBJECTPROPERTY(OBJECT_ID(CONSTRAINT_SCHEMA + '.' + QUOTENAME(CONSTRAINT_NAME)), 'IsPrimaryKey') = 1
			AND TABLE_CATALOG = @thisTableCatalog
			AND TABLE_SCHEMA = @thisTableSchema
			AND TABLE_NAME = @thisTableName
		IF @@ROWCOUNT = 1
		BEGIN
			PRINT CHAR(9) + '> Valeur PK utilisable ? Oui'
		END
		ELSE
		BEGIN
			PRINT CHAR(9) + '> Valeur PK utilisable ? Non, car manquante ou composite'
			SET @thisTablePkSingleColumnName = NULL
		END

		PRINT CHAR(9) + '> Colonnes :'
		
		--Récupération des colonnes de la table
		DECLARE @thisColumnStatement nvarchar(max) 				--Portion de script concernant la colonne
		DECLARE @thisColumnName nvarchar(255) 					--Nom colonne
		DECLARE @thisColumnType nvarchar(255) 					--Typage colonne
		DECLARE @ColumnMaxLength smallint						--Longueur maximale du texte
		DECLARE @thisColumnNumberPrecision smallint 			--Précision du nombre
		DECLARE @thisColumnIsNullable bit						--Flag nullable
		DECLARE @nouvelleValeur AS nvarchar(255)				--Nouvelle valeur anonymisée
		DECLARE cur_ForEachColumn CURSOR LOCAL FAST_FORWARD FOR --Curseur itération table
			SELECT
				[ColumnName]
				,[ColumnType]
				,[ColumnMaxLength]
				,[ColumnNumberPrecision]
				,[ColumnIsNullable]
			FROM #sensitiveColumns s
			WHERE s.[TableFullNameTarget] = @thisTableFullNameTarget
		OPEN    cur_ForEachColumn 
			FETCH NEXT  FROM cur_ForEachColumn INTO @thisColumnName, @thisColumnType, @ColumnMaxLength, @thisColumnNumberPrecision, @thisColumnIsNullable
		WHILE @@FETCH_STATUS = 0 
		BEGIN 
			--Traitement d'une colonne
			PRINT CHAR(9) + CHAR(9) + '- ' + @thisColumnName

			SET @thisColumnStatement = @thisColumnName + ' = '
			
			--Ajout de vérification de données que pour certains types (par exemple bit n'a aucun sens et engendrerait 50% d'échec)
			IF @thisColumnType LIKE '%char%'				--Chaine
				OR @thisColumnType LIKE '%date%'			--Date
				OR @thisColumnNumberPrecision IS NOT NULL	--Nombre
			BEGIN
				SET @thisCheckSelectScript += @thisColumnName + ', '
				SET @thisCheckJoinScript += 't.' + @thisColumnName + ' = o.' + @thisColumnName + ' OR '
			END
			
			--Anonymisation en fonction des types
		   IF @thisColumnType LIKE '%char%'
		   BEGIN
				SET @nouvelleValeur = CASE
					WHEN @thisTablePkSingleColumnName IS NULL
						THEN '''' + @thisColumnName + '-'' + CAST(abs(checksum(NewId()) % ' + CAST(@maxRandomInt AS varchar) + ') AS varchar)'
					WHEN @thisTablePkSingleColumnName IS NOT NULL
						THEN '''' + @thisColumnName + '-'' + CAST(' + @thisTablePkSingleColumnName + ' AS varchar)'
				END
				--Valeurs spécifiques en fonction du nom de colonne
				IF LOWER(@thisColumnName) LIKE '%email%'
				BEGIN
					--Email : Ajout simple suffixe
					SET @nouvelleValeur += ' + ''@test.com'''
				END
				IF LOWER(@thisColumnName) LIKE '%phone%'
				BEGIN
					--Telephone : Format FR
					SET @nouvelleValeur = 'LEFT(''0'' + CAST(abs(checksum(NewId()) % ' + CAST(999999999 AS varchar) + ') AS varchar) + ''000'', 10)'
				END
				IF LOWER(@thisColumnName) LIKE '%codepostal%'
				BEGIN
					--Code postal : Format FR
					SET @nouvelleValeur = 'RIGHT(''0000'' + CAST(abs(checksum(NewId()) % ' + CAST(99999 AS varchar) + ') AS varchar), 5)'
				END
				--Longueur max
				IF @ColumnMaxLength <> -1
				BEGIN
					--@ColumnMaxLength=-1 correspond à "max", troncation ici
					SET @nouvelleValeur = 'LEFT(' + @nouvelleValeur + ', ' + CAST(@ColumnMaxLength AS varchar) + ')'
				END
				SET @thisColumnStatement += @nouvelleValeur
		   END
		   ELSE IF @thisColumnType = 'bit'
		   BEGIN
				SET @thisColumnStatement += 'CRYPT_GEN_RANDOM(1) % 2'
		   END
		   ELSE IF @thisColumnType LIKE '%date%'
		   BEGIN
				--Si NULL, utilisation de NOW par défaut pour ne pas laisser NULL visible
				SET @thisColumnStatement += 'DATEADD(DAY, ((CAST(ABS(CHECKSUM(NEWID())) AS FLOAT) / 2147483648) * ' + CAST(@DateVarianceDays AS varchar) + ' * 2 - ' + CAST(@DateVarianceDays AS varchar) + '), COALESCE(' + @thisColumnName + ', ''' + CAST(@defaultDate AS varchar) + '''))'
		   END
		   ELSE IF @thisColumnNumberPrecision IS NOT NULL
		   BEGIN
				--Si NULL, utilisation de @defaultNumber par défaut pour ne pas laisser NULL visible
				SET @thisColumnStatement += 'COALESCE(' + @thisColumnName + ', ' + CAST(@defaultNumber AS varchar) + ') * (1+(CAST(ABS(CHECKSUM(NEWID())) AS FLOAT) / 2147483648) * ' + CAST(@NumberVariancePercentage AS varchar) + ' * 2 - ' + CAST(@NumberVariancePercentage AS varchar) + ')'
		   END
		   ELSE IF @thisColumnIsNullable = 1
		   BEGIN
				--Type-non pris en charge mais nullable, il aurait été possible de laisser à NULL. Par sécurité, une erreur est levée
				DECLARE @errorTypeManquantNull AS nvarchar(max) = 'ERREUR ! Type non-pris en charge. ' + CHAR(13)+CHAR(10) + CHAR(9)  + '- Type : ' + @thisColumnType + ' : ' + CHAR(13)+CHAR(10) + CHAR(9) + '- Colonne : ' + @thisColumnName;
				THROW 51000, @errorTypeManquantNull, 1;
		   END
		   ELSE
		   BEGIN
				--Type-non pris en charge et non-nullable, il aurait été possible de laisser à vide. Par sécurité, une erreur est levée
				DECLARE @errorTypeManquantNotNull AS nvarchar(max) = 'ERREUR ! Type non-pris en charge. ' + CHAR(13)+CHAR(10) + CHAR(9)  + '- Type : ' + @thisColumnType + ' : ' + CHAR(13)+CHAR(10) + CHAR(9) + '- Colonne : ' + @thisColumnName;
				THROW 51000, @errorTypeManquantNotNull, 1;
		   END

		   IF @executeSql = 0
		   BEGIN
				--Formattage visuel pour debug puisque pas d'execution
				SET @thisTableScript += CHAR(13)+CHAR(10) + CHAR(9) + @thisColumnStatement + ', '
		   END
		   ELSE
		   BEGIN
				--Script en une seule ligne
				SET @thisTableScript += @thisColumnStatement + ', '
		   END
		
		FETCH NEXT FROM cur_ForEachColumn INTO @thisColumnName, @thisColumnType, @ColumnMaxLength, @thisColumnNumberPrecision, @thisColumnIsNullable
		END
		CLOSE cur_ForEachColumn
		DEALLOCATE cur_ForEachColumn

		--Suppression des caractères finaux de concatenation ', ' de colonne
		SET @thisTableScript = LEFT(@thisTableScript, LEN(@thisTableScript) - 1)

		--Exécution update table
		IF @executeSql = 1
		BEGIN
			BEGIN TRY 
				EXEC sp_executesql @thisTableScript
				PRINT CHAR(9) + '> Lignes modifiees : ' + CAST(@@ROWCOUNT as varchar(12))
			END TRY 
			BEGIN CATCH 
				--Affichage requête
				PRINT CHAR(9) + '> Query : ' + @thisTableScript
				--Une erreur stoppe le script et en renvoie une personnalisée
				DECLARE @error AS nvarchar(max) = 'ERREUR ! La requete n''a pas pu etre executee. Raison : ' + CHAR(13)+CHAR(10) + CHAR(9) + ERROR_MESSAGE();
				THROW 51000, @error, 1;
			END CATCH
		END
		
		--Vérification des données
		IF @thisCheckSelectScript <> ''
		BEGIN
			--Note : La vérification ne se fait que sur la première ligne pour éviter impact sur les performances
			--Suppression des caractères finaux de concatenation ', ' de colonne
			SET @thisCheckSelectScript = LEFT(@thisCheckSelectScript, LEN(@thisCheckSelectScript) - 1)
			--Suppression des caractères finaux de concatenation ' OR ' de colonne
			SET @thisCheckJoinScript = LEFT(@thisCheckJoinScript, LEN(@thisCheckJoinScript) - 3)
			--Script de vérification
			SET @thisCheckScript = '
				SELECT @thisCheckScriptResult = COUNT(*)
				FROM (SELECT TOP (1) ' + @thisCheckSelectScript + ' FROM ' + @thisTableFullNameOrigin + ') o
				INNER JOIN (SELECT TOP (1) ' + @thisCheckSelectScript + ' FROM ' + @thisTableFullNameTarget + ') t 
				ON ' + @thisCheckJoinScript
			--Exécution
			EXEC sp_executesql 
					@Query  = @thisCheckScript
				  , @Params = N'@thisCheckScriptResult INT OUTPUT'
				  , @thisCheckScriptResult = @thisCheckScriptResult OUTPUT
			--Vérification
			IF @thisCheckScriptResult > 0
			BEGIN
				PRINT CHAR(9) + '> Script de verification : ' + @thisCheckScript
				PRINT CHAR(9) + '> Verification anonymisation table : KO'
				DECLARE @errorCheck AS nvarchar(max) = 'ERREUR ! Certaines valeurs n''ont pas ete anonymisees. Table : ' + @thisTableFullNameTarget;
				THROW 51000, @errorCheck, 1;
			END
			ELSE
			BEGIN
				PRINT CHAR(9) + '> Verification anonymisation table : OK'
			END
		END
		ELSE
		BEGIN
			PRINT CHAR(9) + '> Verification anonymisation table : Ignore, car aucun type pertinent'
		END

	FETCH NEXT FROM cur_ForEachTable INTO @thisTableCatalog, @thisTableSchema, @thisTableName, @thisTableFullNameOrigin, @thisTableFullNameTarget
	END
	CLOSE cur_ForEachTable
	DEALLOCATE cur_ForEachTable

	--Nettoyages
	DROP TABLE #sensitiveColumns;
END
GO
