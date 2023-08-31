--Auteur :	Gilles Lautrou
--Date :	30/08/2023
--Versions :- 1.0 : Création initiale

--Ce script va anonymiser une base de données vers un BAK anonymisé et crypté.
--!!! ATTENTION : Ce script contient les mots de passe certificat, il ne doit donc pas être partagé !!!
--Actions :
--	- Sauvegarde source
--	- Restauration source en cible
--	- Anonymisation cible
--	- Gestion des certificats
--	- Sauvegarde cryptée BAK cible
--	- Suppression cible
--Potentiels problèmes non-gérés dans ce script :
--	- Droits insuffisants utilisateur SQL
--	- Droits disque pour sauegarde
--	- Espace disque insuffisant

--Paramètres
DECLARE @query varchar(5000)
DECLARE @spAnonymiseDonnees nvarchar(255)			= 'dbo.sp_AnonymiseDonnees'													-- Nom de la procédure stockée d'anonymisation des valeurs
DECLARE @sourceDatabaseLogicalName varchar(255)		= 'TODO_BaseOrigine'																	-- Logical name of the DB ( check DB properties / Files tab )
DECLARE @sourceDatabaseLogicalNameLog varchar(255)	= @sourceDatabaseLogicalName + '_log'										-- Logical name of the DB ( check DB properties / Files tab )
DECLARE @sourceDatabaseName as varchar(255)			= @sourceDatabaseLogicalName												-- Name of the source database
DECLARE @sourceBackupFile varchar(2000)				= 'B:\SQL Server\Anonymisation\' + @sourceDatabaseLogicalName + '.bak'		-- FileName of the backup file
DECLARE @targetDatabaseName varchar(255)			= @sourceDatabaseLogicalName + '_Anonyme'									-- Name of the target database
DECLARE @targetBackupFileAnonyme varchar(2000)		= 'B:\SQL Server\Anonymisation\' + @targetDatabaseName + '.bak'				-- FileName of the anonyme backup file
DECLARE @backupStatsPercentage smallint				= 10																		-- Pourcentage avancement des backups à logguer (plage [0;100]). NULL = pas de log
DECLARE @restoreDataFile varchar(2000)				= 'E:\SQL Server\' + @targetDatabaseName + '.mdf';							-- Fichier data restore
DECLARE @restoreLogFile varchar(2000)				= 'L:\SQL Server\' + @targetDatabaseName + '.ldf';							-- Fichier log restore
DECLARE @removeOriginalBackup bit					= 1																			-- 1 = suppression backup original
DECLARE @compressOriginalBackup bit					= 1																			-- 1 = compression de la sauvegarde originale (réduction de taille mais impact sur perfs)
DECLARE @compressTargetBackup bit					= 1																			-- 1 = compression de la sauvegarde finale anonymisée (réduction de taille mais impact sur perfs)
DECLARE @targetBackupFileAnonymeMoveTo varchar(2000)= NULL																		-- Répertoire vers le lequel déplacer la sauvegade. NULL = pas de déplacement
DECLARE @isEncryptionEnabled bit					= 1																			-- Cryptage de la sauvegarde anonymisée
DECLARE @certificateName nvarchar(255)				= 'PartenaireCertificate'												-- Nom du certificat de cryptage backup
DECLARE @certificateSubject nvarchar(255)			= 'Certificat des partenaires'												-- Sujet du certificat de cryptage backup
DECLARE @certificateMasterKey nvarchar(255)			= 'TODO_CleMasterKey'										-- Master key serveur pour les certificats
DECLARE @certificateExpiryDate nvarchar(12)			= '20291231'																-- Date d'expiration du certificat
DECLARE @certificatePath nvarchar(255)				= 'E:\Apps\Scripts\AnonymisationSql\PartenaireCertificate.pfx'		-- Chemin du certificat exporté
DECLARE @certificatePrivateKey nvarchar(255)		= 'TODO_ClePrivateKey'									-- Clé privé du certificat exporté
-- ****************************************************************
PRINT CHAR(13) + CHAR(10) + '#################### ' + CONVERT( VARCHAR(24), GETDATE(), 121) + ' - Affichage des parametres ####################'
	+ CHAR(13) + CHAR(10) + CHAR(9) + '- DB_NAME()=' + DB_NAME()
	+ CHAR(13) + CHAR(10) + CHAR(9) + '- @spAnonymiseDonnees=' + @spAnonymiseDonnees
	+ CHAR(13) + CHAR(10) + CHAR(9) + '- @sourceDatabaseLogicalName=' + @sourceDatabaseLogicalName
	+ CHAR(13) + CHAR(10) + CHAR(9) + '- @sourceDatabaseLogicalNameLog=' + @sourceDatabaseLogicalNameLog
	+ CHAR(13) + CHAR(10) + CHAR(9) + '- @sourceDatabaseName=' + @sourceDatabaseName
	+ CHAR(13) + CHAR(10) + CHAR(9) + '- @sourceBackupFile=' + @sourceBackupFile
	+ CHAR(13) + CHAR(10) + CHAR(9) + '- @targetBackupFileAnonyme=' + @targetBackupFileAnonyme
	+ CHAR(13) + CHAR(10) + CHAR(9) + '- @targetDatabaseName=' + @targetDatabaseName
	+ CHAR(13) + CHAR(10) + CHAR(9) + '- @restoreDataFile=' + @restoreDataFile
	+ CHAR(13) + CHAR(10) + CHAR(9) + '- @restoreLogFile=' + @restoreLogFile
	+ CHAR(13) + CHAR(10) + CHAR(9) + '- @removeOriginalBackup=' + CAST(@removeOriginalBackup AS varchar(255))
	+ CHAR(13) + CHAR(10) + CHAR(9) + '- @compressOriginalBackup=' + CAST(@compressOriginalBackup AS varchar(255))
	+ CHAR(13) + CHAR(10) + CHAR(9) + '- @compressTargetBackup=' + CAST(@compressTargetBackup AS varchar(255))
	+ CHAR(13) + CHAR(10) + CHAR(9) + '- @isEncryptionEnabled=' + CAST(@isEncryptionEnabled AS varchar(255))
	+ CHAR(13) + CHAR(10) + CHAR(9) + '- @certificateName=' + @certificateName
	+ CHAR(13) + CHAR(10) + CHAR(9) + '- @certificateSubject=' + @certificateSubject
	+ CHAR(13) + CHAR(10) + CHAR(9) + '- @certificateMasterKey=************' + RIGHT(@certificateMasterKey, 3)
	+ CHAR(13) + CHAR(10) + CHAR(9) + '- @certificateExpiryDate=' + @certificateExpiryDate
	+ CHAR(13) + CHAR(10) + CHAR(9) + '- @certificatePath=' + @certificatePath
	+ CHAR(13) + CHAR(10) + CHAR(9) + '- @certificatePrivateKey=' +  RIGHT(@certificatePrivateKey, 3)
-- ****************************************************************

--Vérification procédure stockée anonymisation existante
PRINT CHAR(13) + CHAR(10) + '#################### ' + CONVERT( VARCHAR(24), GETDATE(), 121) + ' - Verification procédure stockee anonymisation existante ####################'
IF NOT EXISTS (SELECT 1 FROM sys.objects WHERE type = 'P' AND OBJECT_ID = OBJECT_ID(@spAnonymiseDonnees))
BEGIN
   ;THROW 51000, 'ERREUR ! La procedure stockee d''anonymisation des donnees est manquante', 1;
END

--Activation commandes "xp_cmdshell"
PRINT CHAR(13) + CHAR(10) + '#################### ' + CONVERT( VARCHAR(24), GETDATE(), 121) + ' - Configuration droits fichiers disque xp_cmdshell ####################'
EXEC sp_configure 'show advanced option', '1';  
RECONFIGURE WITH OVERRIDE;
EXEC sp_configure 'xp_cmdshell', 1;  
RECONFIGURE;
PRINT '> OK!';

--Sauvegarde origine
SET @query = 'BACKUP DATABASE ' + @sourceDatabaseName
	+ ' TO DISK = ' + QUOTENAME(@sourceBackupFile,'''')
	+ ' WITH COPY_ONLY, INIT' 
	+ CASE WHEN @compressOriginalBackup = 1 THEN ', COMPRESSION' ELSE '' END
	+ CASE WHEN @backupStatsPercentage IS NOT NULL THEN ', STATS=' + CAST(@backupStatsPercentage AS nvarchar(3)) ELSE '' END
PRINT CHAR(13) + CHAR(10) + '#################### ' + CONVERT( VARCHAR(24), GETDATE(), 121) + ' - Sauvegarde origine ' + @sourceDatabaseName + ' ####################'
PRINT '> ' + @query;
EXEC (@query)
PRINT '> OK!';

--Suppression de destination temp si existante
IF EXISTS(SELECT * FROM sysdatabases WHERE name = @targetDatabaseName)
BEGIN
	--Kill sessions destination temp
	PRINT CHAR(13) + CHAR(10) + '#################### ' + CONVERT( VARCHAR(24), GETDATE(), 121) + ' - Kill sessions destination temp ' + @targetDatabaseName + ' ####################'
	SET @query = 'ALTER DATABASE ' + @targetDatabaseName + ' SET  SINGLE_USER WITH ROLLBACK IMMEDIATE'
	PRINT '> Executing query : ' + @query;
	EXEC (@query)
	PRINT '> OK!'
	
	--Suppression destination temp
	PRINT CHAR(13) + CHAR(10) + '#################### ' + CONVERT( VARCHAR(24), GETDATE(), 121) + ' - Suppression destination temp existante ' + @targetDatabaseName + ' ####################'
	SET @query = 'DROP DATABASE ' + @targetDatabaseName
	PRINT '> Executing query : ' + @query;
	EXEC (@query)
	PRINT '> OK!'
END
ELSE
BEGIN
	PRINT CHAR(13) + CHAR(10) + 'INFO : La base cible ' + @targetDatabaseName + ' n''existe pas, suppression ignoree'
END

-- Restore destination temp
PRINT CHAR(13) + CHAR(10) + '#################### ' + CONVERT( VARCHAR(24), GETDATE(), 121) + ' - Restore destination temp ' + @targetDatabaseName + ' ####################'
SET @query = 'RESTORE DATABASE ' + @targetDatabaseName + ' FROM DISK = ' + QUOTENAME(@sourceBackupFile,'''') 
	 + ' WITH MOVE ' + QUOTENAME(@sourceDatabaseLogicalName,'''') + ' TO ' + QUOTENAME(@restoreDataFile ,'''')
	 + ' , MOVE ' + QUOTENAME(@sourceDatabaseLogicalNameLog,'''') + ' TO ' + QUOTENAME(@restoreLogFile,'''')
PRINT '> Executing query : ' + @query
EXEC (@query)
PRINT '> OK!'

IF @removeOriginalBackup = 1
BEGIN
	--Suppression backup origine
	PRINT CHAR(13) + CHAR(10) + '#################### ' + CONVERT( VARCHAR(24), GETDATE(), 121) + ' - Suppression backup origine ' + @sourceBackupFile + ' ####################'
	SET @query = 'del "' + @sourceBackupFile + '"'
	PRINT '> Executing query : ' + @query
	EXEC master..xp_cmdshell @query
	PRINT '> OK!'
END
ELSE
BEGIN
	PRINT CHAR(13) + CHAR(10) + 'INFO : Suppression backup original ignoree'
END

--Set target recovery à SIMPLE pour éviter logs
PRINT CHAR(13) + CHAR(10) + '#################### ' + CONVERT( VARCHAR(24), GETDATE(), 121) + ' - Set target recovery à SIMPLE pour éviter logs ####################'
SET @query = 'ALTER DATABASE ' + @targetDatabaseName + ' SET RECOVERY SIMPLE;'
PRINT '> Executing query : ' + @query
EXEC (@query)
PRINT '> OK!'

--Anonymisation des données
PRINT CHAR(13) + CHAR(10) + '#################### ' + CONVERT( VARCHAR(24), GETDATE(), 121) + ' - Anonymisation des donnees de ' + @targetDatabaseName + ' ####################'
SET @query = 'USE ' + @targetDatabaseName + '; EXEC ' + @sourceDatabaseName + '.' + @spAnonymiseDonnees + ' ''' + @sourceDatabaseName + ''', ''' + @targetDatabaseName + ''', 1;'
PRINT '> Query : ' + @query;
BEGIN TRY 
	EXEC (@query)
END TRY 
BEGIN CATCH 
	--Une erreur stoppe le script et en renvoie une personnalisée
	DECLARE @error AS nvarchar(max) = ERROR_MESSAGE();
	THROW 51000, @error, 1;
END CATCH
PRINT '> OK!';

--Remise target recovery à FULL
PRINT CHAR(13) + CHAR(10) + '#################### ' + CONVERT( VARCHAR(24), GETDATE(), 121) + ' - Remise target recovery à FULL ####################'
SET @query = 'ALTER DATABASE ' + @targetDatabaseName + ' SET RECOVERY FULL;'
PRINT '> Executing query : ' + @query
EXEC (@query)
PRINT '> OK!'

--Suppression procedure stockee anonymisation
PRINT CHAR(13) + CHAR(10) + '#################### ' + CONVERT( VARCHAR(24), GETDATE(), 121) + ' - Suppression procedure stockee anonymisation ' + @spAnonymiseDonnees + ' ####################'
SET @query = 'DROP PROCEDURE ' + @spAnonymiseDonnees + ';'
PRINT '> Query : ' + @query;
EXEC (@query)
PRINT '> OK!';

--Cryptage
IF @isEncryptionEnabled = 1
BEGIN
	--Vérification présence certificat
	IF (SELECT COUNT(*) FROM master.sys.certificates WHERE [name] = @certificateName) = 0
	BEGIN
		--Vérification présence master key
		IF (SELECT COUNT(*) FROM master.sys.symmetric_keys WHERE [name] LIKE '%DatabaseMasterKey%') = 0
		BEGIN
			--Création master key
			PRINT CHAR(13) + CHAR(10) + '#################### ' + CONVERT( VARCHAR(24), GETDATE(), 121) + ' - Creation master key ####################'
			SET @query = 'USE [master]; CREATE MASTER KEY ENCRYPTION BY PASSWORD = ''' + @certificateMasterKey + '''; '
			PRINT '> Executing query : ' + REPLACE(@query, @certificateMasterKey, '************' + RIGHT(@certificateMasterKey, 3))
			EXEC (@query)
			PRINT '> OK!'
		END
		ELSE
		BEGIN
			--Ouverture master key
			PRINT CHAR(13) + CHAR(10) + '#################### ' + CONVERT( VARCHAR(24), GETDATE(), 121) + ' - Ouverture master key ####################'
			SET @query = 'USE [master]; OPEN MASTER KEY DECRYPTION BY PASSWORD = ''' + @certificateMasterKey + '''; '
			PRINT '> Executing query : ' + REPLACE(@query, @certificateMasterKey, '************' + RIGHT(@certificateMasterKey, 3))
			EXEC (@query)
			PRINT '> OK!'
		END

		--Création certificat
		PRINT CHAR(13) + CHAR(10) + '#################### ' + CONVERT( VARCHAR(24), GETDATE(), 121) + ' - Creation certificat ####################'
		SET @query = 'USE [master]; CREATE CERTIFICATE ' + @certificateName + ' WITH SUBJECT = ''' + @certificateSubject + ''', EXPIRY_DATE = ''' + @certificateExpiryDate + '''; '
		PRINT '> Executing query : ' + @query
		EXEC (@query)
		PRINT '> OK!'

		--Export du certificat et de sa clé privée vers un fichier PFX, ce fichier permettra le restore de base
		PRINT CHAR(13) + CHAR(10) + '#################### ' + CONVERT( VARCHAR(24), GETDATE(), 121) + ' - Export certificat PFX ####################'
		SET @query = 'USE [master]; BACKUP CERTIFICATE PartenaireCertificate TO FILE = ''' + @certificatePath + '''
			WITH FORMAT = ''PFX'', PRIVATE KEY (ENCRYPTION BY PASSWORD = ''' + @certificatePrivateKey + ''',  ALGORITHM = ''AES_256'');'
		PRINT '> Executing query : ' + REPLACE(@query, @certificatePrivateKey, '************' + RIGHT(@certificatePrivateKey, 3))
		EXEC (@query)
		PRINT '> OK!'
	END
	ELSE
	BEGIN
		PRINT CHAR(13) + CHAR(10) + 'INFO : Certificat deja present'
	END
END
ELSE
BEGIN
	PRINT CHAR(13) + CHAR(10) + 'INFO : Cryptage cible inactif'
END

--Sauvegarde base anonymisée temporaire
PRINT CHAR(13) + CHAR(10) + '#################### ' + CONVERT( VARCHAR(24), GETDATE(), 121) + ' - Sauvegarde base anonymisee temporaire ' + @targetDatabaseName + ' ####################'
SET @query = 'BACKUP DATABASE ' + @targetDatabaseName 
	+ ' TO  DISK = ' + QUOTENAME(@targetBackupFileAnonyme,'''')
	+ ' WITH FORMAT'
	+ CASE WHEN @backupStatsPercentage IS NOT NULL THEN ', STATS=' + CAST(@backupStatsPercentage AS nvarchar(3)) ELSE '' END
	+ CASE WHEN @compressTargetBackup = 1 THEN ', COMPRESSION' ELSE '' END
	+ CASE WHEN @isEncryptionEnabled = 1 THEN ', ENCRYPTION(ALGORITHM = AES_256, SERVER CERTIFICATE = [' + @certificateName + '])' ELSE '' END
PRINT '> Query : ' + @query;
EXEC (@query)
PRINT '> OK!';

--Suppression base anonymisée temporaire
PRINT CHAR(13) + CHAR(10) + '#################### ' + CONVERT( VARCHAR(24), GETDATE(), 121) + ' - Suppression base anonymisee temporaire ' + @targetDatabaseName + ' ####################'
SET @query = 'DROP DATABASE ' + @targetDatabaseName
PRINT '> Query : ' + @query;
EXEC (@query)
PRINT '> OK!'

--Déplacement sauvegarde anonymisee vers support final
IF @targetBackupFileAnonymeMoveTo IS NOT NULL
BEGIN
	PRINT CHAR(13) + CHAR(10) + '#################### ' + CONVERT( VARCHAR(24), GETDATE(), 121) + ' - Déplacement sauvegarde anonymisee vers support final ' + @targetBackupFileAnonymeMoveTo + ' ####################'
	SET @query = 'move "' + @targetBackupFileAnonyme + '" "' + @targetBackupFileAnonymeMoveTo + '"'
	PRINT '> Executing query : ' + @query
	EXEC master..xp_cmdshell @query
	PRINT '> OK!'
END
ELSE
BEGIN
	PRINT CHAR(13) + CHAR(10) + 'INFO : Deplacement backup anonymise vers cible ignore'
END

PRINT CHAR(13) + CHAR(10) + '#################### ' + CONVERT( VARCHAR(24), GETDATE(), 121) + ' - Script complet d''anonymisation termine ####################'

GO
