@echo off

REM Auteur :	Gilles Lautrou
REM Date :		30/08/2023
REM Versions :	- 1.0 : Création initiale

REM Ce script va anonymiser une base de donnees en y creant un fichier BAK anonymise final.
REM Le lancer au moins la première fois en mode Administrateur, sinon l'appel "icacls" pour certificat échouera.
REM Pour lancer en mode Administrateur, soit double-cliquer sur le raccourci "01-Anonymisation.bat (admin).lnk", soit faire clic-droit > Exécuter en admin
REM Pre-requis : Utilitaire SQL Server "sqlcmd"
REM Une fois le script termine, la console affichera s'il est OK ou KO.
REM L'ensemble des logs seront generes dans /Output ainsi que dans la console.

echo Script en cours d'execution...

REM Placement dans répertoire local du script car l'exécution via le raccourci admin changeait le chemin vers system32
pushd "%~dp0"

REM Parametrage
set sqlInstance=[TODO_NomInstance]
set sqlUsername=sa
set sqlPassword=[TODO_MotDePasse]
set dbName=[TODO_NomDbOrigne]
set certificatePath=PartenaireCertificate.pfx
set startTime=%time%

REM Calcul date logs
set dt=%DATE:~6,4%-%DATE:~3,2%-%DATE:~0,2%_%TIME:~0,2%-%TIME:~3,2%-%TIME:~6,2%
set dt=%dt: =0%
set logFile=Output\%dt%_02-Restore.sql-Output.txt

REM Verification pre-requis
where /q sqlcmd
IF ERRORLEVEL 1 (
    set error=%ERRORLEVEL%
	ECHO [91m"Cet utilitaire necessite sqlcmd.exe qui est manquant sur la machine. Il est par defaut installe avec SSMS, ou peut etre installe separemment via ce lien : https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-utility?view=sql-server-ver16&tabs=odbc%2Cwindows#download-and-install-sqlcmd"[0m
    (goto errorScript)
)

REM Creation repertoire logs
if not exist "Output" mkdir "Output"

echo ==================================================================================

REM Creation procedure stockee d'anonymisation des donnees
sqlcmd -S "%sqlInstance%" -U "%sqlUsername%" -P "%sqlPassword%" -d "%dbName%" -i "sp_AnonymiseDonnees.sql" -o "%logFile%"
set error=%ERRORLEVEL%
REM Affichage output
echo Logs sp_AnonymiseDonnees.sql :
type "%logFile%"
REM Gestion erreurs
findstr /m "Msg ERREUR" "%logFile%" >Nul
if %errorlevel%==0 (goto errorScript)
if NOT %error% == 0 (goto errorScript)

echo.
echo ==================================================================================

REM Execution SQL d'anonymisation
sqlcmd -S "%sqlInstance%" -U "%sqlUsername%" -P "%sqlPassword%" -d "%dbName%" -i "01-Anonymisation.sql" -o "Output\%dt%_01-Anonymisation.sql-Output.txt"
set error=%ERRORLEVEL%
REM Affichage output
echo Logs 01-Anonymisation.sql :
type "Output\%dt%_01-Anonymisation.sql-Output.txt"
REM Gestion erreurs
findstr /m "Msg ERREUR" "Output\%dt%_01-Anonymisation.sql-Output.txt" >Nul
if %errorlevel%==0 (goto errorScript)
if NOT %error% == 0 (goto errorScript)

echo.
echo ==================================================================================

REM Le certificat est cree avec des droits que pour le compte SQL, ajout des droits "Tout le monde" afin de pouvoir le transmettre pour le restore
if exist "%certificatePath%" (
	echo Ajout des droits lecture au certificat
	REM "*S-1-1-0" est le SID pour "Tout le monde" ("Everyone")
	REM icacls "%certificatePath%" /grant "*S-1-1-0":(OI^)(CI^)M
	icacls "%certificatePath%" /grant "*S-1-1-0":R
) else (
	echo Pas de certificat a modifier
)
goto succesScript

:succesScript
REM Sortie success
echo.
echo.
echo ==================================================================================
echo [102m [102m Anonymisation de la base effectuee avec succes [0m
echo [92m Error code : %error% [0m
echo Heure Debut : %startTime%
echo Heure fin: %time%
echo ==================================================================================
pause
exit

:errorScript
REM Sortie erreur
echo.
echo.
echo ==================================================================================
echo [101;93m ERREUR : Une erreur s'est produite ! Echec de l'anonymisation [0m
echo [91m Error code : %error% [0m
echo Heure Debut : %startTime%
echo Heure fin: %time%
echo ==================================================================================
pause
exit
