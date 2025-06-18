[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline\_service\_intezer-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-intezer)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-intezer)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-intezer)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-intezer)](./LICENSE)
# Intezer Service

This service fetches results from Intezer based on the submitted file's SHA256 hash.

## Service Details
This repository is an Assemblyline service that fetches the Intezer Analyze report for the SHA256 of a submitted file, and (optionally!) if the SHA256 was not found on the Intezer Analyze instance, then this service will submit that file.

It was created by [x1mus](https://github.com/x1mus) with support from [Sorakurai](https://github.com/Sorakurai) and [reynas](https://github.com/reynas) at [NVISO](https://github.com/NVISOsecurity).

It has since been passed over to the CCCS :canada: for maintenance!

**NOTE**: This service **requires** you to have your own API key (Paid or Free). It is **not** preinstalled during a default installation.

**NOTE!**: This service **requires** extensive setup prior to installation if you are deploying your own instance of IntezerAnalyze.

### Execution

This service calls the Intezer Analyze API with the hash of your file and returns the results (if any).

Because this service could query an external API, if selected by the user, it will prompt the user and notify them that their file or metadata related to their file will leave the Assemblyline system.

#### Service Tweaks
If you are using an Intezer Analyze On-Premise solution, then you do not need to set this service as `External` and the `is_external` flag to true. Change the `category` in the `service_manifest.yml` from `External` to `Dynamic Analysis` if you are using Intezer's Dynamic Execution module on-prem, or `Antivirus` otherwise.

If you are using Intezer's Dynamic Execution module, then set the service timeout to 300 seconds rather than 60 seconds for just antivirus capabilities.

#### Configuration Values
* `base_url`: This is the base url of the Intezer Analyze instance that you will be using. *NB* The public instance is at [https://analyze.intezer.com](https://analyze.intezer.com), but you can also set it to http://\<ip of private instance>. Don't forget the /api/ at the end of the URL!
* `api_version`: This service has only been tested with `v2-0`.
* `api_key`: This is the 36 character key provided to you by [Intezer](https://www.intezer.com/blog/malware-analysis/api-intezer-analyze-community/).
* `private_only`: This is a flag that will only return private submissions on the Intezer Analyze system, if selected.
* `is_on_premise`: This is a flag used for indicating if the Intezer Analyze system is on-premise, rather than the cloud API.
* `retry_forever`: This is a flag used for indicating if the service should poll the Intezer Analyze system until it gets a response. If set to `false`, the service will raise an exception immediately.
* `allow_dynamic_submit`: This flag allows users to submit files to the Intezer Analyze system for analysis, if the hash does not already exist on that system.
* `polling_period_in_seconds`: This integer is the time to wait between status checks for the current analysis.
* `analysis_timeout_in_seconds`: This integer is the time to wait for an analysis to complete.
* `try_to_download_every_file`: This is a flag used for indicating if we want to attempt to download every available file, despite receiving an error on a previous attempt.
* `download_subfiles`: This is a flag used for indicating if we want to download sub files. Users may want to set this to `false` because extracted [files that are downloaded count against your quota](https://docs.intezer.com/docs/quota-consumption).
* `min_malware_genes`: This is the minimum number of "malware" genes found in the "Family Details" for us to set the verdict of the analysis to malicious.
* `score_administration_tools`: This is a flag used for indicating if we want to score files marked as "administration tools" as suspicious. If set to `false`, then no file with this designation will score based on this.
* `use_black_box_verdicts`: This is a flag used for indicating if we want to use the verdict that the Intezer assigns an analysis based on their proprietary algorithm for verdicts. If not, we will rely on gene counts.

#### Submission Parameters
* `analysis_id`: This is the analysis ID of an analysis that is already on the system. The cloud API counts retrieving the analysis by file hash as a "File Scan" which counts towards an account's monthly quota. We can circumvent this by submitting the analysis ID of an analysis. That being said, this will ignore the file that you submit to Assemblyline.
* `dynamic_submit`: Instructs the service to submit to Intezer Analyze if there is no existing analysis for that sample on the system. For this to work, `allow_dynamic_submit` must be set to `True`.

### Troubleshooting
If you get this error `"server returns The request is not valid, details: {'should_get_only_private_analysis': ['unknown field']}"`, then you need to set the service configuration value to true for "is_on_premise".

## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name Intezer \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-intezer

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service Intezer

Ce service récupère les résultats d'Intezer sur la base du hachage SHA256 du fichier soumis.

## Détails du service
Ce dépôt est un service Assemblyline qui récupère le rapport Intezer Analyze pour le SHA256 d'un fichier soumis, et (optionnellement !) si le SHA256 n'a pas été trouvé sur l'instance Intezer Analyze, alors ce service soumettra ce fichier.

Il a été créé par [x1mus](https://github.com/x1mus) avec le soutien de [Sorakurai](https://github.com/Sorakurai) et [reynas](https://github.com/reynas) à [NVISO](https://github.com/NVISOsecurity).

Il a depuis été transféré à la CCCS :canada : pour maintenance !

**NOTE** : Ce service **exige** que vous ayez votre propre clé API (payante ou gratuite). Il n'est **pas** préinstallé lors d'une installation par défaut.

**NOTE!** : Ce service **requiert** une configuration extensive avant l'installation si vous déployez votre propre instance d'IntezerAnalyze.

### Exécution

Ce service appelle l'API IntezerAnalyze avec le hash de votre fichier et renvoie les résultats (s'il y en a).

Parce que ce service pourrait interroger une API externe, s'il est sélectionné par l'utilisateur, il invitera l'utilisateur et l'informera que son fichier ou les métadonnées liées à son fichier quitteront le système Assemblyline.

#### Service Tweaks
Si vous utilisez une solution Intezer Analyze On-Premise, alors vous n'avez pas besoin de définir ce service comme `External` et le drapeau `is_external` à true. Changez la `catégorie` dans le `service_manifest.yml` de `External` à `Dynamic Analysis` si vous utilisez le module Dynamic Execution d'Intezer sur site, ou `Antivirus` sinon.

Si vous utilisez le module d'exécution dynamique d'Intezer, alors définissez le timeout du service à 300 secondes au lieu de 60 secondes pour les capacités antivirus.

#### Valeurs de configuration
* `base_url` : C'est l'url de base de l'instance d'Intezer Analyze que vous allez utiliser. *NB* L'instance publique est à [https://analyze.intezer.com](https://analyze.intezer.com), mais vous pouvez aussi la mettre à http://\<ip de l'instance privée>. N'oubliez pas le /api/ à la fin de l'URL !
* `api_version` : Ce service n'a été testé qu'avec `v2-0`.
* `api_key` : C'est la clé de 36 caractères qui vous est fournie par [Intezer] (https://www.intezer.com/blog/malware-analysis/api-intezer-analyze-community/).
* `private_only` : C'est un drapeau qui ne renverra que les soumissions privées sur le système Intezer Analyze, s'il est sélectionné.
* `is_on_premise` : C'est un drapeau utilisé pour indiquer si le système Intezer Analyze est sur site, plutôt que l'API dans le nuage.
* `retry_forever` : C'est un drapeau utilisé pour indiquer si le service doit interroger le système Intezer Analyze jusqu'à ce qu'il obtienne une réponse. S'il est positionné à `false`, le service lèvera une exception immédiatement.
* `allow_dynamic_submit` : Ce drapeau permet aux utilisateurs de soumettre des fichiers au système Intezer Analyze pour analyse, si le hash n'existe pas déjà sur ce système.
* `polling_period_in_seconds` : Cet entier est le temps d'attente entre les vérifications d'état pour l'analyse en cours.
* `analysis_timeout_in_seconds` : Cet entier est le temps d'attente pour la fin d'une analyse.
* `try_to_download_every_file` : C'est un drapeau utilisé pour indiquer si nous voulons essayer de télécharger tous les fichiers disponibles, même si nous avons reçu une erreur lors d'une tentative précédente.
* `download_subfiles` : C'est un drapeau utilisé pour indiquer si nous voulons télécharger les sous-fichiers. Les utilisateurs peuvent vouloir mettre cette option à `false` parce que les [fichiers téléchargés sont décomptés de votre quota] (https://docs.intezer.com/docs/quota-consumption).
* `min_malware_genes` : C'est le nombre minimum de gènes « malware » trouvés dans les « détails de la famille » pour que le verdict de l'analyse soit malveillant.
* `score_administration_tools` : Il s'agit d'un drapeau utilisé pour indiquer si nous voulons classer les fichiers marqués comme « outils d'administration » comme suspects. S'il vaut `false`, aucun fichier avec cette désignation ne sera évalué sur cette base.
* `use_black_box_verdicts` : Il s'agit d'un drapeau utilisé pour indiquer si nous voulons utiliser le verdict que l'Intezer attribue à une analyse sur la base de leur algorithme propriétaire pour les verdicts. Si ce n'est pas le cas, nous nous baserons sur le nombre de gènes.

#### Paramètres de soumission
* `analysis_id` : Il s'agit de l'identifiant d'une analyse déjà présente dans le système. L'API du cloud comptabilise la récupération de l'analyse par le hachage du fichier comme une « analyse de fichier » qui compte dans le quota mensuel d'un compte. Nous pouvons contourner ce problème en soumettant l'ID d'une analyse. Ceci étant dit, ceci ignorera le fichier que vous soumettez à Assemblyline.
* `dynamic_submit` : Indique au service de soumettre à Intezer Analyze s'il n'y a pas d'analyse existante pour cet échantillon sur le système. Pour que cela fonctionne, `allow_dynamic_submit` doit être réglé sur `True`.

### Dépannage
Si vous obtenez cette erreur `"server returns The request is not valid, details : {'should_get_only_private_analysis' : ['unknown field']}"`, alors vous devez mettre la valeur de configuration du service à true pour “is_on_premise”.

## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Ce service est spécialement optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name Intezer \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-intezer

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
