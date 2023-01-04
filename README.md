# Intezer service
This repository is an Assemblyline service that fetches the Intezer Analyze report for the SHA256 of a submitted file, and (optionally!) if the SHA256 was not found on the Intezer Analyze instance, then this service will submit that file.

**NOTE**: This service **requires** you to have your own API key (Paid or Free). It is **not** preinstalled during a default installation.

**NOTE!**: This service **requires** extensive setup prior to installation if you are deploying your own instance of IntezerAnalyze.

**NOTE!!** This service deprecates the [IntezerStatic](https://github.com/CybercentreCanada/assemblyline-service-intezer-static) service and merges it with the IntezerDynamic service. The submission of a file to Intezer is now a service and submission configuration option.

## Execution

This service calls the Intezer Analyze API with the hash of your file and returns the results (if any).

Because this service could query an external API, if selected by the user, it will prompt the user and notify them that their file or metadata related to their file will leave the Assemblyline system.

**NOTE:** This service **requires** you to have your own API key (Paid or Free). It is **not** preinstalled during a default installation.

### Service Tweaks
If you are using an Intezer Analyze On-Premise solution, then you do not need to set this service as `External` and the `is_external` flag to true. Change the `category` in the `service_manifest.yml` from `External` to `Dynamic Analysis` if you are using Intezer's Dynamic Execution module on-prem, or `Antivirus` otherwise.

If you are using Intezer's Dynamic Execution module, then set the service timeout to 300 seconds rather than 60 seconds for just antivirus capabilities.

### Configuration Values
* **base_url**: This is the base url of the Intezer Analyze instance that you will be using. *NB* The public instance is at [https://analyze.intezer.com](https://analyze.intezer.com), but you can also set it to http://\<ip of private instance>. Don't forget the /api/ at the end of the URL!
* **api_version**: This service has only been tested with `v2-0`.
* **api_key**: This is the 36 character key provided to you by [Intezer](https://www.intezer.com/blog/malware-analysis/api-intezer-analyze-community/).
* **private_only**: This is a flag that will only return private submissions on the Intezer Analyze system, if selected.
* **is_on_premise**: This is a flag used for indicating if the Intezer Analyze system is on-premise, rather than the cloud API.
* **retry_forever**: This is a flag used for indicating if the service should poll the Intezer Analyze system until it gets a response. If set to `false`, the service will raise an exception immediately.
* **allow_dynamic_submit**: This flag allows users to submit files to the Intezer Analyze system for analysis, if the hash does not already exist on that system.
* **polling_period_in_seconds**: This integer is the time to wait between status checks for the current analysis.
* **analysis_timeout_in_seconds**: This integer is the time to wait for an analysis to complete.
* **try_to_download_every_file**: This is a flag used for indicating if we want to attempt to download every available file, despite receiving an error on a previous attempt.

### Submission Parameters
* **analysis_id**: This is the analysis ID of an analysis that is already on the system. The cloud API counts retrieving the analysis by file hash as a "File Scan" which counts towards an account's monthly quota. We can circumvent this by submitting the analysis ID of an analysis. That being said, this will ignore the file that you submit to Assemblyline.
* **dynamic_submit**: Instructs the service to submit to Intezer Analyze if there is no existing analysis for that sample on the system. For this to work, **allow_dynamic_submit** must be set to `True`.

## Troubleshooting
If you get this error "server returns The request is not valid, details: {'should_get_only_private_analysis': ['unknown field']}", then you need to set the service configuration value to true for "is_on_premise".
