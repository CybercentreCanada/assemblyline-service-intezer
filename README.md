# IntezerStatic service
This repository is an Assemblyline service that fetches the Intezer report for the SHA256 of a submitted file.

**NOTE**: This service **requires** you to have your own API key (Paid or Free). It is **not** preinstalled during a default installation.

## Execution

This service calls the Intezer Analyze API with the hash of your file and returns the results (if any).

Because this service queries an external API, if selected by the user, it will prompt the user and notify them that their file or metadata related to their file will leave the Assemblyline system.

### Service Tweaks
If you are using an Inteer Analyze On-Premise solution, then you do not need to set this service as `External`. Change the `category` in the `service_manifest.yml` from `External` to `Dynamic` if you are using Intezer's Dynamic Execution module, or `Antivirus` otherwise.

If you are using Intezer's Dynamic Execution module, then set the service timeout to 300 seconds rather than 60 seconds for antivirus capabilities.

### Configuration Values
* **base_url**: This is the base url of the Intezer Analyze instance that you will be using. *NB* The public instance is at [https://analyze.intezer.com](https://analyze.intezer.com), but you can also set it to http://\<ip of private instance>. Don't forget the /api/ at the end of the URL!
* **api_version**: This service has only been tested with `v2-0`.
* **api_key**: This is the 36 character key provided to you by [Intezer](https://www.intezer.com/blog/malware-analysis/api-intezer-analyze-community/).
* **private_only**: This is a flag that will only return private submissions on the Intezer Analyze system, if selected.
