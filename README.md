# microseg

## Description

This application helps to build a zero-trust environment that micro-segments an existing EPG of an ACI. The segmentation is based on analytics from  AppDynamics. It can also support manual pre-configured JSON file to present your segmentation idea.

## Installation

The microseg dosen't need to install. It's a python script directly running in your python environment.

## Environment

Required <br>
* Python 2.7+ <br>
* ACI and compatible ACI Cobra SDK <br>

Optional
* AppDynamics 4.3+

## Usage

Directly running the script with ‘python microseg.py’, the usage tips will be shown. 
If you want to micro-segment the ACI EPG in which the application resides, you should provide the name of ACI Tenant, Application Profile. If the application is AppDynamics(AppD) monitored, just give the name of the application in AppDynamics. For example:
``` bash
        python microseg.py --tenant hangwe-tn --approfile hangwe-useg-ap --application courseback
```
If the application name omits, you will need JSON files for manual application definition. For example:
* ‘app_mapping.json’ for application tiers/hosts mapping
```json
{
  "Web": [
    "172.16.1.14",
    "172.16.1.15",
    "172.16.1.16"
  ],
  "App": [
    "172.16.1.24"
  ],
  "DB": [
    "172.16.1.34"
  ]
}
```
* ‘tier_relationship.json’ to build the application tiers relationships
```json
{
  "Web": {
    "app2web": [
      "consume"
    ]
  },
  "App": {
    "db2app": [
      "consume"
    ],
    "app2web": [
      "provide"
    ]
  },
  "DB": {
    "db2app": [
      "provide"
    ]
  }
}
```

Currently the microseg is used only for demo purpose. For productive usage, please contact the author at: weihang_hank@gmail.com
