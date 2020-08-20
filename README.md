# tetcli 
This application helps to interact with Tetration using CLI. You can do show, create, download, upload into Tetration Analytics Cluster.

## Table of contents
* [Installation](#Installation)
* [Screenshots](#screenshots)
* [How to Use](#UserGuide)
* [Show Commands](#Show)
* [Create Commands](#Create)
* [Setup Commands](#Setup)
* [Clean Commands](#Clean)
* [Others Commands](#Others)
* [Steps to run](#Steps)
* [Feedback and Author](#Feedback)

## Installation

From sources

Download the sources from [Github](https://github.com/leeahnduk/TetCLI.git), extract and execute the following commands

```
$ pip3 install -r requirements.txt

```

## Screenshots
![Example screenshot](https://github.com/leeahnduk/TetCLI/blob/master/tetcli.jpg)

## UserGuide
How to use this application:
To access to the cluster you need to get the API Credentials with the following permissions
* `sensor_management` - option: SW sensor management: API to configure and monitor status of SW sensors
* `hw_sensor_management` - option: HW sensor management: API to configure and monitor status of HW sensors
* `flow_inventory_query` - option: Flow and inventory search: API to query flows and inventory items in Tetration cluster
* `user_role_scope_management` - option: Users, roles and scope management: API for root scope owners to read/add/modify/remove users, roles and scopes
* `app_policy_management` - option: 
 Applications and policy management: API to manage applications and enforce policies

Download the api_credentials.json locally and have it ready to get the information required for the setup.

A quick look for the help will list the current available options.
To start the script, just use: `python3 tetcli.py --url https://tet-cluster-ip --credential api_credentials.json`
```

Object support:
  * agents          Interact with Software Sensors in Tetration Cluster
  * inventories     Interact with Inventory from Tetration Cluster
  * vrfs            Interact with VRFs in Tetration Cluster
  * applications    Interact with ADM Application from Tetration Cluster
  * users           Interact with Users from Tetration Cluster
  * roles           Interact with Roles in Tetration Cluster
  * scopes          Interact with Scopes configured in Tetration Cluster
  * annotations     Download and upload annotations from and into Tetration Cluster
  * flow            Interact with Flows captured by Tetration Cluster
  * orchestrators   Interact with External Orchestrators (vCenter and K8s) configured in Tetration Cluster
  * policies        Interact with Policies inside Application from Tetration Cluster
  * filehash        Download and upload blacklist or whitelist process binary hash from and into Tetration Cluster
  * report          Build report for a Tetration cluster 

Operator support:
  * show            show all items for a object 
  * show item       show detail of an object item 
  * create item     create an object item 
  * setup           onboard a new cluster or tenant
  * clean           delete all objects in one root scope

```

Each subcommand has its own help that list the options available.

```
You can use -h, help, h, ? to get help and options
```

## Show
```
tetcli #  show ?
Sub commands support: inventories, vrfs, applications, users, roles, scopes, flows, agents, orchestrators, policies

tetcli #  show agents ?
Items support: all, os , osversion

tetcli #  show inv ?
Items support: all, detail 

tetcli #  show apps ?
Items support: all, brief, detail, version, clusters, enforced

tetcli #  show scopes ?
Items support: all, roots, subscopes 

tetcli #  show vrfs ?
Items support: all 

tetcli #  show users ?
Items support: all, detail

tetcli #  show roles ?
Items support: all, detail 

tetcli #  show flows ?
Items support: dimensions, metrics 

tetcli #  show orc ?
Items support: all, detail

tetcli #  show pol ?
Items support: all, brief, detail 
```
## Create
```
tetcli #  agents profiles create 
Create Agent config profile

tetcli #  scopes create ?
Items support: root, subscope, commit 

tetcli #  vrfs create ?
Items support: remote 

tetcli #  inventories create ?
Items support: none. Create inventories

tetcli #  orchestrators create ?
Items support: vcenter, k8s

tetcli #  roles create ?
Create role, sub command: none

tetcli #  user create ?
Create user, sub command: none 

tetcli #  apps create ?
Create app workspace under a scope without policies, sub command: none  

tetcli #  pol create ?
Create Policies or Clusters under an existing application workspace, sub command: clusters, ports 
```
## Report
```
tetcli #  report workloads all 
Report all installed workloads in your cluster in all scopes

tetcli #  report workloads detail
Detail Report about a specific workload 

tetcli #  report workloads stats
Detail Workload communication report from time (t0) to time(t1) 

tetcli #  report workloads software 
Detail Installed Software Packages report for a specific workload

tetcli #  report workloads vulnerabilities ?
Detail Vulnerable Software Packages report for a specific workload or all workloads that match a CVE Score query. Sub: workload or all

tetcli #  report workloads vulnerabilities all
Detail Vulnerable Software Packages report for all workloads that match a CVE score query.

tetcli #  report workloads vulnerabilities workload
Detail Vulnerable Software Packages report for a specific workload.

tetcli #  report workloads processes ?
Detail Running processes report for a specific workload. Sub command: summary or all

tetcli #  report workloads processes summary
Summary Running processes report for a specific workload.

tetcli #  report workloads processes all
Detail all Running processes report for a specific workload.

tetcli #  report apps ?
Build application report into xlsx format. Sub command: conversation or policies

tetcli #  report apps conv
Download conversation report into xlsx format for a specific application.

tetcli #  report apps pol
Build detail application policies report into xlsx format.

tetcli #  report flows ?
Build top flow report in a specific timerange. Sub command: inventory or top

tetcli #  report flows inv
Detail flow communication report about a subnet in a VRF from time (t0) to time(t1).

tetcli #  report flows top ?
Top Talkers/Destination/Service report in excel for a scope from time (t0) to time(t1). Sub command: talkers, servers, sports, dports

tetcli #  report flows top talkers
Top Talkers report in excel for a scope from time (t0) to time(t1).

tetcli #  report flows top dest
Top Destination report in excel for a scope from time (t0) to time(t1).

tetcli #  report flows top sport
Top source Service report in excel for a scope from time (t0) to time(t1). 

tetcli #  report flows top dport
Top Destination Service report in excel for a scope from time (t0) to time(t1). Sub command: talkers, servers, sports, dports


```

## Setup
```
tetcli #  setup ?
Here are basic steps to fresh start a Tetration tenant
```

## Clean
```
tetcli #  clean ?
You are about to delete all objects under a scope.
```

## Others
```
tetcli #  agents download ?
Download Tetration Installation file. Items support: none

tetcli #  annotations download
Download annotation file into AnnotationDownload.csv

tetcli #  annotations upload
Upload annotation file into Tetration scope. Need to put Tetration Annotation csv file: "sampleAnnotationUpload.csv" into the same folder. Sample csv file attached in the github repo.

tetcli #  roles apply ?
Apply role to scope, sub command: none  

tetcli #  filehash ?
Items support: download, upload, delete 

tetcli #  filehash download
Download Blacklist or Whitelist process binary hash information into "FileHashDown.csv".

tetcli #  filehash upload
Upload Blacklist or Whitelist process binary hash file into Tetration scope. Need to put Blacklist or Whitelist process binary hash csv file: "sampleFileHashUpload.csv" into the same folder. Sample csv file attached in the github repo. Sample csv: HashType,FileHash,FileName,Notes

tetcli #  filehash delete
Delete Blacklist or Whitelist process binary hash file from Tetration scope. Need to put Blacklist or Whitelist process binary hash csv delete file: "FileHashDelete.csv" into the same folder. Sample csv file attached in the github repo.

tetcli #  policies download
Get Server Ports config to root scope. Return server ports config. Return a JSON file.

tetcli #  policies upload
Upload Server Ports config to root scope for ADM support. Need to put server port config file: "server_ports.txt" into the same folder "server_ports.txt". Sample txt file attached in the github repo.

tetcli #  policies convert csv
Convert one or more application workspace policies into xlsx format. Output files: policies.json and policies.xlsx
```


## Steps

Step 1: Issue `$ pip3 install -r requirements.txt` to install all required packages.

Step 2: Run the apps: `python3 tetcli.py --url https://tet-cluster-ip --credential api_credentials.json`

Step 3: Test if you can successfully query the cluster from the command line
```
tetcli #  show agents all
Here is the sensors detail: 
```

## Feedback
Any feedback can send to me: Le Anh Duc (leeahnduk@yahoo.com or anhdle@cisco.com)
