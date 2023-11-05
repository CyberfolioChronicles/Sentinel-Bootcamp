<h1>🛡️ Microsoft Sentinel Lab Series 🛡️</h1>


 ### [YouTube Demonstration Playlist](https://www.youtube.com/playlist?list=PLTNt8j7SunIDfFKRerAPNIGWuj16UfLgO)


<h2>Description</h2>
<b>Welcome to the Microsoft Sentinel Lab Series, a comprehensive guide to mastering Microsoft Sentinel and bolstering your cybersecurity skills. This repository contains 8 labs, comprising a total of 29 hands-on exercises, meticulously crafted to elevate your understanding of threat detection, incident management, analytics, and more. Whether you're a security enthusiast or a seasoned professional, this series is your key to unlocking the full potential of Microsoft Sentinel. Dive in, level up your security game, and fortify your defenses. 🚀
The lab deploys a Microsoft Sentinel workspace and ingests pre-recorded data to simulate scenarios that showcase various Microsoft Sentinel features. You should expect very little or no cost at all due to the size of the data (~10 MBs) and the fact that Microsoft Sentinel offers a 30-day free trial.
</b>

<h2>Prerequisites</h2>

To deploy the Microsoft Sentinel Training Lab, you must have a Microsoft Azure subscription. If you do not have an existing Azure subscription, you can sign up for a free trial.

<h3>Module 1 - Setting up the environment</h3>

🎓 Level: 100 (Beginner)
⌛ Estimated time to complete this lab: 20 minutes

### Objectives

This module guides you through the deployment of the Microsoft Sentinel Training Lab
solution that will be used in all subsequent modules.

### Prerequisites

To get started with Microsoft Sentinel, you must have a Microsoft Azure subscription. If you do not have a subscription, you can sign up for a free account. 
Permission to create a resource group in your Azure subscription.

### Exercise 1: The Microsoft Sentinel workspace
In this exercise, we will show you how to create a brand-new Microsoft Sentinel workspace. If you already have a pre-existing one that you would like to use, you can skip to Exercise 2.

1. Navigate to the Azure Portal and log in with your account.
2. In the top search bar, type Microsoft Sentinel and click on Microsoft Sentinel.
3. In the Microsoft Sentinel screen, click Create at the top left.
4. You can choose to add Microsoft Sentinel to an existing Log Analytics workspace or build a new one. We will create a new one, so click on Create a new workspace.
5. In the Create Log Analytics workspace page, fill out the form as follows:

○ Subscription: Choose the Azure subscription where you would like to deploy the Microsoft Sentinel workspace.
○ Resource Group: Select an existing resource group or create a new resource group (recommended) that will host the lab resources.
○ Region: From the drop-down, select the Azure region where the lab will be located.
○ Workspace Name: Provide a name for the Microsoft Sentinel workspace. Please note that the workspace name should include 4-63 letters, digits, or '-'. The '-' shouldn't be the first or the last symbol. Click Review + Create and then Create after the validation completes. The creation takes a few seconds.
7. You will be redirected back to the Add Microsoft Sentinel to a workspace. Type the name of your new workspace in the search box, select your workspace, and click Add at the bottom.
Your Microsoft Sentinel workspace is now ready to use!

### Exercise 2: Deploy the Microsoft Sentinel Training Lab

Solution

In this exercise, you will deploy the Training Lab solution into your existing workspace. This will ingest pre-recorded data (~20 MBs) and create several other artifacts that will be used during the exercises.
1. In the Azure Portal, go to the top search bar and type Microsoft Sentinel Training. Select the Microsoft Sentinel Training Lab Solution (Preview) marketplace item on the right.
2. Read the solution description and click Create at the top.
3. In the Basics tab, select the Subscription, Resource Group, and Workspace that you created in Exercise 1, or the details for your existing workspace. Optionally, review the different tabs (Workbooks, Analytics, Hunting Queries, Watchlists, Playbooks) in the solution. When ready, click on Review + Create.
4. Once validation is ok, click on Create. The deployment process takes about 15 minutes, this is because we want to make sure that all the ingested data is ready for you to use once finished.
5. Once the deployment finishes, you can go back to Microsoft Sentinel and select your workspace. On the home page, you should see some ingested data and several recent incidents. Don't worry if you don't see 3 incidents like in the screenshot below, they might take a few minutes to be raised.

### Exercise 3: Configure Microsoft Sentinel Playbook

In this exercise, we will configure a Playbook that will be later used in the lab. This will allow the playbook to access Sentinel.

1. Navigate to the resource group where the lab has been deployed.
2. In the resource group you should see an API Connection resource called azuresentinel-Get-GeoFromIpAndTagIncident, click on it.
3. Click on Edi API connection under General.
4. Click on Authorize and a new window will open to choose an account. Pick the user that you want to authenticate with. This should normally be the same user that you're logged in with.
5. Click Save.

<h3>Module 2 - Data Connectors</h3>

🎓 Level: 100 (Beginner)
⌛ Estimated time to complete this lab: 15 minutes

### Objectives
In this module, you will learn how to enable Data Connectors in Microsoft Sentinel to bring alerts and/or telemetry from different sources.

### Prerequisites
This module assumes that you have completed Module 1, as you will need a Microsoft Sentinel workspace provisioned. Some of the data connectors that will be used in this lab, require some specific permissions on the workspace or your Azure subscription. If you don't have the appropriate permissions, you can still continue doing the rest of the labs.

### Exercise 1: Enable Azure Activity data connector

This exercise shows you how to enable the Azure Activity data connector. This connector will bring into your Microsoft Sentinel workspace all the audit events for actions performed in your Azure subscription.
NOTE: To do this exercise, your user must have Reader permissions to any subscription that logs you want to stream into Microsoft Sentinel.
1. Go to your Microsoft Sentinel workspace and select Data Connectors under the Configuration section.
2. In the data connectors screen, type activity in the search bar, select the Azure Activity connector and click on the Open connector page.
3. In the Azure Activity connector page, go to option number 2 Connect your subscriptions through the diagnostic settings new pipeline. This method leverages Azure Policy and it brings many improvements compared to the old method (more details about these improvements can be found here).
4. Click on the Launch Azure Policy Assignment wizard, this will redirect you to the policy creation page. On the Scope selection select your relevant subscription.
NOTE: Please note that if you have owner permission on a management group level,
you can assign this policy to configure the collection of Azure Activity logs from all the subscriptions under the management group.
5. Go to the Parameters tab. On the Primary Log Analytics workspace select the Microsoft Sentinel workspace.
6. Press Review and Create to save this policy and Create.
7. Click on Next Steps. Here you see what content is available for the telemetry that is brought into Sentinel by this connector, like Workbooks, Query samples, and Analytics Rules.
8. It is normal if you don't immediately see the connector showing as connected and in green. Also, each subscription has a maximum of 5 destinations for its activity logs. If this limit is already reached, the policy created as part of this exercise won't be able to add an additional destination to your Microsoft Sentinel workspace.

### Exercise 2: Enable Microsoft Defender for Cloud data connector

This exercise shows you how to enable the Microsoft Defender for Cloud data connectors. This connector allows you to stream your security alerts from Microsoft Defender for Cloud into Microsoft Sentinel, so you can view Defender data in workbooks, query it to produce alerts and investigate and respond to incidents.
NOTE: To do this exercise, your user must have the Security Reader role in the subscription of the logs you stream. If not done already, you will need to enable any of the Defender plans in Microsoft Defender for Cloud.
1. Go to your Microsoft Sentinel workspace and select Data Connectors under the Configuration section.
2. In the data connectors screen, type defender in the search bar, select the Microsoft Defender for Cloud connector, and click on the Open connector page.
3. In the Microsoft Defender for Cloud connector page, check that your permissions are enough at the top. If you don't have the required permissions, you can continue to the next exercise.
4. From the list of subscriptions at the bottom of the page, select the desired subscription and click on Connect. Wait for the operation to complete.
5. Click on Next Steps at the top of the page and explore what content is available for this connector.

### Exercise 3: Enable Threat Intelligence Platforms TAXII data connector
This exercise shows you how to enable the Threat Intelligence - TAXII data connector. This connector allows you to send threat indicators from TAXII servers to Microsoft Sentinel. Threat indicators can include IP addresses, domains, URLs, and file hashes.
NOTE: To do this exercise, your user must have the Security Reader role in the subscription of the logs you stream. If not done already, you will need to enable Azure Defender within Azure Security Center.
1. Go to your Microsoft Sentinel workspace and select Data Connectors under the Configuration section.
2. In the data connectors screen, type taxii in the search bar, select the Threat intelligence - TAXII connector, and click on the Open connector page.
3. In the Threat Intelligence - TAXII connector page, add the following information under the Configuration menu:
○ Friendly name (for server): RansomwareIPs
○ API root URL: Your API
○ Collection ID: Your Collection ID
○ Username: guest
○ Password: guest
○ Import Indicators: All available (review all available options)
○ Polling frequency: Once a minute (review all available options)
4. Click Add and wait until the operation completes.
5. Click on Next Steps at the top of the page and explore what content is available for this connector. In a few seconds, the ThreatIntelligenceIndicator will be populated with IOCs from Anomali's feed.

<h3>Module 3 - Analytics Rules</h3>

🎓 Level: 200 (Intermediate)
⌛ Estimated time to complete this lab: 30 minutes

### Objectives

This module guides you through the Analytics Rule part in Microsoft Sentinel and shows you how to create different types of rules (Security Detections)

### Prerequisites

This module assumes that you have completed Module 1, as the data and the artifacts that we will be using in this module need to be deployed on your Microsoft Sentinel instance.

### Exercise 1: Analytics Rules Overview

1. Open your newly created Microsoft Sentinel instance.
2. On the left menu navigate to analytics and select the Rule template section
3. Review the analytics rules templates that ship with the product.
4. On the analytics rule filter select Data sources and check Security Events, review all the analytic rules on the above data source.
5. In the rule search bar type Rare RDP Connections for the rule name.
6. To review the rule logic and possible configuration options, in the right lower corner press Create Rule.
7. Review the rule definition like tactics and severity.
8. Press Next: Set rule logic at the bottom of the page.
9. In the rule logic screen, you have the ability to create or modify the rule KQL query, control the entity mapping, and define the scheduling and lookback time range.
10. After you reviewed the rule configuration options, close this page and navigate back to the main Microsoft Sentinel Overview screen.

### Exercise 2: Enable Microsoft incident creation rule

Microsoft Sentinel is a cloud-native SIEM and as such, it acts as a single pane of glass for alerts and event correlation. For this purpose, and to be able to ingest and surface alerts from Microsoft Security Products, we create a Microsoft incident creation rule. In this exercise, we will review this feature and create one example rule with a filtering option to help the analyst deal with alert fatigue.
1. On Microsoft Sentinel main page press on the Analytics section.
2. In the top bar press on +Create and select the Microsoft incident creation rule
3. In the rule name enter "Azure Defender only medium and high Alerts"
4. In the Microsoft security service dropdown select Azure Defender
5. In the Filter by severity select Custom and mark High and Medium
6. Press Next: Automated response
7. In the above "Automated response" page you can attach an automation rule that can generate automation tasks that can assist your SOC with repetitive tasks, or Security remediation. More on this topic in the SOAR module.
8. Press Next: Review and Create on the next page.

### Exercise 3: Review Fusion Rule (Advanced Multistage Attack Detection)

The fusion rule is a unique kind of detection rule. With the Fusion rule, Microsoft Sentinel can automatically detect multistage attacks by identifying combinations of anomalous behaviors and suspicious activities That are observed at various stages of the kill chain. In this exercise, we will learn how to distinguish and review the Fusion rule in Microsoft Sentinel.
1. In the analytics page rule template tab, use the Rule Type filter and select Fusion.
2. In the template screen notice the tag IN USE as this rule template is enabled by default.
3. Press on the rule and review the data sources in the rule right pane.
As Fusion rules produce security incidents with high fidelity and simulation can be challenging, we are adding an example of an incident that was created from fusion detection.
In the below example, we are seeing 2 low severity alerts from Azure Active Directory
Identity Protection and Microsoft Cloud App Security stick together in high severity incidence:

### Exercise 4: Create a Microsoft Sentinel custom analytics rule.

Your Security consult notified you about this thread https://www.reddit.com/r/sysadmin/comments/7kyp0a/recent_phishing_attempts_my_experience_and_what/ Based on the attack vector and the organization risk he recommends, you to create detection rule for this malicious activity. In this exercise, you will use the Microsoft Sentinel analytics rule wizard to create new detection.
1. Review the article in the above link and understand what is the data source that will be part of the detection.
2. Check if this operation is captured as part of your collection strategy:
● In the left menu press on the Logs and navigate to the search canvas
Important note: In this lab, we are using custom logs that replace the Out-off-the-box tables
Run the search query below to see the list of activities Microsoft Sentinel captured in the last 24 hours.

OfficeActivity_CL
| distinct Operation_s

● As you can see the New-InboxRule operation is indeed captured in your logs.
4. In the analytics rule page, in the top bar press on +Create and select scheduled query Rule
5. In this screen we will add general information regarding this rule.
6. In the Name type "Malicious Inbox Rule - custom".
7. In the rule Description add This rule is detecting on delete all traces of phishing emails from user mailboxes.
8. In the Tactics select Persistence and Defense Evasion.
9. In the rule severity select medium.
10. Press Next: SET rule logic. In the Rule logic page, review and copy the query:

let Keywords = dynamic(["helpdesk", " alert", " suspicious", "fake",
"malicious", "phishing", "spam", "do not click", "do not open", "hijacked",
"Fatal"]);
OfficeActivity_CL
| where Operation_s =~ "New-InboxRule"
| where Parameters_s has "Deleted Items" or Parameters_s has "Junk Email"
| extend Events=todynamic(Parameters_s)
| parse Events with * "SubjectContainsWords" SubjectContainsWords '}'*
| parse Events with * "BodyContainsWords" BodyContainsWords '}'*
| parse Events with * "SubjectOrBodyContainsWords" SubjectOrBodyContainsWords
'}'*
| where SubjectContainsWords has_any (Keywords)
or BodyContainsWords has_any (Keywords)
or SubjectOrBodyContainsWords has_any (Keywords)
| extend ClientIPAddress = case( ClientIP_s has ".",
tostring(split(ClientIP_s,":")[0]), ClientIP_s has "[",
tostring(trim_start(@'[[]',tostring(split(ClientIP_s,"]")[0]))), ClientIP_s )
| extend Keyword = iff(isnotempty(SubjectContainsWords), SubjectContainsWords,
(iff(isnotempty(BodyContainsWords),BodyContainsWords,SubjectOrBodyContainsWords
)))
| extend RuleDetail = case(OfficeObjectId_s contains '/' ,
tostring(split(OfficeObjectId_s, '/')[-1]) , tostring(split(OfficeObjectId_s,
'\\')[-1]))
| summarize count(), StartTimeUtc = min(TimeGenerated), EndTimeUtc =
max(TimeGenerated) by Operation_s, UserId__s, ClientIPAddress, ResultStatus_s,
Keyword, OriginatingServer_s, OfficeObjectId_s, RuleDetail

11. We can view the rule creation estimation by pressing Test with current data on the right side and see the number of hits.
12. Under the Alert enrichment (Preview), expand the entity mapping section that will allow us to map our fields to well-known categories:
○ In the Entity type open the supported list of entities and select Account in the identifier select FullName and map it to UserId__s
○ Press + Add new entity and this time select Host entity in the identifier select FullName and map it to OriginatingServer_s
○ Press + Add new entity, select IP entity, in the identifier select Address, and map it to ClientIPAddress value. To make your SOC more productive, save analyst time and effectively triage newly created incidents, your SOC analyst asks you to add the affected user from the search results as part of the alert title.
3. For applying this request, we will use the Alert details feature and create a custom Alert Name Format
● In the Alert Name Format copy the above dynamic title "Malicious Inbox Rule, affected user {{UserId__s}}"
4. In the Query scheduling, set the run query every 5 minutes and the Lookup data to last 12 Hours (This scheduling might not be ideal for the production environment and should be tuned). If you deployed the lab more than 12 hours ago, you will need to change the lookback period.
5. In the Suppression leave it on Off
6. Press the Next: Incident settings(Preview)
7. As your SOC is under stress, we want to reduce the number of alerts and be sure that when an analyst handles a specific incident, he/she will see all related events or other incidents related to the same attack story. For that, we will implement an Alert grouping feature. To do so, follow the steps below:
● In the Incident settings (Preview) under Alert grouping change it to Enabled.
● Modify the Limit of the group to alerts created within the selected time frame to 12 hours.
● Select the Grouping alerts into a single incident if the selected entity types and details match and select the Account.
8. Press the Next: Automated response and also press Next: Review and create this new analytics rule.

### Exercise 5: Review the resulting security incident

After we created the custom analytics rule that detects us for malicious inbox rule rules. Let's review the incident that was created from this analytics rule.
1. On the main Microsoft Sentinel main page, select incidents and review the incident page.
2. Locate a new incident with the title " Malicious Inbox Rule, affected user AdeleV@contoso.OnMicrosoft.com " Notice that the name adapts and the affected user name is added to the incident name.
3. In the right pane we can review the incident preview, this view will give us a high-level overview of the incident and the entity that is related to it.
4. Press on the "View full details"
5. In the incident full details page you are able to see the alert timeline (effective when you have more than one alert in a given incident).
6. Check the top-level tabs and press on the entity tab, this section will expose all the mapped entities that are related to this incident.
7. Press on the entity " AdeleV@contoso.OnMicrosoft.com " This action will navigate us to the user entity page, this page will give us a holistic view of the user entity, with all its activity and related alerts.

<h3>Module 4 - Incident Management</h3>

🎓 Level: 300 (Intermediate)
⌛ Estimated time to complete this lab: 60 minutes

### Objectives
This module guides you through the SOC Analyst experience using Microsoft Sentinel's incident management capabilities.

### Prerequisites
This module assumes that you have completed Module 1, as the data and the artifacts that we will be using in this module need to be deployed on your Microsoft Sentinel instance.

### Exercise 1: Review Microsoft Sentinel incident tools and capabilities

As a SOC analyst, the entry point to consume Security incidents (tickets) in Sentinel is the Incident page.

1. In the left navigation menu click on Incidents to open the incidents page. This page will show by default all the open incidents in the last 24hr.
2. When we want to change the time window, present only incidents from specific severity, or see also closed incidents, we can use the filters bar:
3. On the incident page select the Sign-ins from IPs that attempt sign-ins to disabled accounts incident. In the right pane, you can see the incident preview with high-level information about the incident.
4. As you are the SME SOC analyst who deals with and investigates tickets, you need to take ownership of this incident. On the right pane, change the unassigned to Assign to me and also change the status from New to Active.
5. Another way to consume incidents and also get a high-level view of the general SOC health is through the Security efficiency workbook.
We have 2 options to open the workbook:
● Through the top navigation, this will open the workbook's general view, where we see overall statistics on the incidents.
● Through the incident itself, that will open the same workbook on a different tab, and present the information and lifecycle for the given incident.
6. Review the dashboard.

### Exercise 2: Handling Incident "Sign-ins from IPs that attempt sign-ins to disabled accounts"

1. Open the Azure Sentinel incident page.
2. Locate the incident "Sign-ins from IPs that attempt sign-ins to disabled accounts"
3. Press on the incident and look on the right pane for the incident preview, please notice that in this pane we are surfacing the incident entities that belong to this incident.
4. Take ownership of the incident and change its status to Active
5. Navigate to incident full details by pressing View full details and execute playbook to bring Geo IP data (user will notice tags being added).
6. Navigate to the Alerts tab and press the number of Events. This action will redirect you to Raw logs that will present the alert evidence to support the investigation
7. In raw log search, expend the received event and review the column and data we received, these properties will help us to decide if this incident is correlated to other events.
8. To get more context for this IP, we want to add GEO IP enrichment. In a real-life SOC, this operation will run automatically, but for this lab we want you to run it manually.
● Navigate back to the incident full page to the alert tab and scroll to the right
● To view the relevant automation that will assist us with the enrichment operation, Press View Playbacks
9. Locate the playbook Get-GeoFromIpAndTagIncident and press Run. If the playbook is configured correctly, it should finish in a couple of seconds.
10. Navigate back to the main incident page and notice new tags that were added to the incident.
** Bonus: Open the resource group for Sentinel deployment, locate the playbook, and look at the last playbook run to review the execution steps.
11. As this enrichment information increases your concern, you want to check other traces of this IP in your network. For this investigation, you want to use the investigation workbook.
12. In the left navigation press Workbooks and select My Workbooks
13. To open the Investigation Insights - sentinel-training-ws saved Workbook, on the right page press View saved workbook.
14. Validate that in the properties selector, your workspace is set on sentinel-training-ws and the subscription is the subscription that hosts your
Microsoft Sentinel Lab.
15. As the subject of the investigation is the suspicious IP from North Korea. we want to see all the activity done by this IP so in the properties selector, switch on the investigate by to Entity.
16. In the Investigate IP Address Tab, add the suspicious IP.
17. Under the activity Detail we see many successful logins from this IP with the user Adele, and also some failed logins to disabled accounts from the last day/hours
18. We copy the User adelev@m365x816222.onmicrosoft.com and validate it in our internal HR system, from the information we collected it seems that Adele is part of the security Red team, and this suspicion is part of the exercise.
19. As the red team exercise discovered by us, the SOC manager asked us to add this IP to the whitelisting IPs, so that we will not trigger an incident on it anymore.
20. On the main incident page, select the relevant incident and press Actions - > Create automation rule.
21. In the new screen, we will see all the incident identifiers ( the IP, and the specific Analytics rule), as the Red Team exercise will finish in 48 hr., adapt the rule expiration till the end of the drill, and press Apply.
22. As this incident is considered benign, we go back to the main incident page and close the incident with the right classification. M5-close-incident

### Exercise 3: Handling "Solorigate Network Beacon" incident

1. If not already there, navigate to the Incidents view in Microsoft Sentinel.
2. From the list of active incidents, select "Solorigate Network Beacon" incident. If you can't find it, use the search bar or adjust the time filter at the top. Don't worry if you see more than one.
3. Assign the incident to yourself and click Apply.
4. Read the description of the incident. As you can see, one of the domain IOCs related to the Solorigate attack has been found. In this case, the domain avsvmcloud.com is involved.
5. Optionally, you can click on View full details to drill down to inspect the raw events that triggered this alert.
6. As you can see, the events originated in Cisco Umbrella DNS, and the analytic rule uses the Microsoft Sentinel Information Model (ASIM) to normalize these events from any DNS source. Read more about ASIM and the DNS schema.

### Exercise 4: Hunting for more evidence

1. As a next step, you would like to identify the hosts that might have been compromised. As part of your research, you find the following guidance from Microsoft. In this article, you can find a query that will do a SolarWinds inventory check query. We will use this query to find any other affected hosts.
2. Switch to Hunting in the Microsoft Sentinel menu.
3. In the search box, type "solorigate". Select Solorigate Inventory check query and click on Run Query.
4. You should see a total of three results. Click on View Results
5. As you can see, besides ClientPC, there are two additional computers where the malicious DLL and named pipe have been found. Bookmark all three records, select them and then click on Add Bookmark.
6. In the window that appears click on Create to create the bookmarks. As you can see, entity mapping is already done for you.
7. Wait until the operation finishes and close the log search using the ✖ at the top right corner. This will land you in the Bookmarks tab inside the Hunting menu, where you should see your two new bookmarks created. Select both of them click on Incident actions at the top and then Add to the existing incident.
8. From the list, pick the Solorigate incident that is assigned to you, and click Add.
9. At this point you can ask the Operations team to isolate the hosts affected by this incident.

### Exercise 5: Add IOC to Threat Intelligence

Now, we will add the IP address related to the incident to our list of IOCs, so we can capture any new occurrences of this IOC in our logs.
1. Go back to the Incidents view.
2. Select the Solorigate incident and copy the IP address entity involved. Notice that you have now more computer entities available (the ones coming from the bookmarks).
3. Go to the Threat Intelligence menu in Microsoft Sentinel and click Add New at the top.
4. Enter the following details in the New indicator dialog, with Valid from today's date and Valid until two months after. Then click Apply.

### Exercise 6: Handover incident

We will now prepare the incident for handover to the forensics team.

1. Go to Incidents and select the Solorigate incident assigned to you. Click on View full details.
2. Move to the Comments tab.
3. Enter information about all the steps performed. As an example:
4. At this point you would hand over the incident to the forensics team.

<h3>Module 5 - Hunting</h3>

🎓 Level: 300 (Intermediate)
⌛ Estimated time to complete this lab: 40 minutes

### Objectives
This module will guide you through a proactive threat-hunting procedure and will review Microsoft Sentinel’s rich hunting features.

### Prerequisites
This module assumes that you have completed Module 1, as the data and the artifacts that we will be using in this module need to be deployed on your Microsoft Sentinel instance.

### Exercise 1: Hunting on a specific MITRE technique

Our security researchers shared the following article describing techniques used in the SolarWinds supply chain: Identifying UNC2452-Related Techniques for ATT&CK Based on the article, our SOC leads understand that to be able to see the full picture of the attack campaign and spot anomalies in our data set, we need to run a proactive threat hunt based on the MITRE tactics and techniques described in this article.

1. Review the above article that highlights MITRE attack techniques and the corresponding tools and methods. In this exercise, we will focus on T1098. To get a greater understanding of this technique, review this article: https://attack.mitre.org/techniques/T1098/
2. On the left navigation click on Hunting.
3. On the hunting page, we can see that Microsoft Sentinel provides built-in hunting queries to kick-start the proactive hunting process. On the metric bar, we can see statistics about how many queries are “active” and have the required data sources to run in your environment. There are also metrics showing how many queries have been run during your current session, and how many of these queries produced results. We also see counts of the number of Livestream results and bookmarks created during the hunting process.
4. On the top action bar, shown in the above diagram, we can find the Run all queries button. Clicking on this button runs all active queries. This can take a significant amount of time depending on the number of queries and amount of log
data being queried. To get results faster, it helps to filter down the set of queries to the specific set you need to run.
5. Microsoft Sentinel provides many different attributes to filter down to just the queries you want to run. To filter by MITRE technique, click Add filter, select Techniques, and press Apply.
6. In the Techniques value field, uncheck the select all and only select T1098 and click OK.
7. Review all the queries in the table using this technique. In this phase, we can multi-select all queries, and run them as a batch. To do so, press on the multi-select checkboxes for the queries you want to run. Notice that the Run all queries button has changed into the Run selected queries (Preview) button. Click this button to run the queries.
Note: In some cases, you will need to modify the selected time range based on the time you deploy the lab to get query results.
8. Once we press on the Run selected queries (Preview) the results start popping on the screen, in our case we immediately spot that the Adding credentials to legitimate OAuth Applications query returns several results.
9. Select this query and in the right pane press View Results. This will navigate us to the log analytics screen to view the hunting query content and run it.
10. On the Logs screen, once the hunting query finishes executing, we can see all the data that is returned with the parsed fields and columns. From a high overview, we can see that we have the actor IP and the username that runs this operation.
11. Expand one of the results and check the fields. As you can see, we are able to spot the Azure AD application name, and the added key name, and type the IP, username of the actor, and other relevant information that helps us understand the specific action.
12. Our SOC analysts need to know which application from all the above result sets is critical and has a security risk. One way to do this is to open the Azure Active Directory for each application from the hunting results, check their permissions, and validate the risk. Our SOC analyst follows the organization knowledge base that guides him to review a list of all the AAD applications with their risk levels.
13. On the Logs screen press on the + icon to open a new search tab and run the query:

_GetWatchlist('HighRiskApps')

As you can see, this watchlist stores the application name, risk level, and permissions. To correlate this information with our hunting results set, we need to run a simple join query.
14. On the same tab, edit the query and join it with the hunting data. For this demo, you can copy the query below and overwrite your existing query. Now run this new query to see the results.

_GetWatchlist('HighRiskApps')
| join
(
AuditLogs_CL
| where OperationName has_any ("Add service principal", "Certificates and
secrets management")
| where Result_s =~ "success"
| mv-expand target = todynamic(TargetResources_s)
| where
tostring(tostring(parse_json(tostring(parse_json(InitiatedBy_s).user)).userPrinc
ipalName)) has "@" or tostring(parse_json(InitiatedBy_s).displayName) has "@"
| extend targetDisplayName =
tostring(parse_json(TargetResources_s)[0].displayName)
| extend targetId = tostring(parse_json(TargetResources_s)[0].id)
| extend targetType = tostring(parse_json(TargetResources_s)[0].type)
| extend eventtemp = todynamic(TargetResources_s)
| extend keyEvents = eventtemp[0].modifiedProperties
| mv-expand keyEvents
| where keyEvents.displayName =~ "KeyDescription"
| extend set1 = parse_json(tostring(keyEvents.newValue))
| extend set2 = parse_json(tostring(keyEvents.oldValue))
| extend diff = set_difference(set1, set2)
| where isnotempty(diff)
| parse diff with * "KeyIdentifier=" keyIdentifier: string ",KeyType=" keyType:
string ",KeyUsage=" keyUsage: string ",DisplayName=" keyDisplayName: string "]"
*
| where keyUsage == "Verify" or keyUsage == ""
| extend AdditionalDetailsttemp = todynamic(AdditionalDetails_s)
| extend UserAgent = iff(todynamic(AdditionalDetailsttemp[0]).key ==
"User-Agent", tostring(AdditionalDetailsttemp[0].value), "")
| extend InitiatedByttemp = todynamic(InitiatedBy_s)
| extend InitiatingUserOrApp =
iff(isnotempty(InitiatedByttemp.user.userPrincipalName),
tostring(InitiatedByttemp.user.userPrincipalName),
tostring(InitiatedByttemp.app.displayName))
| extend InitiatingIpAddress = iff(isnotempty(InitiatedByttemp.user.ipAddress),
tostring(InitiatedByttemp.user.ipAddress),
tostring(InitiatedByttemp.app.ipAddress))
| project-away diff, set1, set2, eventtemp, AdditionalDetailsttemp,
InitiatedByttemp
| project-reorder
TimeGenerated,
OperationName,
InitiatingUserOrApp,
InitiatingIpAddress,
UserAgent,
targetDisplayName,
targetId,
targetType,
keyDisplayName,
keyType,
keyUsage,
keyIdentifier,
CorrelationId
| extend
timestamp = TimeGenerated,
AccountCustomEntity = InitiatingUserOrApp,
IPCustomEntity = InitiatingIpAddress
) on $left.AppName == $right.targetDisplayName
| where HighRisk == "Yes"

As you can see the above query uses a join operator to join two data streams: the high-risk watchlist and the “Adding credentials to legitimate OAuth Applications” hunting query results. We are joining these two datasets based on the application name column. We filter the results with a where operator to see only the high-risk applications. Please keep this window open as we will continue to work on it in the next exercise.

### Exercise 2: Bookmarking hunting query results

While reviewing query results in Log Analytics, we use Microsoft Sentinel’s bookmarking feature to store and enrich these results. We can extract entity identifiers and then use entity pages and the investigation graph to investigate the entity. We can add tags and notes to the results to say why it is interesting. Bookmarks will also preserve the query and time range that generated the specific row result so that analysts can reproduce the query in the future If as part of our investigation, we determine that the bookmarked query result contains malicious activity, we can create a new incident from the bookmark, or attach the bookmark to an existing incident.

1. On the Logs screen, open the join hunting query from Exercise. Select one or more rows using the checkbox on the left-hand side of the table. Click Add bookmark in the action menu just about the results table.
2. On the right-hand bookmark pane modify the Bookmark Name to victim@buildseccxpninja.onmicrosoft.com added a key to purview-spn App with High Risk.
3. Using the drop-down in the entities section of the bookmark pane, map the Account entity to the InitiatingUserOrApp column. You can see a sample value in the drop-down. In the diagram below, the sample value is victim@buildseccxpninja.onmicrosoft.com
4. Map the IP entity to the InitiatingIpAddress column. In the diagram below, you can see the sample value 45.153.160.2.
5. We will also add a tag to map it to the main attack story. In the tags section write, “SolarWinds”
6. Press Create at the bottom of the blade to create the bookmark.

### Exercise 3: Promote a bookmark to an incident

1. In the Hunting page, navigate to the Bookmarks tab to see our newly created
bookmark.
2. In the right pane, we can click the Investigate button to investigate the bookmark
using the Investigation Graph the same way that we can investigate an incident.
3. To create a new incident from the bookmark, select the bookmark and select Incident Actions in the top menu bar and select Create new Incident. Note that you also have the option to attach the bookmark to an existing incident.
4. Select the Severity for the incident, assign the incident to yourself, and click Create.
5. Navigate to the incident blade and review the newly promoted incident we just created.
