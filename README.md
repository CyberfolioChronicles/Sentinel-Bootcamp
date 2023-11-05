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
2. Locate a new incident with the title " Malicious Inbox Rule, affected user AdeleV@contoso.OnMicrosoft.com " notice that the name adapts and the effected user name is added to the incident name.
3. In the right pane we can review the incident preview, this view will give us a high-level overview of the incident and the entity that is related to it.
4. Press on the "View full details"
5. In the incident full details page you are able to see the alert timeline (effective when you have more than one alert in a given incident).
6. Check the top-level tabs and press on the entity tab, this section will expose all the mapped entities that are related to this incident.
7. Press on the entity " AdeleV@contoso.OnMicrosoft.com " This action will navigate us to the user entity page, this page will give us a holistic view of the user entity, with all its activity and related alerts.

