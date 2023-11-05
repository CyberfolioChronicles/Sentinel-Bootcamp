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

Permissions to create a resource group in your Azure subscription.

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
○ Workspace Name: Provide a name for the Microsoft Sentinel workspace. Please note that the workspace name should include 4-63 letters, digits or '-'. The '-' shouldn't be the first or the last symbol. Click Review + create and then Create after the validation completes. The creation takes a few seconds.
7. You will be redirected back to the Add Microsoft Sentinel to a workspace. Type the name of your new workspace in the search box, select your workspace and click Add at the bottom.
Your Microsoft Sentinel workspace is now ready to use!

### Exercise 2: Deploy the Microsoft Sentinel Training Lab

Solution

In this exercise, you will deploy the Training Lab solution into your existing workspace. This will ingest pre-recorded data (~20 MBs) and create several other artifacts that will be used during the exercises.
1. In the Azure Portal, go to the top search bar and type Microsoft Sentinel Training. Select the Microsoft Sentinel Training Lab Solution (Preview) marketplace item on the right.
2. Read the solution description and click Create at the top.
3. In the Basics tab, select the Subscription, Resource Group and Workspace that you created in Exercise 1, or the details for your existing workspace. Optionally, review the different tabs (Workbooks, Analytics, Hunting Queries, Watchlists, Playbooks) in the solution. When ready, click on Review + create.
4. Once validation is ok, click on Create. The deployment process takes about 15 minutes, this is because we want to make sure that all the ingested data is ready for you to use once finished.
5. Once the deployment finishes, you can go back to Microsoft Sentinel and select your workspace. In the home page you should see some ingested data and several recent incidents. Don't worry if you don't see 3 incidents like in the screenshot below, they might take a few minutes to be raised.

### Exercise 3: Configure Microsoft Sentinel Playbook

In this exercise, we will configure a Playbook that will be later used in the lab. This will allow the playbook to access Sentinel.

1. Navigate to the resource group where the lab has been deployed.
2. In the resource group you should see an API Connection resource called azuresentinel-Get-GeoFromIpAndTagIncident, click on it.
3. Click on Edi API connection under General.
4. Click on Authorize and a new window will open to choose an account. Pick the user that you want to authenticate with. This should normally be the same user that you're logged in with.
5. Click Save.

<h4>Module 2 - Data Connectors</h4>

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



