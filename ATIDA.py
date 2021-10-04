import os
import re
import csv
import yaml
import glob
import toml
import json
import string
import requests
import termcolor
import pandas as pd
from pandas import read_excel 
from simple_term_menu import TerminalMenu
from jinja2 import Environment, FileSystemLoader
from stix2 import MemoryStore
from stix2 import Filter
from stix2 import TAXIICollectionSource
from taxii2client.v20 import Collection  
from datetime import datetime

banner = """
                                  _____            _   _            _ 
     /\                          / ____|          | | (_)          | |
    /  \    _____   _ _ __ ___  | (___   ___ _ __ | |_ _ _ __   ___| |
   / /\ \  |_  / | | | '__/ _ \  \___ \ / _ \ '_ \| __| | '_ \ / _ \ |
  / ____ \  / /| |_| | | |  __/  ____) |  __/ | | | |_| | | | |  __/ |
 /_/    \_\/___|\__,_|_|  \___| |_____/ \___|_| |_|\__|_|_| |_|\___|_|
                                                                      
            Automated Threat Informed Defense Assessment Tool

"""
print(termcolor.colored(banner,"cyan"))


# Initial Variables -----------

Local_Path = "Resources/sigma-master/rules/"
SIGMA_CSV = "Resources/SGR.csv"
NIST_Mitigations_File = "Resources/Layers/nist800-53-r5_overview.json"
Local_Path = "Reports/Navigation-Layers/" 
Azure_Native_Security_Controls = "Resources/Layers/Azure_platform_native_security_controls.json"
NIST_Controls_Catalog = "Resources/sp800-53r5-control-catalog.xlsx"
D3FEND_Techniques = "Resources/D3FEND/techniques.csv"
D3FEND_Defenses = "Resources/D3FEND/Defenses.csv"

Local_Queries = []
SGM = []
Rp_SIGMA = []
Rp_NIST = []
ActCnt = []
ActIndus = []
Tools = []
ExtIndus = []
ExtCnt = []
Artifacts = []
Rp_D3FEND = []
Threats = []
chunk = []
APTs =  []
Rp_Threats = []  
Watchlist = []


# Configuration 

# Read local `config.toml` file.
config = toml.load('Config/config.toml')

# Add the rquired fields in the config file (config.toml) lacated in Config Folder
Azure_AD_Tenant = config.get("Azure_AD_Tenant")
Client_ID = config.get("Client_ID")
Client_Secret = config.get("Client_Secret")
ResourceGroup = config.get("ResourceGroup")
Workspace = config.get("Workspace")
Subscription = config.get("Subscription")

file_loader = FileSystemLoader('Resources/templates')
env = Environment(loader=file_loader)
template = env.get_template('template.html')

# ------------------------- Threat Profiling ---------------------------- # 

print("[+] Do you want to use an existant Threat Heatmap (ATT&CK Navigation Layer)? ")
terminal_menu = TerminalMenu(
        ["Yes. Thank you", 
         "I want to Generate a Threat Profile Heatmap"],
        multi_select=False,
        show_multi_select_hint=True,
    )

menu_entry = terminal_menu.show()

if menu_entry == 0:

    print("[+] Enter the Threat Heat Map (Navigation Layer):")
    Navigation_Layer = input()
    with open(Navigation_Layer,"r") as r:
        threat = json.load(r)

    for i in range(len(threat["techniques"])):
       Threats.append(threat["techniques"][i]["techniqueID"])
    

elif menu_entry == 1:
    # Threat Profiling
    # Get the list of Sectors from user
    input_string = input("Enter Sectors: ")
    Indus  = input_string.split(",")
    for sector in Indus:
        print("[+] You selected the following Sectors: ",str(sector))
        
    # Get the list of Countries from user

    input_string2 = input("Enter The Countries: ")
    Countries  = input_string2.split(",")
    for country in Countries:
        print("[+] You selected the following Countries: ",str(country))

    print("[+] Mapped Threat Intelligence Reports were Generated Successfully!") 
    # Load Group Details
    APT_Groups = "Resources/APT-groups.xlsx"
    Group_sheet = "groups"
    APT_df = read_excel(APT_Groups, sheet_name = Group_sheet)
    data = APT_df[["ID","name","Target","Industry","description","url"]].values.tolist()

    # Get the APT groups related to the provided Sectors and industries
    for elm in Indus:
        for d in range(len(data)):
            if elm in str(data[d][3]):
                ActIndus.append(data[d][1])

    # Get the APT groups related to the provided Countries or regions

    for cnt in Countries:
        for d in range(len(data)):
            if cnt in str(data[d][2]):
                ActCnt.append(data[d][1])

    # Grouping all related APTs
    All = ActCnt + ActIndus
    All =  list(dict.fromkeys(All)) # Remove Duplicates


    print("[+] Generating Mapped Threat Actor Reports ...") 

    
    # Group Details from MITRE ATT&CK
    for apt in All:
        for d in range(len(data)):
            if str(apt) == str(data[d][1]):
                Command = "wget "+str(data[d][5])+"/"+str(data[d][0])+"-enterprise-layer.json -P Reports/Navigation-Layers -q > /dev/null 2>&1"
                Online_Nav = "https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fgroups%2F"+str(data[d][0])+"%2F"+str(data[d][0])+"-enterprise-layer.json"
                APTs.append({"groupID":data[d][0],"Name":data[d][1],"Countries":data[d][2],"Sectors":data[d][3],"Description":data[d][4],"URL":data[d][5],"Online Navigation Layer": Online_Nav})
                os.system(Command) # Download ATT&CK Navigation Layers

    print("[+] Mapped Threat Actor Reports were Generated Successfully!") 
    df_APT = pd.DataFrame(APTs)
    with pd.ExcelWriter('Reports/APT-Groups.xlsx') as writer:  
        df_APT.to_excel(writer, sheet_name='APT Groups')

    print("[+] APT Groups Excel Report 'Reports/APT-Groups.xlsx' was  Generated Successfully!") 
 
   
    Techniques = []
    Nav_Layers  = [pos_raw for pos_raw in os.listdir(Local_Path) if pos_raw.endswith('.json')]
    for layer in Nav_Layers:
        #print(layer)
        try:
            with open(Local_Path+layer,'r',) as l:
                techs = json.load(l)
        except:
            pass
        for i in range(len(techs["techniques"])):
            Techniques.append(techs["techniques"][i]["techniqueID"])
        

    Techniques =  list(dict.fromkeys(Techniques)) # Remove Duplicates

    for t in Techniques:
        print

    # Generate MITRE Layer

    Layer_Template = {
        "description": "Techniques Covered by Azure Sentinel Rules and Queries",
        "name": "Azure Sentinel Coverage",
        "domain": "mitre-enterprise",
        "version": "4.2",
        "techniques": 
            [{  "techniqueID": technique, "color": "#ff0000"  } for technique in Techniques] 
        ,
        "gradient": {
            "colors": [
                "#ffffff",
                "#ff0000"
            ],
            "minValue": 0,
            "maxValue": 1
        },
        "legendItems": [
            {
                "label": "Techniques Covered by Azure Sentinel",
                "color": "#ff0000"
            }
        ]
    }

    json_data = json.dumps(Layer_Template)

    with open("Reports/Navigation-Layers/Threat_Heatmap.json", "w") as file:
        json.dump(Layer_Template, file)

    print("[+] The MITRE ATT&CK matrix navigation layers of APT Groups were created successfully")
    print("[+] The unified Threat Heat Map (Navigation Layer) 'Threat_Heatmap.json' was Generated Successfully!") 
    print("[+] The navigation layers are stored in 'Reports/Navigation-Layers/' ") 

    with open("Reports/Navigation-Layers/Threat_Heatmap.json","r") as r:
        threat = json.load(r)

    
    for i in range(len(threat["techniques"])):
       Threats.append(threat["techniques"][i]["techniqueID"])

 
Threats = list(dict.fromkeys(Threats)) #Deletes Duplicates


Nb_Threats = len(Threats)

"""
If you want to use the live ATT&CK taxii Server use the following code instead:

collections = {
    "enterprise_attack": "95ecc380-afe9-11e4-9b6c-751b66dd541e",
    "mobile_attack": "2f669986-b40b-4423-b720-4396ca6a462b",
    "ics-attack": "02c3ef24-9cd4-48f3-a99f-b74ce24f1d34"
}

collection = Collection(f"https://cti-taxii.mitre.org/stix/collections/{collections['enterprise_attack']}/")
src = TAXIICollectionSource(collection)

"""

src = MemoryStore()
src.load_from_file("Resources/enterprise-attack.json")
Tactics = []
for Threat_index in range(len(Threats)):
    TechniqueData = src.query([ Filter("external_references.external_id", "=", Threats[Threat_index]), Filter("type", "=", "attack-pattern")])[0]
    Phases = []
    
    for p in range(len(TechniqueData["kill_chain_phases"])):
        Phases.append(TechniqueData["kill_chain_phases"][p]["phase_name"])
        
        
    Rp_Threats.append({"TechniqueID":Threats[Threat_index],"TechniqueName":TechniqueData["name"],"Phases":Phases,"Description":TechniqueData["description"]})
    for ph in range(len(Phases)):
        Tactics.append(Phases[ph])
        

Unique_Tactics = list(dict.fromkeys(Tactics)) #Deletes Duplicates

total = len(Tactics)

Series = []
Labels = []
for uni in Unique_Tactics:
    #print(uni," ",Tactics.count(uni)," ", int(Tactics.count(uni))*100//total,"%")
    Series.append(Tactics.count(uni))
    Labels.append(uni)

# ------------------------- Azure Sentinel Coverage---------------------------- # 

# Get the Access Token
Access_Url = "https://login.microsoftonline.com/"+Azure_AD_Tenant+"/oauth2/token"
headers = {'Content-Type': 'application/x-www-form-urlencoded'}
payload='grant_type=client_credentials&client_id='+ Client_ID+'&resource=https%3A%2F%2Fmanagement.azure.com&client_secret='+Client_Secret
print("[+] Connecting to Azure Sentinel ...")
Access_response = requests.post(Access_Url, headers=headers, data=payload).json()
Access_Token = Access_response["access_token"]
print("[+] Access Token Received Successfully")

# Techniques from Detections 

Sentinel_AlertTechniques = []

Detections_Url= "https://management.azure.com/subscriptions/"+Subscription+"/resourceGroups/"+ResourceGroup+"/providers/Microsoft.OperationalInsights/workspaces/"+Workspace+"/providers/Microsoft.SecurityInsights/alertRules?api-version=2020-01-01"
Auth = 'Bearer '+Access_Token
headers2 = {
  'Authorization': Auth ,
  'Content-Type': 'text/plain'
}

Detections_response = requests.get(Detections_Url, headers=headers2).json()
print("[+] Alert Rules Details were received Successfully")

Rp_Analytics = []
Rp_Hunting = []

for a in range(len(Detections_response ["value"])):
    if (str(Detections_response ["value"][a]["properties"]["displayName"]).split()[0][0]== "T"):
        Tag = (str(Detections_response["value"][a]["properties"]["displayName"]).split()[0])
        if re.match("T[0-9][0-9]+", Tag):
            Sentinel_AlertTechniques.append(Tag)
            Rp_Analytics.append({"TechniqueID":(str(Detections_response["value"][a]["properties"]["displayName"]).split()[0]),"Sentinel":"Analytics"})

print("[+] ATT&CK Techniques were extracted from your Azure Sentinel Analytics Successfully: ")


# Get covered Techniques from Hunting Queries

Hunting_Url= "https://management.azure.com/subscriptions/"+Subscription+"/resourceGroups/"+ResourceGroup+"/providers/Microsoft.OperationalInsights/workspaces/"+Workspace+"/savedSearches?api-version=2020-08-01"
Auth = 'Bearer '+Access_Token
headers2 = {
  'Authorization': Auth ,
  'Content-Type': 'text/plain'
}

Hunting_response = requests.get(Hunting_Url, headers=headers2).json()
#print(response2)
print("[+] Hunting Query Details were received from Azure Sentinel Successfully")


# Techniques from the Hunting Queries
SentinelHunt_Queries = []  

  
for t in range(len(Hunting_response["value"])):
  try:
    if (str(Hunting_response["value"][t]["properties"]["category"]) == "Hunting Queries"):
      if str(Hunting_response["value"][t]["properties"]["tags"][2]["name"]) == "techniques":
        #print(str(Hunting_response["value"][t]["properties"]["tags"][2]["value"]).split(",")[1])
        for k in range(len(str(Hunting_response["value"][t]["properties"]["tags"][2]["value"]).split(","))):
          SentinelHunt_Queries.append(str(Hunting_response["value"][t]["properties"]["tags"][2]["value"]).split(",")[k])
          Rp_Hunting.append({"TechniqueID":str(Hunting_response["value"][t]["properties"]["tags"][2]["value"]).split(",")[k],"Sentinel":"Hunting Query"})
  except KeyError:
    pass
             
#print("Covered Hunting Techniques: ",SentinelHunt_Queries)

Total_Techniques = Sentinel_AlertTechniques + SentinelHunt_Queries

Nb_Coverage = len(Total_Techniques)
Rp_Coverage = Rp_Hunting + Rp_Analytics

# Generate MITRE Layer

Layer_Template = {
        "description": "Techniques Covered by Azure Sentinel Rules and Queries",
        "name": "Azure Sentinel Coverage",
        "domain": "mitre-enterprise",
        "version": "4.2",
        "techniques": 
            [{  "techniqueID": technique, "color": "#ff0000"  } for technique in Total_Techniques] 
        ,
        "gradient": {
            "colors": [
                "#ffffff",
                "#ff0000"
            ],
            "minValue": 0,
            "maxValue": 1
        },
        "legendItems": [
            {
                "label": "Techniques Covered by Azure Sentinel",
                "color": "#ff0000"
            }
        ]
    }

json_data = json.dumps(Layer_Template)

with open("Reports/Coverage_Matrix.json", "w") as file:
    json.dump(Layer_Template, file)

print("[+] The MITRE matrix json file 'Coverage_Matrix.json' was created successfully")


# --------------  Detection Gap Analysis  -------------------- # 

Threat_Techniques = []
for i in range(len(threat["techniques"])):
  Threat_Techniques.append(threat["techniques"][i]["techniqueID"])

Watchlist0 = set(Total_Techniques)^set(Threat_Techniques)
Watchlist = list(Watchlist0)
Watchlist =  list(dict.fromkeys(Watchlist))
#print(Watchlist)


# --------------  Azure Native Security Controls -------------------- # 

print("[+] Azure Native Controls")

Azure_Native_Security_Controls = "Resources/Layers/Azure_platform_native_security_controls.json"

Rp_Controls = []
result = []
chunk = []

with open(Azure_Native_Security_Controls,"r") as g:
  controls = json.load(g)

for elm in Watchlist:
    for j in range(len(controls["techniques"])):
        if str(controls["techniques"][j]["techniqueID"]) == elm:  
          for ctr in range(len(controls["techniques"][j]["metadata"])):
              chunk.append(controls["techniques"][j]["metadata"][ctr])
              #print(chunk[0])
              #print(chunk[0]["value"])
              if  "divide" in str(controls["techniques"][j]["metadata"][ctr]):
                  result.append(chunk[0]["value"])
                  #print(result)
                  if chunk[0]["name"] == "control":
                    Rp_Controls.append({"TechniqueID":elm,"ControlDetails":chunk[0]["value"]})
                  chunk = []

# --------------------  D3FEND Defenses -------------------------- # 

# D3FEND

with open(D3FEND_Techniques, newline='') as csvfile:
    reader = csv.DictReader(csvfile)
    print("[+] D3FEND Techniques and Artifacts were loaded Successfully")
    for row in reader:
        for i in Watchlist:
            if str(i) == str(row['ATTACKid']):
                #print(row)
                #print(row['ATTACKid'])
                for artf in list(row.values())[2:]:
                        Artifacts.append(artf)

while '' in Artifacts:
   Artifacts.remove('')   #Deletes empty elements

Artifacts = list(dict.fromkeys(Artifacts)) #Deletes Duplicates

print("[+] Related D3FEND Artifacts were extracted Successfully")                              
#print(Artifacts)        

Total_Artifacts= []

for f in Artifacts:
    #print(f.strip('][').split(', '))
    for g in range(len(f.strip('][').split(', '))):
        Total_Artifacts.append(f.strip('][').replace("'",'').split(', ')[g])


Total_Artifacts = list(dict.fromkeys(Total_Artifacts)) #Deletes Duplicates
#print(G[0])
for t in Total_Artifacts:
    t.translate({ord(c): None for c in string.whitespace})

print("[+] Related D3FEND Artifacts were extracted Successfully")        
#print(Total_Artifacts)

Defenses = []

with open(D3FEND_Defenses, newline='') as csvfile:
    reader = csv.DictReader(csvfile)
    print("[+] D3FEND Defenses were loaded Successfully")  
    print("[+] Related D3FEND Defenses are the following") 
    for row in reader:
        for Art in Total_Artifacts:
            if str(Art) in str(row):
                 #print(row['DEFENDid'])
                 #Defenses.append(row['DEFENDid'])
                 Rp_D3FEND.append({
                            "ID":row['DEFENDid'],
                            "Defense":row['Defense'],
                            "Definition":row['Definition'],
                            "Analyzes":row['Analyzes'],
                            "Neutralizes":row['Neutralizes'],
                            "Verifies":row['Verifies'],
                            "Obfuscates":row['Obfuscates'],
                            "Filters":row['Filters'],
                            "Encrypts":row['Encrypts'],
                            "Blocks":row['Blocks'],
                            "Authenticates":row['Authenticates'],
                            "Terminates":row['Terminates'],
                            "Isolates":row['Isolates'],
                            "Spoofs":row['Spoofs'],
                            "Disables":row['Disables'],
                            "Modifies":row['Modifies'],
                            "URL":"https://d3fend.mitre.org/technique/d3f:"+str(row['Defense']).translate({ord(c): None for c in string.whitespace})
                        })


#print(Rp_D3FEND)
Nb_D3FEND = len(Rp_D3FEND)

# -------------------------  NIST Mitigations ---------------------------- # 

print("[+] Related NIST MITIGATIONS")

with open(NIST_Mitigations_File,"r") as r:
  NIST = json.load(r)

df_NIST = read_excel(NIST_Controls_Catalog)
NIST_Info = df_NIST[["Control Identifier","Control (or Control Enhancement) Name","Control Text"]].to_dict() 

for elm in Watchlist:
    for j in range(len(NIST["techniques"])):
        if str(NIST["techniques"][j]["techniqueID"]) == elm:
            Mitlist = str(NIST["techniques"][j]["comment"]).replace("Mitigated by","").translate({ord(c): None for c in string.whitespace}).split(",")
            for m in Mitlist:
                for Inf in range(len(NIST_Info["Control Identifier"])):
                    if str(m+"(") in str(NIST_Info["Control Identifier"][Inf]) or (str(m) == str(NIST_Info["Control Identifier"][Inf])):
                        #print(NIST_Info["Control Identifier"][Inf])
                        Rp_NIST.append({"Technique":elm,"Control":NIST_Info["Control Identifier"][Inf],"Name":NIST_Info["Control (or Control Enhancement) Name"][Inf],"Comment":NIST_Info["Control Text"][Inf]})



# ------------------------- Sigma Rules -------------------------- #

print("[+] Related SIGMA Rules")


if os.path.isdir("Resources/sigma-master/") == False: # ! Check if Sigma Rules exist 
    print("[+] Downloading SIGMA Rules ...")
    Command2 = "git clone https://github.com/SigmaHQ/sigma Resources/sigma-master  > /dev/null 2>&1"
    os.system(Command2) # Clone Sigma Rules

if os.path.isfile(SIGMA_CSV) == False:
  print("[+] The local list of SIGMA rules does not exists. Thus, we are creating a new one ...")
  for rule in glob.iglob(Local_Path  + '**/**', recursive=True):
    if rule.endswith('.yml'): 
      #print(rule)
      with open(rule,'r',encoding='utf-8') as q: #errors='ignore'
        try:
          yaml_query = yaml.load(q, Loader=yaml.FullLoader)
          for j in range(len(yaml_query["tags"])):
            print("[+] "+ (str(yaml_query["tags"][j]).replace("t","T").replace("aTTack.","")) +" "+str(rule))
            SGM.append({"Techniques":str(yaml_query["tags"][j]).replace("t","T").replace("aTTack.",""),"Rule":str(rule)})
            
        except:
          pass
          
  df = pd.DataFrame(SGM)       
  df.to_csv('Resources/SGR.csv')
  with open(SIGMA_CSV,'r') as ru:
    rules = csv.reader(ru, delimiter=',')
    #for W in range(len(Watchlist)):
    for row in rules:
      for W in Watchlist:
        if W in str(row):
          #print(row[1:])
          Rp_SIGMA.append({"Techniques":row[1],"Rule":row[2]})

  
  for rule in Rp_SIGMA:
    print(rule["Techniques"]," ",rule["Rule"])

else:
  with open(SIGMA_CSV,'r') as ru:
    rules = csv.reader(ru, delimiter=',')
    #for W in range(len(Watchlist)):
    for row in rules:
      for W in Watchlist:
        if W in str(row):
          #print(row[1:])
          Rp_SIGMA.append({"Techniques":row[1],"Rule":row[2]})

for rule in Rp_SIGMA:
  print(rule["Techniques"]," ",rule["Rule"])
#print(Rp_SIGMA)

Nb_Sigma = len(Rp_SIGMA)

# ------------------------- Atomic Tests -------------------------- #

print(termcolor.colored("[+] Related Atomic Tests","cyan"))

with open("Resources/Layers/art-navigator-layer.json","r") as r:
  Atomic_Tests = json.load(r)

Atomic_Tests_Techniques = []
for i in range(len(Atomic_Tests["techniques"])):
  Atomic_Tests_Techniques.append(Atomic_Tests["techniques"][i]["techniqueID"])

Atomic_Tests_Techniques = list(dict.fromkeys(Atomic_Tests_Techniques)) #Deletes Duplicates

Rp_Atomics =  []

for atomic_technique in Atomic_Tests_Techniques:
  for W in Watchlist:
    if str(W) == str(atomic_technique):
      print(str(W),": ","https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/"+str(W)+"/"+str(W)+".md")
      Rp_Atomics.append({"Technique":W,"URL":"https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/"+str(W)+"/"+str(W)+".md"})

Nb_Atomics = len(Rp_Atomics)

# ------------------------- Coverage Score Calculation---------------------------- # 

Coverage_Score = (int(Nb_Coverage)*100)//int(Nb_Threats) 

# ------------------------- Generate Reports---------------------------- # 


print("[+] Generating the final report ...") 

# Generate Excel (xlsx) Report

df_Atomics = pd.DataFrame(Rp_Atomics)
df_SIGMA = pd.DataFrame(Rp_SIGMA)
df_NIST = pd.DataFrame(Rp_NIST)
df_D3FEND = pd.DataFrame(Rp_D3FEND)
df_Controls = pd.DataFrame(Rp_Controls)
df_Coverage = pd.DataFrame(Rp_Coverage)
df_Threats = pd.DataFrame(Rp_Threats)


with pd.ExcelWriter('Reports/finalReport.xlsx') as writer:  
    df_Atomics.to_excel(writer, sheet_name='Atomic Tests')
    df_SIGMA.to_excel(writer, sheet_name='SIGMA Rules')
    df_NIST.to_excel(writer, sheet_name='NIST Mitigations')
    df_D3FEND.to_excel(writer, sheet_name='Defenses')
    df_Controls.to_excel(writer, sheet_name='Native Security Controls')
    df_Coverage.to_excel(writer, sheet_name='Azure Sentinel Coverage')
    df_Threats.to_excel(writer, sheet_name='Threat Profile Techniques')


# Generate Web Report

# datetime object containing current date and time
now = datetime.now()
 # dd/mm/YY H:M:S
dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
Nb_Time = dt_string

#output = template.render(Rp_Atomics=Rp_Atomics,Rp_SIGMA=Rp_SIGMA,Rp_NIST=Rp_NIST,Rp_D3FEND=Rp_D3FEND,Rp_Controls=Rp_Controls)
output = template.render(Rp_Atomics=Rp_Atomics,Rp_SIGMA=Rp_SIGMA,Rp_NIST=Rp_NIST,Rp_D3FEND=Rp_D3FEND,Rp_Controls=Rp_Controls,
Rp_Coverage=Rp_Coverage,Rp_Threats=Rp_Threats,
Nb_Threats=Nb_Threats,Nb_Atomics=Nb_Atomics,Nb_Coverage=Nb_Coverage,Nb_D3FEND=Nb_D3FEND,Nb_Sigma=Nb_Sigma,Nb_Time=Nb_Time,
Coverage_Score=Coverage_Score,Series=Series,Labels=Labels)
#print(output)



with open('Web-Report.html', 'w') as f:
    f.write(output)
print("[+] A Web Page Report was generated Successfully")
