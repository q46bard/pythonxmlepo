"""
HIPS 8 FW XML Parser

UPDATED NOV 2018 - v400 - See Changelog at Bottom
UPDATED OCT 2017 - v302 - See Changelog at Bottom
UPDATED OCT 2015 - v301

Provided as is, no guarantees this will work.

Author: Nathan Hirst

usage: python3 HIPS_8_FW_XML_Parser.py <HIPS 8 FW XML file to parse>
"""
import xml.parsers.expat as expat
import csv, os, copy, sys, time

class FWRule():
    #class to contain firewall rule as object
    def __init__(self, GUID=None):
        self.name = ""
        self.GUID = GUID
        self.action = ""
        self.group = ""
        self.direction = ""
        self.ruleenabled = ""        
        self.remotenetwork = []
        self.remoteport = []
        self.localnetwork = []        
        self.localport = []
        self.networkprotocol = ""
        self.transportprotocol = "All"
        self.executable = []
        self.exename = []
        self.exehash = []
        self.appsigner = []
        self.exenote = []
        self.rulenote = []
        self.aggref = []
        self.lastmodified = ""
        self.LastModifyingUsername = ""
        
    def __str__(self):
        #returns rule as a comma separated string: Group, Name, Action, Direction, Status, Network Protocol, Transport Protocol, Local Address, Local Service, Remote Address,   
        #Remote Service, Application, App Path, Fingerprint, AppSigner, ExeNote, RuleNote, Last Modified, Last Modifying Username
        returnstring = "\"%s\",\"%s\",\"%s\",%s,%s,%s,%s," % (self.group, self.name, self.action, self.direction, self.ruleenabled, self.networkprotocol, self.transportprotocol)
        if (self.remotenetwork == []):
            returnstring += "Any,"
        else:
            returnstring += "\""
            for net in self.remotenetwork:
                returnstring += net
            returnstring += "\","
        if (self.remoteport == []):
            returnstring += "Any,"
        else:
            returnstring += "\""
            for port in self.remoteport:
                returnstring += port
            returnstring += "\","
        if (self.localnetwork == []):
            returnstring += "Any,"
        else:
            returnstring += "\""
            for net in self.localnetwork:
                returnstring += net
            returnstring += "\","   
        if (self.localport == []):
            returnstring += "Any,"
        else:
            returnstring += "\""
            for port in self.localport:
                returnstring += port
            returnstring += "\","        
        #---Exe Name---    
        beenthrough = False
        returnstring += "\""
        for exe in self.exename:
            if (beenthrough):
                returnstring += ", "
            returnstring += exe
            beenthrough = True
        returnstring += "\","
        #---Executable---
        beenthrough = False
        returnstring += "\""
        for exe in self.executable:
            if (beenthrough):
                returnstring += ", "
            returnstring += exe
            beenthrough = True
        returnstring += "\","
        #---Exe Hash---
        beenthrough = False
        returnstring += "\""
        for exe in self.exehash:
            if (beenthrough):
                returnstring += ", "
            returnstring += exe
            beenthrough = True
        returnstring += "\","
        #---App Signer---
        beenthrough = False
        returnstring += "\""
        for exe in self.appsigner:
            if (beenthrough):
                returnstring += ", "
            returnstring += exe
            beenthrough = True
        returnstring += "\","
        #---Exe Note---
        beenthrough = False
        returnstring += "\""
        for exe in self.exenote:
            if (beenthrough):
                returnstring += ", "
            returnstring += exe
            beenthrough = True
        returnstring += "\","
        #---Rule Note---
        beenthrough = True
        returnstring += "\""
        for exe in self.rulenote:
            if (beenthrough):
                returnstring += ""
            returnstring += exe
            beenthrough = True
        returnstring += "\","
        #---Last Modified Date---
        if (self.lastmodified == []):
            returnstring += "Any,"
        else:
            returnstring += "\""
            for mod in self.lastmodified:
                returnstring += mod
            returnstring += "\","
        #---Last Modified User Name---
        if (self.LastModifyingUsername == []):
            returnstring += ""
        else:
            returnstring += "\"" 
            for mod in self.LastModifyingUsername:
                returnstring += mod
            returnstring += "\","
        #---End of defined strings---
        return returnstring 
	
class aggregate():
    #class to contain aggregate information for rules, these are either applications, or network information
    #note that for a particular aggregate not all member variables will have information depending on type
    def __init__(self, GUID=None):
        self.name = ""
        self.apppath = ""
        self.appname = ""
        self.apphash = ""
        self.appsigner = ""
        self.exenote = ""
        self.rulenote = ""
        self.ruleenabled = ""
        self.remotenetwork = ""
        self.localnetwork = ""
        self.GUID = GUID
        self.type = 0
        
class GrowingList(list):
    """This is a class to allow easier insertion of rules that may appear out of order to insert the ID sequence into the correct space although the correct space didn't exist at the time it will grow to have enough space. 
    i.e. if we currently have a list and we've inserted items into [0] and [1] then we see the next item to insert should be at [10] it will grow the list and have None place holders for items [2]-[9]"""
    def __setitem__(self, index, value):
        if index >= len(self):
            self.extend([None]*(index + 1 - len(self)))
        list.__setitem__(self, index, value)
        
class RuleIDSequence():
    #class to contain group rule order, uses growinglist to allow for rules to be added out of order from XML
    def __init__(self, GUID=None):
        self.rulelist = GrowingList()
        self.GUID = GUID

def ipFieldFromHex(hex_field):
    ip_dict = {'0000:0000:0000:0000:0000:0000:0000:0000':'Any',
               '[trusted]':'Trusted'}
    subnet_mask = ''
    ip_v4 = False
    for key in ip_dict:
        if key in hex_field:
            return ip_dict[key]
    if hex_field.startswith('0000:0000:0000:0000:0000:ffff:'):
        hex_field = hex_field.replace(
            '0000:0000:0000:0000:0000:ffff:', '')
        ip_v4 = True
    if (ip_v4 != True):
        return hex_field
    if ('-' in hex_field):
        hex_field = hex_field.split('-')
        for y in range(2):
            hex_field[y] = hex_field[y].split(':')
            for z in range(2):
                first_oct = int(hex_field[y][z][:2], 16)
                second_oct = int(hex_field[y][z][2:], 16)
                hex_field[y][z] = (str(first_oct) + '.' +
                                   str(second_oct))
            hex_field[y] = hex_field[y][0] + '.' + hex_field[y][1]
        hex_field = hex_field[0] + ' - ' + hex_field[1]
        return hex_field
    if ('/' in hex_field):
        hex_field = hex_field.split('/')
        subnet_mask = int(hex_field[1]) - 96
        subnet_mask = '/' + str(subnet_mask)
        hex_field = hex_field[0]
    hex_field = hex_field.split(':')
    for z in range(2):
        first_oct = int(hex_field[z][:2], 16)
        second_oct = int(hex_field[z][2:], 16)
        hex_field[z] = (str(first_oct) + '.' + str(second_oct))
    hex_field = hex_field[0] + '.' + hex_field[1]
    hex_field  = hex_field + subnet_mask
    return hex_field
        
        
def start(name, attr):
    #function to parse each line in XML with a start tag
    global Rules, currentGUID, currentsectiontype, linecount, Rulesequences, Aggregates, listIDfound
    #print ('current line parse', name, attr)
    linecount += 1
    if (name == "EPOPolicySettings"):
        #print ('line: ', name, attr)
        if (attr['featureid'] != 'HOSTIPS_8000_FW'):
            raise Exception("invalid file type, cannot process ", attr['featureid'])
        nameelements = attr['name'].split(':')
        currentsectiontypeparam = attr['param_int']
        if currentsectiontypeparam == '101':
            currentsectiontype = "Rule"
        elif currentsectiontypeparam == '100':
            currentsectiontype = "Sequence"
        elif currentsectiontypeparam == '104':
            currentsectiontype = "Aggregate"
        #print (currentsectiontype)
        currentGUID = nameelements[2]
        if (currentsectiontype=="Rule"):
            Rules[currentGUID] = FWRule(currentGUID)
            #print ("created new rule for", currentGUID)
        elif (currentsectiontype == "Aggregate"):
            Aggregates[currentGUID] = aggregate(currentGUID)
            #print ("create aggregate for", currentGUID)
        elif (currentsectiontype == "Sequence"):
            Rulesequences[currentGUID] = RuleIDSequence(currentGUID)
            listIDfound = False
            #print ("create sequence for", currentGUID)
    if (currentsectiontype == "Rule"):
        if (name == "Setting"):
            if (attr['name'] == "Name"):
                #print ("adding name ", attr['value'], "to rule", currentGUID)
                Rules[currentGUID].name = attr['value']
            if (attr['name'] == "Action"):
                Rules[currentGUID].action = attr['value']
            if (attr['name'] == "Direction"):
                Rules[currentGUID].direction = attr['value']
            if (attr['name'] == "LastModified"):
                date = attr['value'].split('T')
                Rules[currentGUID].lastmodified = date[0]
            if "+LocalPort" in attr['name']:
                Rules[currentGUID].localport.append(attr['value'])
            if (attr['name'] == "+TransportProtocol#0"):
                translate = {'0':'HOPOPT','1':'ICMP','2':'IGMP','4':'IPv4','6':'TCP','17':'UDP','41':'IPv6','46':'RSVP','47':'GRE','50':'IPsec ESP','58':'ICMPv6','89':'OSPFIGP','94':'IPIP','103':'PIM','1024':'All IP'}
                if attr['value'] in translate:
                    Rules[currentGUID].transportprotocol = translate[attr['value']]
                else:
                    Rules[currentGUID].transportprotocol = "Transport Protocol " + attr['value']
            if "+NetworkProtocol" in attr['name']:
                translate = {'2048':'IPv4','34525':'IPv6','34958':'0x888e'}
                if (Rules[currentGUID].networkprotocol != ""):
                    Rules[currentGUID].networkprotocol += "/"
                if attr['value'] in translate:
                    Rules[currentGUID].networkprotocol += translate[attr['value']]
                else:
                    Rules[currentGUID].networkprotocol += "Network Protocol " + attr['value']
                
            if "+RemotePort" in attr['name']:
                Rules[currentGUID].remoteport.append(attr['value'])
            if "+AggRef" in attr['name']:
                #print ("adding agg", attr['value'], "to", currentGUID)
                Rules[currentGUID].aggref.append(attr['value'])
            if (attr['name'] == "GUID"):
                if currentGUID != attr['value']:
                    Rules[attr['value']] = Rules[currentGUID]
                    #print ("Rules just got a lot more complicated")
            if "+AppSigner" in attr['name']:
                Aggregates[currentGUID].appsigner = attr['value']
            #---Rule Note Begin---
            if (attr['name'] == "Note"):
                Rules[currentGUID].rulenote = attr['value']
                #print ("adding Rule Note ", attr['value'])
            #---Rule Enabled Begin---
            if (attr['name'] == "Enabled"):
                Rules[currentGUID].ruleenabled = attr['value']
                if attr['value'] == "1":
                    Rules[currentGUID].ruleenabled = "Enabled"
                else:
                    Rules[currentGUID].ruleenabled = "Disabled"
                #print ("adding Enabled ", attr['value'])
            #---Rule Enabled End---                
    elif (currentsectiontype == "Aggregate"):
        if (name == "Setting"):
            if (attr['name'] == "Name"):
                Aggregates[currentGUID].name = attr['value']
            if "+AppPath" in attr['name']:
                Aggregates[currentGUID].apppath = attr['value']
            if "+AppHash" in attr['name']:
                Aggregates[currentGUID].apphash = attr['value']
                if attr['value'] == "00000000000000000000000000000000":
                    Aggregates[currentGUID].apphash = "None"
            if "+AppSigner" in attr['name']:
                Aggregates[currentGUID].appsigner = attr['value']
                #print ("adding signer ", attr['value'])
            if "Note" in attr['name']:
                Aggregates[currentGUID].exenote = attr['value']
                #---Executable Note---
            if (attr['name'] == "Type"):
                Aggregates[currentGUID].type = attr['value']
            if "+RemoteAddress" in attr['name']:
                Aggregates[currentGUID].remotenetwork = attr['value']
            if "+LocalAddress" in attr['name']:
                Aggregates[currentGUID].localnetwork = attr['value']
            if "+AppName" in attr['name']:
                Aggregates[currentGUID].appname = attr['value'] 
            if "+DnsSuffix" in attr['name']:
                Aggregates[currentGUID].localnetwork = attr['value']
            if (attr['name'] == "GUID"):
                if currentGUID != attr['value']:
                    Aggregates[attr['value']] = Aggregates[currentGUID]
                    #print ("Aggregates just got a lot more complicated")
    elif (currentsectiontype == "Sequence"):
        if (name == "Setting"):
            if "+RuleIDSequence" in attr['name']:
                nums = attr['name'].split('#')
                index = int(nums[1])
                Rulesequences[currentGUID].rulelist[index] =  attr['value']
                #print (nums[1], "set to", Rulesequences[currentGUID].rulelist[index])
            if "_RuleIDSequence" in attr['name']:
                if len(Rulesequences[currentGUID].rulelist) != int(attr['value']):
                    print ("uh oh not right length", len(Rulesequences[currentGUID].rulelist))
            if (attr['name'] == "RuleListID"):
                listIDfound = True
                if currentGUID != attr['value']:
                    Rulesequences[attr['value']] = Rulesequences[currentGUID]
                    #print ("Sequence ", attr['value'], "set to", currentGUID)
 
def end(name):
    #function to parse each line in XML with an end tag
    global Rules, currentGUID, currentsectiontype, linecount, Rulesequences, Aggregates, listIDfound
    #if (name != "Setting"):
        #print ("closing out", name, "for", currentGUID)
        #currentGUID = "" 
    if (name == "EPOPolicySettings"):
        if currentsectiontype == "Sequence":
            if listIDfound == False:
                #print ("no sequence ID found null is", currentGUID)
                Rulesequences['null'] = Rulesequences[currentGUID]
        #print ("closing out", currentsectiontype, currentGUID, "Lines in this section: ", linecount)
        linecount = 0
        currentsectiontype = ""
        currentGUID = ""
        
def processaggs(rule):
    #adds in rule's aggregate information into the rule's object
    global Aggregates
    for agg in rule.aggref:
        if agg in Aggregates.keys():
            #print ("proccessing agg ", agg, "for rule", rule.GUID)
            if (int(Aggregates[agg].type) == 65547):
                #Aggregate contains Application information
                rule.executable.append (Aggregates[agg].apppath)
                rule.exename.append (Aggregates[agg].appname)
                rule.exehash.append (Aggregates[agg].apphash)
                rule.appsigner.append (Aggregates[agg].appsigner)
                rule.exenote.append (Aggregates[agg].exenote)
            if (int(Aggregates[agg].type) == 65546):
                #Aggregate contains remote network information
                rule.remotenetwork.append(ipFieldFromHex(Aggregates[agg].remotenetwork))
            if (int(Aggregates[agg].type) == 65541):
                #Aggregate contains local network information
                rule.localnetwork.append(ipFieldFromHex(Aggregates[agg].localnetwork))
            if (int(Aggregates[agg].type) == 65543):
                #Aggregate contains DNSSuffix information
                rule.localnetwork.append(Aggregates[agg].localnetwork)
        
def orderrules(rules, sequences, value):
    finallist = []
    #print ("processing list for", value)
    for ID in sequences[value].rulelist:
        if ID in rules.keys():
            if value != 'null':
                rules[ID].group = rules[value].group
            finallist.append(ID)
        if ID in sequences.keys():
            rules[ID].group = rules[ID].name
            rules[ID].name = ""
            newlist = orderrules(rules, sequences, ID)
            finallist.extend(newlist)
            
    return finallist
        
def main(argv, CSV = False):
    csv = CSV
    #print (len(argv))
    if (len(argv) < 2):
        print ("Not enough arguments\n Usage HIPS_8_FW_XML_Parser_Action.py [XML file to parse] [Optional: Date of rules changed since in format MM-DD-YYYY]")
        exit(0)
    filename = argv[1]
    onlyrulessince = False
    
    xml_file = open(filename, 'rb')
    
    #print (filename)
    p = expat.ParserCreate()
    p.StartElementHandler = start
    p.EndElementHandler = end
    global Rules, Rulesequences, Aggregates
    global currentsectiontype, linecount
    currentsectiontype = ""
    linecount = 0
    Rules = {}
    Rulesequences = {}
    Aggregates = {}
    global currentGUID 
    currentGUID = ""
    try:
        #print ("starting parse")
        p.ParseFile(xml_file)
    except expat.ExpatError as err:
        print ("Error:", expat.errors.messages[err.code])
    #print ("finished parse")
    if (len(argv) >= 3):
        #print ("date provided")
        onlyrulessince = True
    if csv and not onlyrulessince:
        csv_file = open(filename[:-4] + '_CSV_TR.csv', 'w')
    if (onlyrulessince):
        rulessincestr = argv[2]
        rulessince = time.strptime(rulessincestr, "%m-%d-%Y")
        if csv:
            csv_file = open(filename[:-4] +'_'+ rulessincestr +'_CSV_TR.csv', 'w')
        #print (rulessince)
    if not csv:
        print ("Group, Name, Action, Direction, Status, Network Protocol, Transport Protocol, Remote Address, Remote Service, Local Address, Local Service, Application, App Path, Fingerprint, Signer, ExeNote, RuleNote, Last Modified, Last Modifying Username")
    else:
        csv_file.write("Group, Name, Action, Direction, Status, Network Protocol, Transport Protocol, Remote Address, Remote Service, Local Address, Local Service, Application, App Path, Fingerprint, Signer, ExeNote, RuleNote, Last Modified, Last Modifying Username\n")
    for key in Rules.keys():
        if "Settings" in key:
            continue
        if (len(Rules[key].aggref) != 0):
            #print (key)
            processaggs(Rules[key])
        #print (Rules[key])
    orderedruleset = orderrules(Rules, Rulesequences, 'null')
    for rule in orderedruleset:
        if (onlyrulessince):
            #parse time
            #print (Rules[rule].lastmodified)
            if (time.strptime(Rules[rule].lastmodified, "%Y-%m-%d") > rulessince):
                if not csv:
                    print (Rules[rule])
                else:
                    csv_file.write(str(Rules[rule]))
                    csv_file.write('\n')
                
        else:
            if not csv:
                print (Rules[rule])
            else:
                csv_file.write(str(Rules[rule]))
                csv_file.write('\n')
    if csv:
        csv_file.close()
    


    
        
if __name__=="__main__":
    main(sys.argv, False)




################################################################################
# BEGIN: Changelog
################################################################################
#   v400 -      CANES:  Added Last Modified column to output.
#                       Added Last Modifying Username column to output.
#                       Updated Transport Protocols
#                            ~ Terrence L. Ward
#
#   v302 -    JIRA CDD 290: Added Digital Signer column to output.
#                           Added Executable Note column to output.
#                           Added Rule Group Note column to output.
#                           Added Rule Enabled column to output.
#                               ~ Brian Foster
################################################################################
# END: Changelog
################################################################################


