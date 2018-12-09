"""Classes for HBSS XML Parser
Developed by: Wade, Timothy J
tjwade.sd@gmail.com
"""

tool_version = 0.201

import csv, os, copy, xml.dom.minidom

################################################################################
# BEGIN CLASS DECLARATION
################################################################################
#
#
#
################################################################################
# BEGIN: XML Modification Classes
################################################################################
#
#
# HBSSXMLParser
class HBSSXMLParser():
    '''The HBSSXMLParser Class is the core class used to drive through various
types of XMLs that may be exported by the McAfee ePolicy Orchestrator.  It
contains two attributes of type List:  xml_list and hbss_object_list.  Each list
begins with no elements.  Through the methods of this class, those lists may
be populated.  The xml_list is used for hold all files ending with the .XML
extension.  Then, one by one, each file is checked to determine if it contains
strings that identify it as a supported product.  For each supported product,
the hbss_object_list is appended with an object that contains the necessary
dictionaries and methods to parse that .XML file and create a spreadsheet
appropriate to its function.
'''
    def __init__(self):
        '''An HBSSXMLParser Object begins with two empty lists, and a dictionary
of supported products.  This dictionary ties supported products to the function
necessary to build objects associated with each supported product.
'''
   
        self.xml_list = []
        self.hbss_object_list = []
        self.product_dict = {'HOSTIPS_7000_IPS':self.ips7000HipsBLDR,
                             'HOSTIPS_8000_IPS':self.ips8000HipsBLDR,
                             'HOSTIPS_7000_FW':self.ips7000FWBLDR,
                             'HOSTIPS_7000_APP':self.ips7000ABBLDR
                             }

    def singleFileXMLListBLDR(self, file):
        '''The singleFileXMLListBLDR is used to add a single .XML file into the
xml_list, for the conversion into a single .CSV file.
'''
        self.xml_list.append(file)

    def currentDirXMLListBLDR(self):
        '''The currentDirXMLListBLDR is used to create a list of .XML files
based on the current directory that this object resides in, as determined by
the os.listdir() function. (This creates the dependancy that requires an
'import os'.)
'''
        for each_file in os.listdir():
            if each_file.endswith('.xml'):
                self.xml_list.append(each_file)

    def ips7000HipsBLDR(self, xml_file):
        '''The ips7000HipsBLDR function creates an object of type HIPS_7000,
which contains the dictionary and methods necessary to parse a HIPS 7 IPS
policy.  It is passed an xml_file that will associated with that object.
'''
        return HIPS_7000(xml_file)

    def ips8000HipsBLDR(self, xml_file):
        '''The ips8000HipsBLDR function creates an object of type HIPS_8000,
which contains the dictionary and methods necessary to parse a HIPS 8 IPS
policy.  It is passed an xml_file that will be associated with that object.
'''        
        return HIPS_8000(xml_file)

    def ips7000FWBLDR(self, xml_file):
        '''The ips7000FWBLDR function creates an object of type IPS_FW_7000,
which contains the dictionary and methods necessary to parse an IPS 7 FW policy.
It is passed an xml_file that will be associated with that object.
'''         
        return IPS_FW_7000(xml_file)

		
    def ips7000ABBLDR(self, xml_file):
        '''The ips7000ABBLDR function creates an object of type IPS_AB_7000,
which contains the dictionary and methods necessary to parse an IPS 7 AB policy.
It is passed an xml_file that will be associated with that object.

NOTE:  Application Blocking is no longer a supported module in HIPS 8, and
this functionality is instead found in the IPS component using signature
6010 and 6011.
'''
        return IPS_AB_7000(xml_file)

    def hbssObjectListBLDR(self):
        '''The hbssObjectListBLDR function iterates through each element of the
xml_list attribute of this class and invokes the hbssObjectCreator function.
If the local variable 'hbss_object' is not Null, it will append the returned
object to the hbss_object_list.
'''
        for each_file in self.xml_list:
            hbss_object = self.hbssObjectCreator(each_file)
            if (hbss_object):
                self.hbss_object_list.append(hbss_object)

    def hbssObjectCreator(self,xml_file):
        '''The hbssObjectCreator function is passed an xml_file by the function
hbssObjectListBldr.  It opens that xml_file, and begins to iterate through each
line of the xml file, checking each line against its dictionary of supported
products.  If a key value from that dictionary is found in a line of the XML
it will use that key to call the function associated to that key, passing
the xml_file, and then return the resultant object from that function call.

It will check up to 20 lines of an XML before aborting.
'''
        with open(xml_file, 'r') as product_checker:
            x = 0
            for current_line in product_checker:
                if (x > 20):
                    return
                for key in self.product_dict:
                    if key in current_line:                        
                        return self.product_dict[key](xml_file)
                x += 1
        
    def hbssObjParseToCSV(self):
        '''The hbssObjParseToCSV function will iterate through each element of
the hbss_object attribute, and invoke the parseAndWritetoCSV method on each
object.  This method is implemented uniquely on each type of supported product,
resulting in specially formatted CSV spreadsheets based on that product.
'''
        for hbss_object in self.hbss_object_list:
            try:
                if ("HOSTIPS_8000" in hbss_object.PolicyType):
                    hbss_object.HIPS8_parseAndWriteToCSV()
                elif ("HOSTIPS_7000" in hbss_object.PolicyType):
                    hbss_object.parseAndWriteToCSV()
            except AttributeError:
                pass


################################################################################
# END: XML Modification Classes
################################################################################
#
################################################################################
# BEGIN: HBSS Master Object Class
################################################################################
#
#
# HBSSMasterObject
class HBSSMasterObject:
    '''The HBSSMasterObject is the parent class of all HBSS supported objects
below.
'''
    def __init__(self, input_xml_file = None):
        self.input_xml_file = input_xml_file
        self.output_csv_file = self.input_xml_file[:-4] + '_CSV.csv'
        
################################################################################
# END: HBSS Master Object Class
################################################################################
#
################################################################################
# BEGIN: IPS Classes
################################################################################
#
#
# HIPS_CORE child of HBSSMasterObject
class HIPS_Core(HBSSMasterObject):
    '''The HIPS_Core class is a child of the HBSSMasterObject and contains
common elements between IPS products.  These elements either affect the means
by which the XML is parsed or final output spreadsheet.  the default_d
dictionary defines a correlation between the default cell value of a row, as it
relates to the column that it resides in.  The csv_d attribute correlates an
XML tag type to the column that it will be placed in.  The running_csv is used
as a line builder list, and begins with a number of empty elements equal to the
number of header columns that have been defined in the code.  The xml_dkey is
a key that operates on the list entries of the xml_d dictionary.  The xml_d is a
dictionary that maps the strings associated with specific XML tags to the
csv_d dictionary, and parameter type.  The xml_control dictionary includes the
strings associated with controlling the main loop of XML parsing such as where
to begin exceptions, where to end exceptions, and how to split lines into a
tag/value.  The header_list is used to define the first line of the spreadsheet.
'''
    def __init__(self, input_xml_file = None):
        '''A HIPS_Core object is passed an xml_file that has been validated to
contain key information identifying it as an XML associated with an IPS product.
The dictionaries below may be modified to alter the behavior of this class as
well as update with new parameters and future updates.  To add a new XML tag,
modify the xml_d in the following way:  Use a key that will informally identify
the parameter, and format the associated list entry such that the first element
contains the XML tag, the second element contains the 'param_val' entry to place
the results into the parameter column, and the third element of the list
formally identifying its parameter type.

The two boolean values of 'has_signature' and 'all_signatures' limits the
final written results only to entries included in the XML that are actual
policy exceptions tied to specific signatures, or allowing
users/files/parameters to act on all signatures.  These values support logic
to eliminate extra, non-exception related data contained in the XML from
being written to the final output.
'''
        HBSSMasterObject.__init__(self, input_xml_file)
        self.default_d = {0:'Default name',
                          1:'Any',
                          2:'All Users',
                          3:'Any Executable',
                          4:'',
                          5:'',
                          6:'Unknown'
                          }
        self.csv_d = {'excep_name':0,
                     'sig':1,
                     'users':2,
                     'executable':3,
                     'param_val':4,
                     'note':5,
                     'Last_modified':6
                     }
        self.running_csv = ['']*len(self.csv_d)
        self.xml_dkey = {'xml_tag':0,
                        'cell_array':1,
                        'param_type':2
                        }
        self.xml_d = {'signature':['2$SignatureID#', 'sig', 'NA'],
                      'user':['+OSUserName#', 'users', 'NA'],
                      'file':['+$files#', 'param_val', 'File(s): '],
                      'reg_key':['+$keys#', 'param_val', 'Registry Key(s): '],
                      'reg_val':['$values#',
                                 'param_val',
                                 'Registry Value(s): '],
                      'notes':['<Setting name="Note"', 'note', 'NA'],
                      'excep_name':['<Setting name="Name"', 'excep_name', 'NA'],
                      'Last_modified':['<Setting name="LastModify', 'Last_modified', 'NA']
                     }
        self.xml_control = {'val_split':'value="',
                           'begin_tag':'<EPOPolicySettings',
                           'end_tag':'</EPOPolicySettings>',
                           'exception':'IPSException'
                           }
        self.header_list = ['Exception Name',
                            'Signature',
                            'Users',
                            'Executable',
                            'Parameter Type: Value',
                            'Notes',
                            'LastModified'
                            ]
        self.has_signature = False
        self.all_signatures = False
        
    def adjustInputFile(self, input_file):
        '''This method allows the input_xml_file to be modified at runtime.
'''
        self.input_xml_file = input_file

    def adjustOutputFile(self, output_file):
        '''This method allows the output_csv_file to be modified at runtime.
'''
        self.output_csv_file = output_file

    def parseAndWriteToCSV(self):
        '''This method is implemented in all HBSS product objects, unique to the
requirements of their product type.  It will parse through the XML file
associated with this object, creating the parsed_list local variable after
passing a number of its attributes to the parserIPSMacro function.  This
pased_list will be passed to the csvWriter function, along with the
output_csv_file, and the header_list.
'''
        parsed_list = self.parserIPSMacro(self.input_xml_file,
                                          self.xml_control,
                                          self.running_csv,
                                          self.csv_d,
                                          self.default_d)
        self.csvWriter(self.output_csv_file, self.header_list,
                       parsed_list)
    
    def HIPS8_parseAndWriteToCSV(self):         
        parsed_list = self.HIPS8_parserIPSMacro(self.input_xml_file,
                                          self.xml_control,
                                          self.running_csv,
                                          self.csv_d, self.default_d)
        self.csvWriter(self.output_csv_file, self.header_list,
                       parsed_list)
      
    def HIPS8_parserIPSMacro(self, input_xml_file, xml_control, running_csv, csv_d, default_d):
        node = []
        section = []
        setting = []
        single_line_list = []
        app_path = ""
        target_app_path = ""
        parameter_name = ""
        parameter_value = ""
        signatureID = ""
        users = ""
        all_sig = True
        all_user = True
        dom = xml.dom.minidom.parse(input_xml_file)
        for node in dom.getElementsByTagName("EPOPolicySettings"):
            isException = False            
            if (node.getAttribute ("param_int") == "1"):                
                isException = True
                running_csv = ['']*len(self.csv_d)
                app_path = ""
                target_app_path = ""
                parameter_name = ""
                parameter_value = ""
                signatureID = ""
                users = ""
                all_sig = True
                all_user = True
            if isException:                                      
                for section in node.getElementsByTagName('Section'):  
                    for setting in section.getElementsByTagName('Setting'):
                        if (setting.getAttribute ("name") == "Name"):
                            running_csv[0] = setting.getAttribute ("value")
                        if ("2$SignatureID#" in setting.getAttribute ("name")):
                            signatureID += setting.getAttribute ("value") + ' '
                            all_sig = False
                        if ("OSUserName#" in setting.getAttribute ("name")):
                            users += setting.getAttribute ("value") + ' '
                            all_user = False
                        if ("+AppPath#" in setting.getAttribute ("name")):
                            app_path += setting.getAttribute ("value") + ' '   
                        if ("+TargetAppPath#" in setting.getAttribute ("name")):
                            target_app_path += setting.getAttribute ("value") + ' '
                        if ("+$" in setting.getAttribute ("name")):
                            parameter_name = setting.getAttribute ("name")[2:-2]
                            parameter_value = setting.getAttribute ("value")
                            running_csv[4] += parameter_name + ":" + parameter_value + ' '
                        if (setting.getAttribute ("name") == "Note"):
                            running_csv[5] = setting.getAttribute ("value")
                        if (setting.getAttribute ("name") == "LastModifyDate"):
                            justdate = setting.getAttribute ("value").split('T')
                            running_csv[6] = justdate[0]
                if (all_sig):
                    running_csv[1] = "All signatures"
                else:
                    running_csv[1] = signatureID
                if (all_user):
                    running_csv[2] = "All users"
                else:
                    running_csv[2] = users
                if (app_path != ""):
                    running_csv[3] = "app_path: " + app_path
                if (target_app_path != ""):
                    running_csv[3] += "target_app_path: " + target_app_path
                single_line_list.append(running_csv)
        return single_line_list        

    def parserIPSMacro(self, input_xml_file, xml_control, running_csv,
                       csv_d, default_d):
        '''This is the main logic loop for parsing an HBSS product XML.  It
uses a single line builder logic, such that a single exeception is placed on
a single line.  It will call the parserIPSMicro to identify if each XML line
contains information that is related to an exception line for the resulting
spreadsheet.  Once an entire exception has been captured, that exception will
be placed in the single_line_list, which is a master list for each single
exception.  
Only lines that are related to exceptions are processed, skip the rest of the lines.
'''
        single_line_list = []
        isException = False
        with open(input_xml_file, 'r') as ips_xml:
            for each_line in ips_xml:                 
                if each_line.startswith(xml_control['begin_tag']) and xml_control['exception'] in each_line:
                    isException = True
                    running_csv = ['']*len(self.csv_d)
                if isException:
                    self.sigBooleanSetter(each_line)                    
                    csv_mapper = self.parserIPSMicro(each_line)
                    if (csv_mapper):
                        entry = each_line.split(xml_control['val_split'])
                        if (csv_mapper[1] == 'NA'):
                            csv_mapper[1] = ''
                        if (running_csv[csv_d[csv_mapper[0]]]):
                            running_csv[csv_d[csv_mapper[0]]] += ' '
                        running_csv[csv_d[csv_mapper[0]]] += (csv_mapper[1] +
                                                          entry[1][:-4])
                    if (each_line.startswith(xml_control['end_tag'])):
                        isException = False
                        if self.sigBooleanChecker(running_csv):
                            running_csv = self.defaultIPSValueCreator(running_csv,
                                                                  default_d)
                            single_line_list.append(running_csv)
        return single_line_list

    def sigBooleanChecker(self, running_csv):
        '''This function checks the boolean values that are marked when an
XML entry is truly a exception to IPS policy and allows an entry in the final
output if either of the values are true.

It resets the 'has_signature' and 'all_signatures' flags to false after the
check has been made.
'''
        if (self.has_signature or self.all_signatures):
            self.has_signature = False
            self.all_signature = False
            return True

    def sigBooleanSetter(self, this_line):
        '''Sets flags to support signature control logic.'''

        if ('2$SignatureID#' in this_line):
            self.has_signature = True
        if ('\"IncludeAllSignatures\" value=\"1\"' in this_line):
            self.all_signatures = True
            
    def parserIPSMicro(self, this_line):
        '''The parserIPSMicro is the logic necessary to be passed a single line
from the input XML, and comparse that line to the IPS dictionary.  If a match
is found, appropriate data related to that match is passed back to the
parserIPSMacro function.
'''
        for key in self.xml_d:            
            if (self.xml_d[key][self.xml_dkey['xml_tag']] in this_line):
                return ([self.xml_d[key][self.xml_dkey['cell_array']],
                         self.xml_d[key][self.xml_dkey['param_type']]])
        if ('+$' in this_line):      
            custom_param = this_line.split('+$')
            custom_param = custom_param[1].split('#')
            return ('param_val', custom_param[0] + ': ')
        return False

    def defaultIPSValueCreator(self, running_csv, default_d):
        '''This method will load the default entries of an empty cell into that
cell for final spreadsheet formatting.
'''
        for x in range(len(running_csv)):
            if (running_csv[x] == ''):
                running_csv[x] = default_d[x]
        return running_csv

    def csvWriter(self, output_csv_file, header_list, master_list):
        '''This method will iterate through the final formatted list of IPS
exceptions, writing a CSV file.
'''
        with open(output_csv_file, 'w', newline = '') as output_file:
            hips_writer = csv.writer(output_file, delimiter = ',')
            hips_writer.writerow(header_list)
            for each_entry in master_list:
                hips_writer.writerow(each_entry)        
#
#
# HIPS_7000 child of HIPS_CORE
class HIPS_7000(HIPS_Core):
    '''The HIPS_7000 class is a child of the HIPS_Core class, and contains the
unique elements of HIPS 7 to allow product specific parsing.
'''
    def __init__(self, input_xml = None):
        '''The xml_d is updated with the full suite of HIPS 7 specific XML tags
and HIPS 7 parameters
'''
        HIPS_Core.__init__(self, input_xml)
        self.PolicyType = "HOSTIPS_7000_IPS"
        self.xml_d['executable'] = ['+FullProcessName#', 'executable', 'NA']
        self.xml_d['application'] = ['+$application#', 'param_val',
                                     'Application: ']
        self.xml_d['dest_file'] = ['+$dest_file#', 'param_val',
                                   'Destination File: ']
        self.xml_d['display_name'] = ['+$display_names#', 'param_val',
                                      'Display Name: ']
        self.xml_d['method'] = ['+$method#', 'param_val', 'Method: ']
        self.xml_d['query'] = ['+$query#', 'param_val', 'Query: ']
        self.xml_d['services'] = ['+$services#', 'param_val', 'Services: ']
        self.xml_d['source'] = ['+$source#', 'param_val', 'Source: ']
        self.xml_d['url'] = ['+$url#', 'param_val', 'URL: ']
#
#
# HIPS_8000 child of HIPS_CORE
class HIPS_8000(HIPS_Core):
    '''The HIPS_8000 class is a child of the HIPS_Core class, and contains the
unique elements of HIPS 8 to allow product specific parsing.

THIS CLASS IS WORK IN PROGRESS

'''
    def __init__(self, input_xml = None):
        '''The xml_d is updated with the full suite of HIPS 8 specific XML tags
and HIPS 8 parameters

THIS __init___ function is a work in progress:  Does not contain the full
HIPS 8 dictionary at this time.

'''
        HIPS_Core.__init__(self, input_xml)
        self.PolicyType = "HOSTIPS_8000_IPS"
        self.xml_d['executable'] = ['+AppPath#', 'executable', 'NA']
        self.xml_d['target_exec'] = ['+TargetAppPath#', 'param_val',
                                     'Target Exectuable: ']
        self.xml_d['target_handler'] = ['+HandlerAppPath#', 'param_val',
                                        'Target Handler: ']
################################################################################
# END: IPS Classes
################################################################################
#
################################################################################
# BEGIN: Firewall Classes
################################################################################
#
#
# IPS_FW_Core child of HBSSMasterObject
class IPS_FW_Core(HBSSMasterObject):
    '''The IPS_FW_Core class is a child of the HBSSMasterObject and contains
common elements between Firewall products.
'''
    def __init__(self, input_xml_file = None):
        HBSSMasterObject.__init__(self, input_xml_file)
        self.PolicyType = "HOSTIPS_7000_FW"
    def csvWriter(self, final_list, output_csv_file = None):
        output_csv_file = output_csv_file or self.output_csv_file
        with open(output_csv_file, 'w', newline = '') as output_file:
            hips_writer = csv.writer(output_file, delimiter = ',')
            for each_row in final_list:
                hips_writer.writerow(each_row)
#
#
# IPS_FW_7000 child of IPS_FW_Core
class IPS_FW_7000(IPS_FW_Core):
        def __init__(self, input_xml_file = None):
            IPS_FW_Core.__init__(self, input_xml_file)
            self.num_of_rule_fields = 37
            self.parse_dict = {'begin':'<EPOPolicySettings',
                               'data_tag':'<Setting name="Data" value="',
                               'rule_ID':'<Setting name="RuleID" value="',
                               'Last_modified':'<Setting name="LastModifyDate" value="',
                               'rule_order':'<Setting name="+RuleIDSequence#',
                               'end':'</EPOPolicySettings>'
                               }
            self.cleaner_dict = {0:{'TRUE':'Enabled', 'FALSE':'Disabled'},
                                 1:{'TRUE':'Allow', 'FALSE':'Block'},
                                 3:{'0':'In/Out', '1':'In', '2':'Out'},
                                 4:{'0':'HOPOPT',
                                    '1':'ICMP',
                                    '2':'IGMP',
                                    '4':'IPv4',
                                    '6':'TCP',
                                    '17':'UDP',
                                    '41':'IPv6',
                                    '46':'RSVP',
                                    '50':'IPsec ESP',
                                    '58':'ICMPv6',
                                    '89':'OSPFIGP',
                                    '94':'IPIP',
                                    '103':'PIM',
                                    '1024':'All IP'},
                                 25:{'0':'',
                                     '33169':'NetBEUI',
                                     '32823':'IPX',
                                     '32923':'AppleTalk'},
                                 }
            self.header_on_off_key = {'Enabled':'N',
                                      'Action':'Y',
                                      'Direction':'Y',
                                      'Transport':'Y',
                                      'Destination':'Y',
                                      'Remote Port':'Y',
                                      'Local Port':'Y',
                                      'Name':'Y',
                                      'Exec':'Y',
                                      'Fingerprint':'Y',
                                      'Non-IP?':'Y',
                                      'Last Modified':'Y'                                      
                                      }
            self.header_dict = {0:'Enabled',
                                1:'Action',
                                3:'Direction',
                                4:'Transport',
                                6:'Destination',
                                8:'Remote Port',
                                9:'Local Port',
                                10:'Name',
                                11:'Exec',
                                12:'Fingerprint',
                                25:'Non-IP?'
                                }
                                      
        
        def parseAndWriteToCSV(self):
            policy_list, rule_seq_dict = self.initialParse()
            policy_list = self.policyOrderer(policy_list, rule_seq_dict)
            policy_list = self.policyFieldCleaner(policy_list)
            policy_list = self.groupRuleDivisionCreator(policy_list)
            policy_list = self.valuesFromCleanerDictionary(policy_list)
            policy_list = self.headerToPolicyAdder(policy_list)
            self.csvWriter(policy_list)

        def initialParse(self,
                         input_xml_file = None,
                         parse_dict = None,
                         num_of_rule_fields = None):
            input_xml_file = input_xml_file or self.input_xml_file
            parse_dict = parse_dict or self.parse_dict
            num_of_rule_fields = num_of_rule_fields or self.num_of_rule_fields
            initial_parse_list, rule_seq_dict = [], {}
            with open(input_xml_file, 'r') as hips_file:
                for this_entry in hips_file:
                    if this_entry.startswith(parse_dict['begin']):
                        single_entry = []
                        data_written = False
                    if this_entry.startswith(parse_dict['data_tag']):
                        single_entry = this_entry.split(
                            parse_dict['data_tag'])                       
                        single_entry = single_entry[1][:-4].split(',')
                        if (len(single_entry) > num_of_rule_fields):
                            single_entry = self.dataStringFixer(single_entry)
                        data_written = True
                    if (this_entry.startswith(parse_dict['Last_modified']) and
                    data_written == True):
                        fw_last_modified = this_entry.split(parse_dict['Last_modified'])
                        fw_last_modified = fw_last_modified[1][:10]
                        single_entry.append(fw_last_modified)
                    if (this_entry.startswith(parse_dict['rule_ID']) and
                        data_written == True):
                        rule_id = this_entry.split(parse_dict['rule_ID'])
                        single_entry.append(rule_id[1][:-4])
                    if (this_entry.startswith(parse_dict['end']) and
                        data_written == True):
                        initial_parse_list.append(single_entry)
                    if this_entry.startswith(parse_dict['rule_order']):
                        rule_set_dict = self.ruleSeqDictCreator(this_entry,
                                                                rule_seq_dict)
                return initial_parse_list, rule_seq_dict

        def dataStringFixer(self, data):
            x, max_loops = 0, len(data)
            while (x < max_loops):
                if ((data[x].startswith('&quot;') == True) and
                    (data[x].endswith('&quot;') == False)):
                    while(data[x].endswith('&quot;') == False):
                        data[x] = data[x] + ',' + data.pop(x+1)
                        max_loops =- 1
                x += 1
            return data

        def ruleSeqDictCreator(self, entry, rule_seq_dict):
            entry = entry.split('" value="')
            rule_sequence_num = entry[0].split('#')[1]
            rule_ID_num = entry[1][:-4]
            rule_seq_dict[rule_ID_num] = rule_sequence_num
            return rule_seq_dict

        def policyOrderer(self, running_list, rule_seq_dict):
            final_list = [''] * len(rule_seq_dict)
            for z in range(len(running_list)):
                key = running_list[z][-1]
                x = int(rule_seq_dict[key])
                final_list[x] = running_list[z]
            try:
                final_list.remove('')
            finally:
                return final_list

        def portFieldCombiner(self, single_line):
            if (single_line[0] == '0'):
                if (single_line[2] == '0'):
                    return 'Any'
                return single_line[2]
            if (single_line[0] == '1'):
                range_bldr = (single_line[2] + '-' + single_line[3])
                return range_bldr
            if (single_line[0] == '2'):
                if (single_line[1] == '2'):
                    multi_bldr = (single_line[2] + ', ' +
                                  single_line[3])
                if (single_line[1] == '3'):
                    multi_bldr = (single_line[2] + ', ' +
                                  single_line[3] + ', ' + single_line[4])
                if (single_line[1] =='4'):
                    multi_bldr = (single_line[2] + ', ' +
                                  single_line[3] + ', ' + single_line[4] +
                                  ', ' +single_line[5])
                return multi_bldr
            if (single_line[0] == '3'):
                return 'Any'

        def ipFieldFromHex(self, hex_field):
            ip_dict = {'0000:0000:0000:0000:0000:0000:0000:0000':'Any',
                       '[trusted]':'Trusted'}
            subnet_mask = ''
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
        
        def dataStringFormat(self, string):
            new_string = string.replace('&quot;', '')
            new_string = new_string.replace('&apos;', '\'')
            new_string = new_string.replace('&lt;--&gt;', '--')
            return new_string

        def dataFingerPrint(self, finger_print):
            if (finger_print == '0x00000000000000000000000000000000'):
                finger_print = ''
            return finger_print

        def policyFieldCleaner(self, running_list):
            cleaned_list = []
            for x in range(len(running_list)):
                single_line = []
                if(running_list[x]):
                    for y in range(6):
                        single_line.append(running_list[x].pop(0))
                    single_line.append(self.ipFieldFromHex(
                        running_list[x].pop(0)))
                    single_line.append(running_list[x].pop(0))
                    for y in range(2):                        
                        single_line.append(self.portFieldCombiner(
                            running_list[x][:6]))
                        running_list[x][:6] = []
                    for y in range(2):
                        single_line.append(self.dataStringFormat(
                            running_list[x].pop(0)))
                try:
                    single_line.append(self.dataFingerPrint(
                        running_list[x].pop(0)))
                except Exception:
                    single_line.append('')
                single_line += running_list[x]
                cleaned_list.append(single_line)
            return cleaned_list

        def groupRuleDivisionCreator(self,
                                     running_list,
                                     group_column = 14,
                                     name_column = 10):
            group_ender_list = [''] *len(running_list[-1])
            group_begin_list = group_ender_list
            x = 0
            while (x < len(running_list)):
                if(running_list[x] != [''] and
                   running_list[x-1] !=['']):
                    if ((running_list[x][group_column] != '2') and
                        (running_list[x-1][group_column] == '2')):
                        group_ender_list[name_column] = ('END GROUP: ' +
                                                         current_group)
                        running_list.insert(x, copy.deepcopy(group_ender_list))
                        x = x + 1
                    if (running_list[x][group_column] == '1'):
                        current_group = running_list[x][name_column]
                        running_list[x] = [''] *len(running_list[x-1])
                        running_list[x][name_column] = ('BEGIN GROUP: ' +
                                                        current_group)
                x = x + 1
            return running_list

        def valuesFromCleanerDictionary(self,
                                        running_list,
                                        cleaner_dict = None):
            cleaner_dict = cleaner_dict or self.cleaner_dict
            for x in range(len(running_list)):
                for y in range(len(running_list[x])):
                    if y in cleaner_dict:
                        for key in cleaner_dict[y]:
                            if (key == running_list[x][y]):
                                running_list[x][y] = cleaner_dict[y][key]
            for x in range(len(running_list)):
                if (running_list[x][0] == 'Disabled'):
                    running_list[x][1] = 'Disabled'
            return running_list

        def headerToPolicyAdder(self,
                                running_list,
                                header_on_off_key = None,
                                header_dict = None):
            header_on_off_key = header_on_off_key or self.header_on_off_key
            header_dict = header_dict or self.header_dict
            finished_list, header_list = [], []
            for x in range(len(running_list)):
                if x in header_dict:
                    if header_dict[x] in header_on_off_key:
                        if (header_on_off_key[header_dict[x]] == 'Y'):
                            header_list.append(header_dict[x])
            finished_list.append(header_list)
            
            for x in range(len(running_list)):
                single_line = []
                for y in range(len(running_list[x])):
                    if (y in header_dict):
                        if (header_dict[y] in header_on_off_key):
                            if (header_on_off_key[header_dict[y]] == 'Y'):
                                single_line.append(running_list[x][y])
                finished_list.append(single_line)
            return finished_list
                                                   
################################################################################
# END: Firewall Classes
################################################################################
#
################################################################################
# BEGIN: Application Blocking Classes
################################################################################
#
#
# IPS_AB_7000 child of HBSSMasterObject
class IPS_AB_7000(HBSSMasterObject):
    '''Object for IPS_7000 Application Blocking.  There is no IPS_8000
equivalent because Application Blocking has been moved into IPS policy for
HIPS 8.
'''
    def __init__(self, input_xml_file = None):
        '''The self.parse_dict is used to keep the control text necessary
to navigate through an Application Blocking XML file.
'''
        HBSSMasterObject.__init__(self, input_xml_file)
        self.PolicyType = "HOSTIPS_7000_AB"
        self.input_xml_file = input_xml_file
        self.output_csv_file = self.input_xml_file[:-4] + '_CSV.csv'
        self.parse_dict = {'begin':'<EPOPolicySettings',
                           'data_tag':'<Setting name="Data" value="',
                           'rule_ID':'<Setting name="RuleID" value="',
                           'ab_rule_name':'<Setting name="Name" value="',
                           'ab_note':'<Setting name="Note" value="',
                           'Last_modified':'<Setting name="LastModifyDate" value="',
                           'rule_order':'<Setting name="+RuleIDSequence#',
                           'end':'</EPOPolicySettings>'
                           }
        self.header_list = ['Rule Name', 'Process', 'Notes', 'Last Modified', 'Rule ID']

    def parseAndWriteToCSV(self):
        '''Common method found in all HBSS objects.
'''
        policy_list, rule_seq_dict = self.initialParse()
        policy_list = self.policyOrderer(policy_list, rule_seq_dict)
        policy_list.insert(0, self.header_list)
        self.csvWriter(policy_list)

    def initialParse(self,
                     input_xml_file = None,
                     parse_dict = None):
        '''Main function that takes first parse of XML file and creates list
to subsequently build appropriate output file.
'''
        input_xml_file = input_xml_file or self.input_xml_file
        parse_dict = parse_dict or self.parse_dict
        initial_parse_list, rule_seq_dict = [], {}
        with open(input_xml_file, 'r') as hips_file:
            for this_entry in hips_file:
                if this_entry.startswith(parse_dict['begin']):
                    single_entry = []
                    ab_path, ab_rule_name, ab_note, ab_last_modified = '', '', '', ''
                    data_written = False
                if this_entry.startswith(parse_dict['data_tag']):
                    ab_path = this_entry.split(parse_dict['data_tag'])
                    ab_path = ab_path[1][:-4].split(',')
                    ab_path = ab_path[3]
                    ab_path = self.dataStringFormat(ab_path)
                    data_written = True
                if (this_entry.startswith(parse_dict['rule_ID']) and
                    data_written == True):
                    rule_id = this_entry.split(parse_dict['rule_ID'])
                    rule_id = rule_id[1][:-4]
                if (this_entry.startswith(parse_dict['ab_rule_name']) and
                    data_written == True):
                    ab_rule_name = this_entry.split(parse_dict['ab_rule_name'])
                    ab_rule_name = ab_rule_name[1][:-4]
                    ab_rule_name = self.dataStringFormat(ab_rule_name)
                if (this_entry.startswith(parse_dict['Last_modified']) and
                    data_written == True):
                    ab_last_modified = this_entry.split(parse_dict['Last_modified'])
                    ab_last_modified = ab_last_modified[1][:10]
                    ab_last_modified = self.dataStringFormat(ab_last_modified)
                if (this_entry.startswith(parse_dict['ab_note']) and
                    data_written == True):
                    ab_note = this_entry.split(parse_dict['ab_note'])
                    ab_note = ab_note[1][:-4]
                if (this_entry.startswith(parse_dict['end']) and
                    data_written == True):
                    single_entry.append(ab_rule_name)
                    single_entry.append(ab_path)
                    single_entry.append(ab_note)
                    single_entry.append(ab_last_modified)
                    single_entry.append(rule_id)
                    initial_parse_list.append(single_entry)
                if this_entry.startswith(parse_dict['rule_order']):
                    rule_set_dict = self.ruleSeqDictCreator(this_entry,
                                                            rule_seq_dict)
            return initial_parse_list, rule_seq_dict

    def ruleSeqDictCreator(self, entry, rule_seq_dict):
        '''Builds the rules sequence dictionary.
'''
        entry = entry.split('" value="')
        rule_sequence_num = entry[0].split('#')[1]
        rule_ID_num = entry[1][:-4]
        rule_seq_dict[rule_ID_num] = rule_sequence_num
        return rule_seq_dict
    
    def dataStringFormat(self, string):
        '''Cleans up strings for final human-readable presentation.
'''
        new_string = string.replace('&quot;', '')
        new_string = new_string.replace('&apos;', '\'')
        return new_string
        
    def policyOrderer(self, running_list, rule_seq_dict):
        '''Places policy in order based on the sequencing dictionary.
'''
        highest_ruleID = 0
        for rule in range(len(running_list)):
            if (int(running_list[rule][-1]) > highest_ruleID):
                highest_ruleID = int(running_list[rule][-1])
        final_list = [''] * highest_ruleID
        for z in range(len(running_list)):
            key = running_list[z][-1]
            x = int(rule_seq_dict[key])
            final_list[x] = running_list[z]
        try:
            final_list.remove('')
        finally:
            return final_list
                        
    def csvWriter(self, final_list, output_csv_file = None):
        '''Writes output to CSV file.
'''
        output_csv_file = output_csv_file or self.output_csv_file
        with open(output_csv_file, 'w', newline = '') as output_file:
            hips_writer = csv.writer(output_file, delimiter = ',')
            for each_row in final_list:
                hips_writer.writerow(each_row)
                
################################################################################
# END: Firewall Classes
################################################################################
#
#
#
################################################################################
# END: CLASS DECLARATION
################################################################################


################################################################################
# BEGIN: Changelog
################################################################################
#   v0.200 -    CND-A adopted the script.  Fixed logic error where multi-value  
#               of signature IDs and paths could not be displayed.  Missing IPS 
#               exceptions is also fixed.
#               Added minor changes to the HIPS 7 output fields.
#               New function added to handle HIPS 8 IPS policies.  
#               ....
#   v0.114 -    No longer parses IPD entries with CreatorID == McAfee.
#   v0.113 -    Included minor use of Try/Except blocks.
#   v0.112 -    Documented Application Blocking object, modified policy orderer
#               to create list with a number of elements equal rule location of
#               highest rule.
#   v0.111 -    Fixed logic error where Transport Port could be incorrectly
#               parsed by single digit dictionary keys.
#   v0.110 -    Added IPS_AB_7000 class to support Application Blocking module
#               included in HIPS 7 product.  Also included string literal
#               replacement of &apos; with \'
#   v0.109 -    Placed limitation on how deeply it would parse XML file to
#               determine if it was a supported product.  Current limitation is
#               20 lines.
#   v0.108 -    Firewall classes rebuilt to better, more efficiently parse
#               and model firewall data than initial prototype.
#   v0.107 -    Modified Firewall class to parse both port ranges, and
#               individual ports listed up to the maximum supported length of
#               four.
#   v0.106 -    Firewall class modified to reorder rules based on RuleID value.
#   v0.105 -    Added DocStrings, and added additional definitions to Firewall
#               Object dictionary.
#   v0.104 -    HIPS_7000 updated with full dictionary of IPS parameters and
#               IPS_FW_7000 updated with additional header definitions.
#   v0.103 -    HBSSXMLParser class added to handle lists of HBSS objects
#               to parse through and write appropriate output.  Currently,
#               supported output is CSV.
#   v0.102 -    IPS and FW classes have been colocated into single HBSS Class
#               file to simplify maintenance and version control.
#   v0.101 -    HIPS_7000 and HIPS_8000 classes added to extend the core IPS
#               class and add product specific entries to the dictionary.
#   v0.100 -    Redraft/Redsign of initial scripted Prototype into framework for
#               a more modular application design.
################################################################################
# END: Changelog
################################################################################

