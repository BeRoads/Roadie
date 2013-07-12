from APNSWrapper import *
import binascii

t = "E19 Bxl/Bsl > Mons-Valenciennes(F) # A54 (E420) Nivelles > Charleroi a Arquennes" 
lio = '1ca6cb0daf757a87b60dccb9104a7855952573000c0e34ad4ddee94aa2967ed3'
quentin = '6ec924310e1fe65573c83b7fe08a7de398cc282fd9c7ccf88528b0945cdad42f'
deviceToken = binascii.unhexlify(quentin);
wrapper = APNSNotificationWrapper('beroads.pem', True)
message = APNSNotification()
message.token(deviceToken)
message.alert(t[0:219])
message.badge(5)
message.sound()
wrapper.append(message)
wrapper.notify()
