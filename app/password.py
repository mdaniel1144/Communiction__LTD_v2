from Comunication_LTD.settings import BASE_DIR
from django.core.mail import send_mail
from django.contrib.auth.hashers import check_password
from .models import HistoryPassword , User
import random
import json
import hashlib
import re

path = BASE_DIR/'static'/'config.txt'


#If Retrun None => it OK
def CheckPasswordIsOk(password , userid):
    
    config_info ={}
    check = None
    try:
        with open(path, 'r+') as file:
            # Read the entire contents of the file
            config_text = file.read()
            config_info = json.loads(config_text)
            file.close()
        
        if( int(config_info['lenght_min']) >  len(password) or len(password) > int(config_info['lenght_max'])):
            raise Exception("Password is not in the correct lenght")

        for x in config_info['contain']:
            pattern = '['+x+']'
            if(re.search(pattern, password) == None):
                raise Exception(f"Password is not contain the correct letters: {x}")

        if password in config_info['forbidden']:
            raise Exception("Password is weak")
        
        if userid != None:
            checkHistory(int(config_info['history']), userid , password)

    except Exception as error:
        check = error
    
    return check
        
        


def BuildPattern(template):
    
    pattern = '^'
    
    for x in template:
        pattern += "(?=.+["+x+"])"
    pattern +='$'
    return pattern

def checkHistory(history , userId , password):
    
    user_t = User.objects.get(id=userId)
    collectionHistory = HistoryPassword.objects.filter(user = user_t)
                        
    for historypassword in collectionHistory:
        if check_password(password ,historypassword.password):      #--> this is decode from hashing password
            raise Exception("Its your old password") 
                        
        if len(collectionHistory) > history:
            collectionHistory.order_by('-date_insert').first().delete()



def sendEmailVerifiction(email):
    subject = 'Subject of the Email'
    message = 'This is the body of the email.'
    from_email = "Communication_LTD@domain.com"  # This can be omitted to use DEFAULT_FROM_EMAIL
    recipient_list = [email]
    
    code =  ''.join(random.choices('0123456789', k=6))
    
    # Convert the code to bytes (UTF-8 encoding)
    code_bytes = code.encode('utf-8')
    sha1_hash = hashlib.sha1()
    sha1_hash.update(code_bytes)
    code_with_SAH_1 = sha1_hash.hexdigest()
    
    message = f"Hi {email} ,\n\nthis is you code reset:\n\n{code_with_SAH_1}"
    
    try:
        print("sad assad ")
        send_mail(subject, message, from_email, recipient_list)
        return code_with_SAH_1
    except Exception as e:
        raise Exception(e)