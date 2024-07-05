from django.shortcuts import render , redirect , HttpResponseRedirect
from django.http import HttpResponse
from django.contrib import messages
from django.contrib.auth import authenticate, login

from Comunication_LTD.settings import BASE_DIR
from .form import LoginForm , RegisterForm , CustomerForm , SearchForm , ForgetPasswordForm , SettingForm , SettingAdminForm
from django.db import connection
from django.contrib.auth.hashers import make_password
from .models import User , HistoryPassword
from .password import CheckPasswordIsOk ,sendEmailVerifiction
import ast
import datetime
import json
import html



#Action For Register Method
def Register(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            print("Trying Register...")
            lastname = form.cleaned_data['lastname']
            firstname = form.cleaned_data['firstname']
            birthday = form.cleaned_data['birthday']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            confirmpassword = form.cleaned_data['confirmpassword']
            try:
                # Check if Costumer is all ready exist
                SqlQuery = """SELECT email FROM app_user WHERE email = %s"""
                with connection.cursor() as cursor:
                    cursor.execute(SqlQuery, [email])
                    results = cursor.fetchall()
                    if len(results) == 1:
                        raise Exception("This User is all ready exist")
                    
                if confirmpassword != password:
                    raise Exception("There is no match between Password and confirmpassword")
                
                checkPassword = CheckPasswordIsOk(password , None)
                if checkPassword is not None:
                    raise Exception(checkPassword)
                
                # Define the SQL INSERT statement
                current_datetime = datetime.datetime.now()
                date_join = current_datetime.strftime('%Y-%m-%d %H:%M:%S') 
                #birthday = birthday.strftime('%Y-%m-%d %H:%M:%S')
                hashed_password = make_password(password, salt=None, hasher='pbkdf2_sha256') #Its make Random salt

                SqlQuery_1 = """INSERT INTO app_user (firstname, lastname, birthday, email, password , is_superuser , is_active ,is_staff ,date_joined) 
                        VALUES (%s, %s, %s, %s, %s , %s ,%s , %s , %s)"""
                values_1 = (firstname, lastname, birthday , email, hashed_password, False , True , False , date_join)
                
                SqlQuery_2 = """INSERT INTO app_historypassword  (user_id, password, date_insert) 
                        VALUES (%s, %s, %s)"""
                # Execute the SQL statement
                with connection.cursor() as cursor:
                    cursor.execute(SqlQuery_1, values_1)
                    userid = cursor.lastrowid
                    values_2 = (userid, hashed_password, date_join)
                    cursor.execute(SqlQuery_2, values_2)
                print("""Add New User \n----------------------""")
                return HttpResponseRedirect('/login')  # Redirect to the same page after successful addition
            except Exception as error:
                # Handle other exceptions
                print(f""" An error occurred: {error} \n-------------------""")
                messages.error(request,error)
                context = {'form' : form ,  'Error' : error}
                return render(request, 'user.html', context) # Redirect to the same page after error           
        else:
            error = "Your Values in InValid"
            print(f"{error}\n---------")
            context = {'form' : form , 'Error' : error}
            return render(request, 'user.html', context)                      
    elif request.method == "GET":
        form = RegisterForm()
        context = {'form' : form ,'Error' : None}
        print("Building Empty Register Form..")
        return render(request, 'user.html', context)
    else:
         return render(request, '404.html')


#Action For login Method
def Login(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        path = BASE_DIR/'static'/'config.txt'
        if form.is_valid():            
            print("---------------")
            print("Trying Login...")
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = authenticate(request, email=email, password=password)
            if user is not None:
                login(request, user)
                print('       Successfully logged in!     ')
                print(f'       Wellcome  {email}         ')
                print(f'---------------------------------')
                print(user.id)
                request.session['user_id'] = user.id
                print(User.objects.get(id=user.id).firstname)
                
                request.session['user_name'] = User.objects.get(id=user.id).firstname
                request.session['user_IsAdmin'] = User.objects.get(id=user.id).is_superuser
                request.session['login_attempts'] = 0
                
                return HttpResponseRedirect('/Communication_LTD/Customer')  # Redirect to a success page.
            else:
                request.session.setdefault('login_attempts', 0)
                request.session['login_attempts'] += 1   
                try:
                    with open(path, 'r+') as file:
                    # Read the entire contents of the file
                        config_text = file.read()
                        initialdata = json.loads(config_text)
                        file.close()
                        
                    if(request.session['login_attempts'] >= int(initialdata['attempt'])):
                        SqlQuery = f"UPDATE app_user SET is_active = False WHERE email = {email}"
                        print(SqlQuery)
                        with connection.cursor() as cursor:
                            cursor.execute(SqlQuery)
                        request.session.flush()
                        raise Exception("You are using SQLite3, You over you attempts - user is lock")

                    error = "   Invalid Email or password."
                    context = {'form' : form , 'Type' : 'Login' , 'Error' : error}
                    return render(request, 'user.html', context)
                except Exception as error:
                    context = {'form' : form , 'Type' : 'Login' , 'Error' : error}
                    return render(request, 'user.html', context)
              
    elif request.method == "GET":
        form = LoginForm()
        context = {'form' : form , 'Type' : 'Login' , 'Error' : None}
        print("------------\nBuilding Login form..\n--------")
        return render(request , "user.html" , context)
    else:
        return render(request , "404.html")


#Action For Communication_LTD Method
def Search(request):
    if request.session.get('user_id'):
        form = SearchForm(request.GET or None)
        print("------------------\n    Searching...")
        if form.is_valid():
            #Cleaning Data After do Action
            typeSearch = html.escape(str(form.cleaned_data['type']))
            text = str(form.cleaned_data['text'])
            
            try:
                # Check if Costumer is all ready exist
                SqlQuery = f"SELECT firstname || ' ' || lastname AS fullname, email, city, job FROM app_customer WHERE {typeSearch} LIKE '%{text}%'"
                print(f"    Try Searching by {typeSearch} which contain {text}\n----------------")
                with connection.cursor() as cursor:
                    cursor.execute(SqlQuery)
                    results = cursor.fetchall()
                if len(results) < 1:
                    raise Exception("No Found Nothing")
                context = {'form' : form , 'Type' : 'User', 'results' : results ,'name': request.session['user_name']}
                return render(request, 'search.html', context)

            except Exception as error:
                # Handle other exceptions
                print(f"""   An error occurred: {error} \n-------------------""")
                context = {'form' : form , 'Type' : 'User', "Error" : error , 'name': request.session['user_name']}
                messages.error(request,error)
                return render(request, 'search.html', context) # Redirect to the same page after error   
        else:
            form = SearchForm()
            context = {'form' : form , 'Type' : 'User' ,'Error' : None , 'results' : None , 'name': request.session['user_name']}
            print("Building Communication_LTD Page..")
            return render(request, 'search.html', context)
    else:
        return render(request, '404.html')


def Customer(request):
    print("sad")
    print(request.session.get('user_id'))
    if request.session.get('user_id'):
        if request.method == 'POST':
            form = CustomerForm(request.POST)
            print("-----------------------\n   Trying Add New Costumers")
            if form.is_valid():
                firstname =form.cleaned_data['firstname']
                lastname = form.cleaned_data['lastname']
                birthday = form.cleaned_data['birthday']
                phone = form.cleaned_data['phone']
                email = form.cleaned_data['email']
                city = form.cleaned_data['city']
                street = form.cleaned_data['street']
                job = form.cleaned_data['job']

                try:    
                    # Check if Costumer is all ready exist
                    SqlQuery = """SELECT email FROM app_customer WHERE email = %s"""
                    with connection.cursor() as cursor:
                        cursor.execute(SqlQuery, [email])
                        results = cursor.fetchall()
                    if len(results) == 1:
                            raise Exception("This Customer is all ready exist")
                
                    # Define the SQL INSERT statement
                    current_datetime = datetime.datetime.now()
                    formatted_datetime = current_datetime.strftime('%Y-%m-%d %H:%M:%S')
                    SqlQuery = """INSERT INTO app_customer (firstname, lastname, birthday, phone, email, city , street , job ,date_join) 
                            VALUES (%s, %s, %s, %s, %s, %s , %s , %s , %s)"""
                    # Define the values to insert
                    values = (firstname, lastname, birthday , phone, email, city , street , job , formatted_datetime)

                    # Execute the SQL statement
                    with connection.cursor() as cursor:
                        cursor.execute(SqlQuery, values)
                    print("Add New Customer \n----------------------")
                    form = CustomerForm()
                    context = {'form' : form , 'Type' : 'User' , "Error" : None , 'message_success': f"Add {firstname} {lastname}" ,'name': request.session['user_name']}
                    return render(request, 'user.html', context)
            
                except Exception as error:
                    # Handle other exceptions
                    print(f"""   An error occurred: {error} \n-------------------""")
                    context = {'form' : form , 'Type' : 'User' , 'Error' : error}
                    messages.error(request,error)
                    return render(request, 'user.html', context) # Redirect to the same page after error           
            else:
                print("   Your Values in InValid\n------------")
                error = "Your Values in InValid"
                context = {'form' : form , 'Type' : 'User' , "Error" : error}
                return render(request, 'user.html', context)
        else:
            form = CustomerForm()
            context = {'form' : form , 'Type' : 'User' , 'Error' : None, 'message_success': None,  'name': request.session['user_name']}
            print("Building Communication_LTD/Customer Page..")
            return render(request, 'user.html', context)
    else:
        return render(request, '404.html')
    
def Setting(request):
    path = BASE_DIR/'static'/'config.txt'
    if request.session.get('user_id'):
        if request.method == 'POST':
            form = None
            if request.session['user_IsAdmin']:
                print("------------------\n    Setting Admin...")
                form = SettingAdminForm(request.POST)
            else:
                print("------------------\n    Setting User...")
                form = SettingForm(request.POST)

            if form.is_valid():
                try:
                    #Cleaning Data After do Action
                    password = html.escape(str(form.cleaned_data['password']))
                    confirmpassword =  html.escape(str(form.cleaned_data['confirmpassword']))

        
                    if request.session['user_IsAdmin']:
                        lenght_min = html.escape(str(form.cleaned_data['lenght_min']))
                        lenght_max = html.escape(str(form.cleaned_data['lenght_max']))
                        contain = form.cleaned_data['contain']
                        attempt = html.escape(str(form.cleaned_data['attempt']))
                        forbidden = form.cleaned_data['forbidden']
                        history = html.escape(str(form.cleaned_data['history']))
                        
                        if int(history) < 1 or int(lenght_max)<int(lenght_min) or int(lenght_min)<0:
                            raise Exception("Your number is not logic")
                        try:
                        
                            contain = ast.literal_eval(contain) # -->convert to list
                            forbidden = ast.literal_eval(forbidden) # -->convert to list
                            for i in range(len(contain)):
                                if isinstance(contain[i] , str) == False:
                                    raise Exception("it is not in a string value")
                                else:
                                    contain[i] = contain[i].replace("'",'').replace('"','')
                            for i in range(len(forbidden)):
                                if isinstance(forbidden[i] , str) == False:
                                    raise Exception("it is not in a string value")
                                else:
                                    forbidden[i] = forbidden[i].replace("'",'').replace('"','')
                            form.contain = contain
                            form.forbidden = forbidden
                        
                            config_info = {"lenght_min": lenght_min ,"lenght_max": lenght_max , "contain": contain ,"attempt": attempt ,"forbidden": forbidden, "history": history }
                            with open(path , "w") as file:
                                upadted_config = json.dumps(config_info, indent=4) #indent => 4 spaces ' ' - more readable
                                file.write(upadted_config)
                                file.close()     
                        except:
                            raise Exception("You are not in the correct format of config")
                        
                        
                    #--->Check password for user
                    if confirmpassword != password:
                        raise Exception("There is no match between Password and confirmpassword")
                    
                    hashed_password = make_password(password, salt=None, hasher='pbkdf2_sha256') #Its make Random salt
                    userId = request.session["user_id"]
                    
                    if request.session['user_IsAdmin'] and password != "" or request.session['user_IsAdmin'] == False:
                        checkPassword = CheckPasswordIsOk(password , userId)
                        if checkPassword is not None:  
                            raise Exception(checkPassword)
                        
                    # Check if Costumer is all ready exist
                    print(" Trying to upadte the info")
                    SqlQuery_1 = "UPDATE app_user SET password = %s WHERE id = %s"
                    SqlQuery_2 = """INSERT INTO app_historypassword (user_id, password  ,date_insert) 
                        VALUES (%s , %s , %s)"""
                    with connection.cursor() as cursor:
                        cursor.execute(SqlQuery_1, [hashed_password, userId])
                        cursor.execute(SqlQuery_2, [userId ,hashed_password , datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
                    
                    print(" Succseful upadte\n----------")
                    messages.success(request, "Succseful upadted setting of user")
                    context = {'form' : form , 'Type' : 'User' , "Error" : None ,'message_success': 'Succseful upadte' ,'name': request.session['user_name'] }
                    return render(request, 'setting.html', context)

                except Exception as error:
                    # Handle other exceptions
                    print(f"""   An error occurred: {error} \n-------------------""")
                    messages.error(request,error)
                    context = {'form' : form , 'Type' : 'User' , 'Error' : error}
                    return render(request, 'setting.html', context) # Redirect to the same page after error   
            else:
                error = "Your Values in InValid"
                context = {'form' : form , 'Type' : 'User' , 'name': request.session['user_name'] , 'Error' : error}
                print("Building Setting Page..\n---------")
                return render(request, 'setting.html', context)
        else:
            if request.session['user_IsAdmin']:
                with open(path, 'r+') as file:
                    # Read the entire contents of the file
                    config_text = file.read()
                    initialdata = json.loads(config_text)
                    file.close()
                form = SettingAdminForm(initial=initialdata)
            else:
                form = SettingForm()
            context = {'form' : form , 'Type' : 'User' , 'Error' : None, 'message_success': None ,'name': request.session['user_name']}
            print("Building Setting Page..")
            return render(request, 'setting.html', context)
    else:
        return render(request, '404.html')



def ForgetPassword(request):
    if request.method == 'POST':
        form = ForgetPasswordForm(request.POST)
        
        if form.is_valid():
            email = html.escape(str(form.cleaned_data['email']))
            password = html.escape(str(form.cleaned_data['password']))
            code = html.escape(str(form.cleaned_data['code']))
            
            try:
                if(request.session["code"] != None):
                    print(request.session["code"])
                    print(code)
                    if str(request.session["code"]) != str(code):
                        raise Exception("Your Code Is not Correct")
                    
                    
                    checkPassword = CheckPasswordIsOk(password , None)
                    if checkPassword is not None:
                        raise Exception(checkPassword)
                    
                    hashed_password = make_password(password, salt=None, hasher='pbkdf2_sha256') #Its make Random salt

            
                    print(" Trying to upadte the info")
                    SqlQuery = "UPDATE app_user SET password = %s WHERE email = %s"
                    with connection.cursor() as cursor:
                        cursor.execute(SqlQuery, [hashed_password, email])
                    
                    print("Make reset all passowrd of this user")
                    user_t = User.objects.get(email = email)
                    collectionHistory = HistoryPassword.objects.filter(user = user_t)
                    for historypassword in collectionHistory:
                        historypassword.delete()

                        
                    print(" Succseful upadte\n----------")
                    request.session.flush()
                    messages.success(request, "Succseful upadted setting of user")
                    return HttpResponseRedirect('/login')
                else:
                    print("Sending to your mail code..")
                    code = sendEmailVerifiction(email)
                    request.session["code"] = code
                    context = {'form' : form , 'Type' : "Code" , 'Error' : None, 'message_success': None }
                    print("Building ForgetPassword Page..")
                    return render(request, 'forgetpassword.html', context)
            except Exception as error:
                context = {'form' : form , 'Type' : "Code" , 'Error' : error, 'message_success': None}
                print("Building ForgetPassword Page..")
                return render(request, 'forgetpassword.html', context)
        else:   
            context = {'form' : form , 'Type' : "Code" , 'Error' : None, 'message_success': None}
            return render(request, 'forgetpassword.html', context)   
    else:
        form = ForgetPasswordForm()
        request.session["code"] = None
        context = {'form' : form , 'Type' : None , 'Error' : None, 'message_success': None}
        print("Building ForgetPassword Page..")
        return render(request, 'forgetpassword.html', context)


def Logout(request):
    request.session.flush()
    return HttpResponseRedirect("/login")

#Action For Communication_LTD Method
def Hello_World(request):
     return HttpResponse("Hello World")
 
def view_404(request):
     return render(request, '404.html')
 
