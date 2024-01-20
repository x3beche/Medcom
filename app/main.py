from flask import Flask
from flask_mail import Mail
from flask_executor import Executor
import pymongo
import yaml

# loading configurations
with open('config.yaml') as file: sv = yaml.load(file, Loader=yaml.FullLoader)

member_level = sv['member_level']
community_level = sv['community_level']
supervisor_level = sv['supervisor_level']
admin_level = sv['admin_level']

version = sv['version']
domain = sv['domain']

app = Flask(__name__)
app.secret_key = sv['secret_key']
executor = Executor(app)

# mail
app.config['MAIL_SERVER'] = sv['mail_server']
app.config['MAIL_PORT'] = sv['mail_port']
app.config['MAIL_USE_TLS'] = sv['mail_tls_status']
app.config['MAIL_USERNAME'] = sv['mail_username']
app.config['MAIL_PASSWORD'] = sv['mail_password']
mail = Mail(app)

# database
client = pymongo.MongoClient(sv['mongodb'])
db = client.user_login_system

from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from passlib.hash import pbkdf2_sha512
from pandas import DataFrame
from flask import jsonify, request, session, redirect, render_template, url_for
from flask_mail import Message
from time import time, mktime, ctime
import uuid, datetime

class User:

    # user agent
    def log_event(self, user_id, event = None):
        try:
            add_to_log = { "ip" : request.remote_addr, "user_agent":request.user_agent.string, "date" : int(time()) }
            if event: add_to_log.update({ "event": event})
            log = db.users.find_one({ "_id": user_id })
            log['log'].append(add_to_log)
            db.users.update_one({'_id': user_id}, {"$set": log}, upsert=False)
        except:
            session.clear()
            return redirect('/login')
    def start_session(self, user):
        del user['password']
        session['level'] = user['level']
        session['logged_in'] = True
        session['user'] = user
        return jsonify({"info": "Login Success"})
    def signup(self):
        if request.form.get('pass1') != request.form.get('pass2'):
            return jsonify({ "error": "Passwords not match."}), 400
        
        user = {
            "_id": uuid.uuid4().hex,
            "status": "active",
            "first_name": request.form.get('first_name').title(),
            "last_name": request.form.get('last_name').title(),
            "email": request.form.get('email').lower(),
            "password": request.form.get('pass1'),
            "verification": False,
            "level": 0,
            "registration_date" : int(time()),
            "last_login" : 0,
            "note": "There are no notes about this user.",
            "log": []
        }

        user["password"] = pbkdf2_sha512.encrypt(user['password'])
        
        if db.users.find_one({"email": user['email']}): 
            return jsonify({ "error": "Email already in use."}), 400
        if db.users.insert_one(user): 
            send_email_verification(user)
            self.log_event(user['_id'], event = "signup")
            return jsonify({ "info": "We sent you a confirmation mail 🚀, please check it before logging in."})
        return jsonify({ "error": "Signup Failed"}), 400
    def signout(self):
        self.log_event(session['user']['_id'], event = "signout")
        session.clear()
        return redirect('/login')
    def login(self):
        user = db.users.find_one({ "email": request.form.get('email') })
        if user and pbkdf2_sha512.verify(request.form.get('password'), user['password']):
            if not user['verification']: return jsonify({ "error": "Please confirm your account with the e-mail we sent to you."}), 401
            if user['status'] == "active": pass
            elif user['status'] == "suspend": return jsonify({ "error": "Your account has been suspended, contact MEDCOM for more information."}), 401
            elif user['status'] == "deleted": return jsonify({ "error": "Your account has been deleted, contact MEDCOM for more information."}), 401
            user['last_login'] = int(time())
            db.users.update_one({'_id':user["_id"]}, {"$set": user}, upsert=False)
            self.log_event(user['_id'], event = "login")
            return self.start_session(user)
        if user: 
            self.log_event(user['_id'], event = "invaild_login_attemp")
            return jsonify({ "error": "Email and password do not match."}), 401
        else: return jsonify({ "error": "Email and password do not match."}), 401
    def reset(self):   
        user = db.users.find_one({
            "email": request.form.get('email')
        })

        if user:
            send_change_pass(user)
            return jsonify({ "info": "We have sent an e-mail to reset your password."}), 200
        return jsonify({ "error": "We could not find a registered user for this email."}), 400
    def change_password(self, token):
        user_id = Serializer(app.secret_key).loads(token)["user_id"]
        user = db.users.find_one({ "_id": user_id })
        if request.form.get('pass1') == request.form.get('pass2'):
            user['password'] = pbkdf2_sha512.encrypt(request.form.get('pass1'))
            db.users.update_one({'_id':user_id}, {"$set": user}, upsert=False)
            if user['verification']: self.start_session(user)
            return jsonify({ "info": "Password changed successfully."}), 200
        else:
            return jsonify({ "error": "Passwords not match."}), 400
    def email_verification(self, token):
        try :
            email = URLSafeTimedSerializer(app.secret_key).loads(token, salt="email-verification", max_age=30*24*60*60)
            user = db.users.find_one({"email": email})
            if user["verification"] == False:
                user["verification"] = True
                db.users.update_one({'_id':user["_id"]}, {"$set": user}, upsert=False)
                self.start_session(user)
                return alert_page("Your email has been successfully verified, we direct you to the home page.", url_for('home'))
            else:
                if session: 
                    return alert_page("Your email has already been verified, we direct you to the home.", url_for('home'))
                return alert_page("Your email has been verified, you can continue by logging in from the main page, we direct you to the login page.", url_for('login'))
        except SignatureExpired: return alert_page("Your email verification link has expired, contact medcom to fix the problem.", url_for('home'))
        except: return alert_page("You're swimming in the wrong oceans. Please don't do such things again. Honeypot triggered.", url_for('home'))

    # admin
    def get_users(page):
        users = db.users.find()
        users_dataframe = DataFrame(list(users)).sort_values('first_name')
        members = users_dataframe[users_dataframe['level'] == 0]
        members_list = members.values.tolist()[((page-1)*5):((page)*5)]
        communities = users_dataframe[users_dataframe['level'] == 1]
        communities_list = communities.values.tolist()[((page-1)*5):((page)*5)]
        supervisors = users_dataframe[users_dataframe['level'] == 2]
        supervisors_list = supervisors.values.tolist()[((page-1)*5):((page)*5)]
        administrators = users_dataframe[users_dataframe['level'] == 3]
        administrators_list = administrators.values.tolist()[((page-1)*5):((page)*5)]
        return render_template("dashboard_admin_user.html", members_list=members_list, 
                                                            communities_list = communities_list, 
                                                            supervisors_list = supervisors_list, 
                                                            administrators_list = administrators_list,
                                                            next = page + 1,
                                                            prev = ((page - 1) if page > 1 else 1))
    def find_user():
        data = request.form.get('data')
        if data.count("@"):
            user = db.users.find_one({ "email": data })
            if user: return jsonify({"info": "Match found, you are redirected to user's page.", "redirect":user["_id"], "user": user}), 200
        else: 
            user = db.users.find_one({ "_id": data })
            if user: return jsonify({"info": "Match found, you are redirected to user's page.", "redirect":user["_id"], "user": user}), 200
        return jsonify({"error": "No matches were found."}), 400
    def user_info(user_id):
        user = db.users.find_one({ "_id": user_id })
        if user:
            user['_id'] = user['_id'][:17] + "..."
            if user['level'] == 0: user['level'] = "Member"
            elif user['level'] == 1: user['level'] = "Community"
            elif user['level'] == 2: user['level'] = "Supervisor"
            elif user['level'] == 3: user['level'] = "Admin"
            del user['password']
            return render_template('user_info.html', user=user)
        return redirect("/dashboard/users/1")
    def operate_user(user_id):

        user_id = user_id.replace("@", "")
        user = db.users.find_one({ "_id": user_id })
        operation = request.form.get("operation")
        print(operation)

        if operation == "set_role_member":
            user['level'] = 0
            db.users.update_one({'_id':user_id}, {"$set": user}, upsert=False)
        elif operation == "set_role_community": 
            user['level'] = 1
            db.users.update_one({'_id':user_id}, {"$set": user}, upsert=False)
        elif operation == "set_role_supervisor": 
            user['level'] = 2
            db.users.update_one({'_id':user_id}, {"$set": user}, upsert=False)
        elif operation == "set_role_admin": 
            user['level'] = 3
            db.users.update_one({'_id':user_id}, {"$set": user}, upsert=False)
            
        elif operation == "send_email_verification": send_email_verification(user)
        elif operation == "send_password_request": send_change_pass(user)
        elif operation == "verify_mail": 
            user['verification'] = True
            db.users.update_one({'_id':user_id}, {"$set": user}, upsert=False)
        elif operation == "change_note":
            user['note'] = request.form.get('note')
            db.users.update_one({'_id':user_id}, {"$set": user}, upsert=False)
        elif operation == "activate_user":
            user['status'] = "active"
            db.users.update_one({'_id':user_id}, {"$set": user}, upsert=False)
        elif operation == "suspend_user":
            user['status'] = "suspend"
            db.users.update_one({'_id':user_id}, {"$set": user}, upsert=False)
        elif operation == "delete_user":
            user['status'] = "deleted"
            db.users.update_one({'_id':user_id}, {"$set": user}, upsert=False)
        else: return jsonify({"error": "Error"}), 400
        
        return jsonify({"info": "Success"})
    def community_manager(community_id = None):
        user = get_user(session['user']['_id'])
        user_level = user['level']
        if community_id: community = get_community(community_id)
        operation = request.form.get('operation')
        if operation:
            if user_level == admin_level:
                if operation == "create_community":
                    user = db.users.find_one({"email": request.form.get('email')})
                    community_name = request.form.get('name')
                    if not user: return jsonify({'error': "User don't exist."}), 400
                    if create_community(user, community_name): return jsonify({'info': 'Community Created'})
                    else: return jsonify({'error': "Error while creating community."}), 400
                elif operation == "set_community_manager":
                    user = db.users.find_one({"email": request.form.get('email')})
                    community = db.communities.find_one({'_id':request.form.get("_id")})
                    if not user: return jsonify({'error': "User don't exist."}), 400
                    if not community: return jsonify({'error': "Community doesn't exist."}), 400
                    if make_community_admin(user, community): return jsonify({'info': "Authorized"})
                    else: return jsonify({'error': "Already authorized."}), 400
                elif operation == "edit_community":
                    return community_edit(community, user)
                elif operation == "close_registrations":
                    community['registration_status'] = False
                    db.communities.update_one({'_id':community['_id']}, {"$set": community}, upsert=False)
                    print('closed')
                    return jsonify({'info': 'Changed'})
                elif operation == "open_registrations":
                    community['registration_status'] = True
                    db.communities.update_one({'_id':community['_id']}, {"$set": community}, upsert=False)
                    print('opened')
                    return jsonify({'info': 'Changed'})
                elif operation == "activate_community":
                    community['status'] = "requested"
                    db.communities.update_one({'_id':community['_id']}, {"$set": community}, upsert=False)
                    return jsonify({'info': 'Changed'})
                elif operation == "archive_community":
                    community['status'] = "approved"
                    db.communities.update_one({'_id':community['_id']}, {"$set": community}, upsert=False)
                    return jsonify({'info': 'Changed'})
                else: return jsonify({'error': "Operation Error."}), 400
            elif community_manager_auth(community, user):
                if operation == 'edit_community':
                    return community_edit(community, user)
                elif operation == "close_registrations":
                    community['registration_status'] = False
                    db.communities.update_one({'_id':community['_id']}, {"$set": community}, upsert=False)
                    print('closed')
                    return jsonify({'info': 'Changed'})
                elif operation == "open_registrations":
                    community['registration_status'] = True
                    db.communities.update_one({'_id':community['_id']}, {"$set": community}, upsert=False)
                    return jsonify({'info': 'Changed'})
                elif operation == "activate_community":
                    community['status'] = "requested"
                    db.communities.update_one({'_id':community['_id']}, {"$set": community}, upsert=False)
                    return jsonify({'info': 'Changed'})
                elif operation == "archive_community":
                    community['status'] = "archived"
                    db.communities.update_one({'_id':community['_id']}, {"$set": community}, upsert=False)
                    return jsonify({'info': 'Changed'})
                else: return jsonify({'error': "Operation Error."}), 400
            elif user_level == supervisor_level:
                if operation == "approve_community":
                    return community_edit(community, user, 'approved')
                elif operation == "decline_community":
                    return community_edit(community, user, 'declined')
                else: return jsonify({'error': "Operation Error."}), 400
            else: return jsonify({'error': "Authentication Error."}), 400
        else: return jsonify({'error':'authentication_error'})
    def community_lister():
        try: 
            communities = db.communities.find()
            communities_dataframe = DataFrame(list(communities)).sort_values('name')
            communities_list = communities_dataframe.values.tolist()
            return communities_list
        except: return []
    def community_user_remove(community_id, user_id):
        print(request.base_url)
        print('test test test')
        community = db.communities.find_one(community_id)
        user = db.users.find_one(user_id)
        if  session['user']['_id'] in community['managers'] or session['level'] == admin_level:
            community['subscribers'].remove(user['_id'])
            db.communities.update_one({'_id':community['_id']}, {"$set": community}, upsert=False)
            return render_template('alert.html', text=f"{user['first_name']}, {user['last_name']} removed from {community['name']}.", redirect_page=f"/dashboard/community_manager/@{community['_id']}")
        else: 
            return alert_page('Authentication Error.')
    def community_event():
        user = get_user(session['user']['_id'])
        user_level = user['level']
        if user_level == community_level:
            events = get_created_events(user)
            communities = get_approved_managed_communities(user)
            if communities: return render_template('community_event.html', communities=communities, events=events, event=None)
            else: return alert_page("You do not have an approved community.", "/")
        elif user_level == admin_level:
            events = get_all_created_events()
            communities = get_communities()
            return render_template('community_event.html', communities=communities, events=events, event=None)
        else: return authentication_error()
    def community_event_post():
        community_id = request.form.get('event_community')
        community = db.communities.find_one(community_id)
        event_log = {"requested_by":session['user']['_id']}
        user_level = session['user']['level']
        
        if request.form.get('event_participants').isnumeric():
            partipiciants = int(request.form.get('event_participants'))
        elif request.form.get('event_participants')=="":
            partipiciants = 0
        else: return jsonify({'error':"Number of participants should be numeric."}), 400

        event = {
            "_id": uuid.uuid4().hex,
            "status": ("approved" if user_level == admin_level else "requested"),
            "community": community['name'],
            "log": [event_log],
            "subscribers": [session['user']['_id']],
            "event_name": request.form.get('event_name').title(),
            "event_location": request.form.get('event_location'),
            "event_description": request.form.get('event_description'),
            "event_participants": partipiciants,
            "event_community": request.form.get('event_community'),
            "event_status": request.form.get('event_status'),
            "event_date_1": request.form.get('event_date_1'),
            "event_date_2": request.form.get('event_date_2'),
        }

        try:
            event.update({"event_date": int(mktime(datetime.datetime.strptime(request.form.get('event_date_1')+" "+request.form.get('event_date_2'), "%Y-%m-%d %H.%M").timetuple()))})
        except:
            return jsonify({'error':"Wrong hour format."}), 400

        community['events'].append(event)
        status = db.communities.update_one({'_id':community['_id']}, {"$set": community}, upsert=False)
        if status: 
            if user_level == admin_level: return jsonify({'info':'Published'}), 200
            else: return jsonify({'info':'Successfully sent to supervisor'}), 200
        return jsonify({'error':'Error while submitting request'}), 400  
    def community_edit_event(event_id):
        user = get_user(session['user']['_id'])
        if not user: return authentication_error()
        user_level = user['level']
        event = find_event(event_id)
        if event:
            community = db.communities.find_one({"_id": event['event_community']})
            if event_manager_auth(event, user) or (user_level in [admin_level, supervisor_level]):
                if user_level == admin_level: events = get_all_created_events()
                elif user_level == supervisor_level: events = get_requested_events()
                elif user_level == community_level: events = get_created_events(user)
                return render_template('community_event.html', communities=[community], events=events, event=event, participants=get_event_members(event['subscribers']))
        return redirect(url_for('community_event', event_id='create_event'))
    def community_edit_event_post(event_id):
        event = find_event(event_id)
        user = get_user(session['user']['_id'])
        try: operation = request.form.get('operation')
        except: return jsonify({'error': 'ERROR'}), 400
        if operation: return edit_event(event, user, operation)
        return jsonify({'error': 'ERROR'}), 400
    def event(event_id):
        event = find_event(event_id)
        if not event: return alert_page("Event doesn't exist.", url_for('home'))
        if event['status'] != 'approved': return alert_page("Event doesn't exist.", url_for('home'))
        community_id = event['event_community']
        community = find_community(community_id)
        return render_template('event.html', event=event, community=community)
    def event_operation(event_id):
        try:
            event = find_event(event_id)
            community_id = event['event_community']
            community = find_community(community_id)
            operation = request.form.get('operation')
            new_event = event
        except: 
            return authentication_error()
        if not session: return jsonify({'error': "Login for register."}), 400
        if operation and session and event:
            user_id = session['user']['_id']
            if user_id not in event['subscribers']:
                new_event['subscribers'].append(user_id)
                for i, current_event in enumerate(community['events']):
                    if current_event['_id'] == event_id: event_index = i
                community['events'][event_index] = new_event
                db.communities.update_one({'_id':community['_id']}, {"$set": community}, upsert=False)
                return jsonify({'info': "Successfuly registered."})
            else:
                new_event['subscribers'].remove(user_id)
                for i, current_event in enumerate(community['events']):
                    if current_event['_id'] == event_id: event_index = i
                community['events'][event_index] = new_event
                db.communities.update_one({'_id':community['_id']}, {"$set": community}, upsert=False)
                return jsonify({'error': "Registration canceled."}), 400
        else: return authentication_error()
    def community_event_supervisor():
        pass    
    def community_requests():
        events = get_requested_events()
        communities = get_requested_communities()
        return render_template('community_requests.html', events=events, communities=communities)
    def community_requests_post():
        event_id = request.form.get('event_id')
        event = find_event(event_id)
        if event: return jsonify({'info': 'Event found.', 'event_id': event_id})
        else: return jsonify({'error': "Event doesn't exist."}), 400
    
    # community
    def community_editor(community_id):
        community = db.communities.find_one({"_id": community_id})
        if not community: alert_page("Error")
        managers, subscribers = [], [] 
        for user in community['managers']: managers.append(db.users.find_one({ "_id": user }))
        for user in community['subscribers']: subscribers.append(db.users.find_one({ "_id": user }))
        return render_template('community_edit.html', community=community, managers=managers, subscribers=subscribers)
    def community_manager_page():
        user_id = session['user']['_id']
        user = get_user(user_id)
        return get_managed_communities(user)

    # user
    def community(community_id):
        community = db.communities.find_one({"_id": community_id})
        if community:
            if community['status'] == 'approved':
                return render_template('community.html', community = community)
        return render_template('alert.html', text="Community doesn't exist.", redirect_page="/")
    def communities():
        communities = get_approved_communities()
        comunities_organized = []
        if len(communities) % 2 == 1: community_len = int(len(communities)/2) + 1
        else: community_len = int(len(communities)/2)
        for i in range(community_len):
            comunities_organized.append([communities[(i*2)-1], communities[(i*2)]])
        if len(communities) % 2 == 1: 
            comunities_organized[-1].pop(-1)
        return render_template('communities.html', communities=comunities_organized)
    def community_register(community_id):
        if not session: return jsonify({'error':"You need to login first."}), 400
        community = db.communities.find_one({"_id": community_id})
        
        if session['user']['_id'] in community['subscribers']:
            community['subscribers'].remove(session['user']['_id'])
            db.communities.update_one({'_id':community['_id']}, {"$set": community}, upsert=False)
            return jsonify({'error':"Registration Cancelled."}), 400
        
        if community['registration_status']:
            if session['user']['_id'] not in (community['subscribers'] + community['managers']):
                community['subscribers'].append(session['user']['_id'])
                db.communities.update_one({'_id':community['_id']}, {"$set": community}, upsert=False)
                return jsonify({'info':"Registered"})
            else: 
                return jsonify({'error':'Authentication Error'})

        else: return jsonify({'error':"This community doesn't accept new registrations"}), 400

    def home():
        return render_template('index.html', events=get_approved_events())
    def profile():
        user_id = session['user']['_id']
        user = get_user(user_id)
        try: operation = request.form.get('operation')
        except: return jsonify({'error':'Error Message'}), 400
        if operation:
            print(session['user']['first_name'])
            print(session['user']['last_name'])
            if operation == 'change_names':
                user['first_name'] = request.form.get('first_name')
                user['last_name'] = request.form.get('last_name')
                session['user']['first_name'] = request.form.get('first_name')
                session['user']['last_name'] = request.form.get('last_name')
                session.modified = True
                db.users.update_one({'_id': user_id}, {"$set": user}, upsert=False)
                return jsonify({'info':'Changed'})
            elif operation == 'change_pass':
                pass1 = request.form.get('pass1')
                pass2 = request.form.get('pass2')
                if pass1 == pass2:
                    user["password"] = pbkdf2_sha512.encrypt(pass1)
                    db.users.update_one({'_id': user_id}, {"$set": user}, upsert=False)
                    return jsonify({'info':'Changed'})
                else: 
                    return jsonify({'error':"Passwords doesn't match."})
            elif operation == 'community_request':
                msg = Message("MEDCOM | Community Request", recipients=['emirpehlevan@gmail.com'], sender='noreply@medcom.com')
                msg.body = f"Requested by {user['first_name']}, {user['last_name']}\nMail : {user['email']}\nCommunity Name : {request.form.get('community_name').title()}"
                mail.send(msg)
                return jsonify({'info':'Request Submited'})
        else: return jsonify({'error':'Error Message'}), 400

    @staticmethod
    def verify_token(token):
        serial = Serializer(app.secret_key)
        try : user_id = serial.loads(token)['user_id']
        except: return None
        return db.users.find_one({ "_id": user_id })

#otherts
@app.template_filter('cctime')
def timectime(s):
    return ctime(s)
@app.template_filter('ctime')
def timectime(s):
    return datetime.datetime.utcfromtimestamp(s).strftime('%Y/%m/%d')
@app.template_filter('cname')
def community_name_organizer(s):
    if len(s)>8:
        c_names = s.upper().split(" ")
        c_name = ""
        for c in c_names: c_name = c_name + c[0]
        return c_name
    else: return s
def alert_page(text, redirect_url='/'):
    return render_template('alert.html', text=text, redirect_page=redirect_url)

#error
def authentication_error():
    return render_template('alert.html', text="Authentication Error.", redirect_page="/")

#community
def get_community(communit_id):
    community = db.communities.find_one(communit_id)
    if community: return community
    else: return False
def get_user(user_id):
    user = db.users.find_one(user_id)
    if user: return user
    else: return False
def get_communities():
    communities = db.communities.find()
    return communities
def get_approved_communities():
    communities = get_communities()
    approved_communities = []
    for community in communities:
        if community['status'] == 'approved': approved_communities.append(community)
    return approved_communities
def get_requested_communities():
    communities = get_communities()
    requested_communities = []
    for community in communities: 
        if community['status'] == 'requested': requested_communities.append(community)
    return requested_communities
def get_managed_communities(user):
    user_id = user['_id']
    communities = get_communities()
    managed_communities = []
    for community in communities:
        if user_id in community['managers']: managed_communities.append(community)
    if len(managed_communities) > 0: return managed_communities
    else: return False
def get_approved_managed_communities(user):
    user_id = user['_id']
    communities = get_communities()
    managed_communities = []
    for community in communities:
        if user_id in community['managers'] and community['status'] == 'approved': managed_communities.append(community)
    if len(managed_communities) > 0: return managed_communities
    else: return False
def get_user(user_id):
    user = db.users.find_one(user_id)
    if user: return user
    else: return False
def community_edit(community, user, status = None):
    user_level = user['level']

    if user_level == admin_level: status = f'approved'
    elif user_level == community_level: status = f'requested'

    if community:
        try:
            if status == 'declined': 
                community['status'] = status
                db.communities.update_one({'_id':community['_id']}, {"$set": community}, upsert=False)
                return jsonify({"info":"Declined"})

            community['name'] = request.form.get('community_name')
            community['department'] = request.form.get('community_department')
            community['description'] = request.form.get('community_description')
            community['communication'] = request.form.get('email')
            community['website'] = request.form.get('community_website')
            community['social_media'] = request.form.get('community_social_media')
            community['status'] = status
            db.communities.update_one({'_id':community['_id']}, {"$set": community}, upsert=False)
            
            if user_level == supervisor_level:
                if status == 'approved': return jsonify({"info":"Approved"})
                elif status == 'declined': return jsonify({"info":"Declined"})
                else: return jsonify({"error":"Error captured."}), 400
            
            return jsonify({"info":"Successfully Sent"})
        except: return jsonify({"error":"error"}), 400
    return jsonify({"error":"error"}), 400
def get_created_events(user):
    user_id = user['_id']
    communities = db.communities.find()
    events = []
    for community in communities:
        if user_id in community['managers']:
            for event in community['events']:
                events.append(event)
    return events
def get_all_created_events():
    communities = db.communities.find()
    events = []
    for community in communities:
        if community['status'] == 'approved':
            for event in community['events']:
                events.append(event)
    return events
def find_event(event_id):
    events = get_all_created_events()
    for event in events:
        if event['_id'] == event_id:
            return event
    return False
def find_community(community_id):
    community = db.communities.find_one(community_id)
    if community: return community
    else: return False
def get_event_managers(event):
    community_id = event['event_community']
    community = db.communities.find_one(community_id)
    return community['managers']
def get_requested_events():
    all_events = get_all_created_events()
    events = []
    for event in all_events:
        if event['status'] == 'requested':
            events.append(event)
    return events
def get_approved_events():
    all_events = get_all_created_events()
    events = []
    for event in all_events:
        if event['status'] == 'approved':
            events.append(event)
    return events
def get_deleted_events():
    all_events = get_all_created_events()
    events = []
    for event in all_events:
        if event['status'] == 'deleted':
            events.append(event)
    return events
def get_event_members(member_ids):
    members = []
    for member_id in member_ids: 
        members.append(db.users.find_one({ "_id": member_id }))
    return members
def community_manager_auth(community, user):
    user_id = user['_id']
    if user_id in community['managers']: return True
    else: return False
def event_manager_auth(event, user):
    if user['_id'] in get_event_managers(event): return True
    else: return False
def edit_event(event, user, operation):
    community_id = event['event_community']
    community = db.communities.find_one(community_id)
    event_index = community['events'].index(event)
    user_level = user['level']
    return_message = ''
    
    if user_level == admin_level:
        if operation == 'edit_event':
            if request.form.get('event_participants').isnumeric(): partipiciants = int(request.form.get('event_participants'))
            elif request.form.get('event_participants')=="": partipiciants = 0
            else: return jsonify({'error':"Number of participants should be numeric."}), 400
            event['status'] = 'approved'
            event['event_name'] = request.form.get('event_name')
            event['event_location'] = request.form.get('event_location')
            event['event_description'] = request.form.get('event_description')
            event['event_participants'] = partipiciants
            event['event_community'] = request.form.get('event_community')
            print(request.form.get('event_status'))
            event['event_status'] = request.form.get('event_status')
            event['event_date_1'] = request.form.get('event_date_1')
            event['event_date_2'] = request.form.get('event_date_2')
            try: event['event_date'] = int(mktime(datetime.datetime.strptime(request.form.get('event_date_1')+" "+request.form.get('event_date_2'), "%Y-%m-%d %H.%M").timetuple()))
            except: return jsonify({'error':"Wrong hour format."}), 400
            return_message = 'Published'
        elif operation == 'delete_event':
            event['status'] = 'deleted'
            return_message = 'Deleted'
    elif user_level == community_level:
        if operation == 'edit_event':
            if request.form.get('event_participants').isnumeric(): partipiciants = int(request.form.get('event_participants'))
            elif request.form.get('event_participants')=="": partipiciants = 0
            else: return jsonify({'error':"Number of participants should be numeric."}), 400
            event['status'] = 'requested'
            event['event_name'] = request.form.get('event_name')
            event['event_location'] = request.form.get('event_location')
            event['event_description'] = request.form.get('event_description')
            event['event_participants'] = partipiciants
            event['event_community'] = request.form.get('event_community')
            event['event_status'] = request.form.get('event_status')
            event['event_date_1'] = request.form.get('event_date_1')
            event['event_date_2'] = request.form.get('event_date_2')
            try: event['event_date'] = int(mktime(datetime.datetime.strptime(request.form.get('event_date_1')+" "+request.form.get('event_date_2'), "%Y-%m-%d %H.%M").timetuple()))
            except: return jsonify({'error':"Wrong hour format."}), 400
            return_message = 'Successfully sent to supervisor'
        elif operation == 'delete_event':
            event['status'] = 'deleted'
            return_message = 'Deleted'
    elif user_level == supervisor_level:
        if operation == 'approve_event':
            event['status'] = 'approved'
            return_message = 'Approved'
        elif operation == 'decline_event':
            event['status'] = 'declined'
            return_message = 'Declined'
    else: return jsonify({'error': 'ERROR'}), 400
    
    community['events'][event_index] = event
    if db.communities.update_one({'_id':community['_id']}, {"$set": community}, upsert=False): 
        return jsonify({'info': return_message})
    else: return jsonify({'error': 'ERROR'}), 400

#admin
def make_community_admin(user, community):
    try:
        if user['_id'] in community['managers']: return False
        else: community['managers'].append(user['_id']) 
        if user['level'] < 1: user['level'] = 1
        db.communities.update_one({'_id':community['_id']}, {"$set": community}, upsert=False)
        return True
    except: return False
def create_community(user, community_name):
    try:
        # community side
        community = {
            "_id": uuid.uuid4().hex,
            "name": community_name,
            "department": "",
            "description": "",
            "communication": "",
            "website": "",
            "social_media": "",
            "registration_status": False,
            "managers": [user['_id']],
            "subscribers": [],
            "events": [],
            "status": "",
        }

        # give authority
        if user['level'] < 1: user['level'] = 1
        if db.communities.insert_one(community) and db.users.update_one({'_id':user['_id']}, {"$set": user}, upsert=False):  
            return True

    except: return False 

# user agent
def send_email_verification(user):
    serial = URLSafeTimedSerializer(app.secret_key)
    token = serial.dumps(user['email'], salt='email-verification')
    msg = Message("MEDCOM | Email Verification", recipients=[user['email']], sender='noreply@medcom.com')
    verify_link = domain+"email_verification/"+token
    msg.html = render_template('email_verify.html', first_name = user['first_name'], verify_link = verify_link)
    mail.send(msg)
def send_change_pass(user):
    token = get_token(user["_id"])
    token_link = domain+"change_password/"+token
    msg = Message("MEDCOM | Password Reset Request", recipients=[user['email']], sender='noreply@medcom.com')
    msg.html = render_template("email_reset_pass.html", first_name = user["first_name"], change_pass_link = token_link)
    mail.send(msg)
def get_token(user_id, expires_sec = 10*60):
    serial = Serializer(app.secret_key, expires_in = expires_sec)
    return serial.dumps({"user_id": user_id}).decode("utf-8")

from flask import jsonify, render_template, session, redirect, request
from functools import wraps
from uptime import uptime

# rules
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session: return f(*args, **kwargs)
        else: return redirect('/')
    return wrap
def logout_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session: return redirect('/dashboard/')
        else: return f(*args, **kwargs)
    return wrap

# admin dashboard routes
@app.route("/dashboard/manager/",  methods = ['GET'])
@login_required
def dashboard_admin_manager(): 
    if session['level'] in [admin_level]:
        return render_template('dashboard_admin_manager.html', version = version, uptime = f"{int(uptime()/60)} minutes")
    else: return jsonify({"error":"error"})
 
# community routes
@app.route("/dashboard/community_event/<event_id>",  methods = ['GET','POST'])
@login_required
def community_event(event_id = None):
    if request.method == 'GET': 
        if event_id == "create_event": return User.community_event()
        else: return User.community_edit_event(event_id)
    elif request.method == 'POST': 
        if event_id == "create_event": return User.community_event_post()
        else: return User.community_edit_event_post(event_id)
@app.route("/dashboard/community_user_management/<community_id>/<user_id>",  methods = ['GET'])
@login_required
def community_user_remove(community_id = None, user_id = None):
    return User.community_user_remove(community_id, user_id)
@app.route("/dashboard/community_manager/<page>", methods = ['GET', 'POST'])
@login_required
def dashboard_admin_community_manager(page = "1"):
    user_id = session['user']["_id"]
    user_level = session['user']["level"]
    if user_level in [admin_level, supervisor_level, community_level]:
        if request.method == 'GET':
            if page[0] == "@":
                community_id = page.replace("@","")
                community = db.communities.find_one({"_id": community_id})
                if not community: return alert_page("Community doesn't found.")
                community_managers = community['managers']
                if user_level == supervisor_level:
                    if community['status'] == "requested": return User.community_editor(community_id)
                    else: return authentication_error()
                elif user_level == admin_level: return User.community_editor(community_id)
                elif user_level == community_level and community_id and user_id and community_managers:
                    if user_id in community_managers: return User.community_editor(community_id)
                    else: return alert_page('Aurhentication error.')
            elif user_level == admin_level: 
                community_list = User.community_lister()
                return render_template("dashboard_admin_community_manager.html", community_list = community_list)
            elif user_level == community_level: 
                community_list = User.community_manager_page()
                return render_template("community_manager.html", community_list = community_list)
            else: return alert_page('Error')
        if request.method == 'POST':
            if page[0] == "@" or page[0] == "%": 
                page = page.replace("@","")
                page = page.replace("%","")
            return User.community_manager(page) 
    else: return alert_page('Aurhentication error.')

# supervisor dashboard routes
@app.route("/dashboard/users/<page>", methods=['GET', 'POST'])
@login_required
def dashboard_admin_user(page = "1"):
    if session['level'] in [admin_level, supervisor_level]:
        if request.method == 'GET':  
            if page[0] == "@":
                page = page.replace("@", "")
                return User.user_info(page)
            else: return User.get_users((int(page) if (int(page) if page.isnumeric() else False) else 1))
        elif request.method == "POST":
            if session['user']['level'] != 3: return jsonify({'error':'Auth Error'}), 400
            else:
                try:
                    if request.form.get("type") == "search_user":
                        return User.find_user()
                    elif request.form.get("type") == "user_operations":
                        return User.operate_user(page)
                    else: return jsonify({'error':'Undefined transaction.'})
                except Exception as e:
                    return jsonify({'error': "Error"})
    else: return redirect("/dashboard/")
@app.route("/dashboard/community_requests/",  methods = ['GET', 'POST'])
@login_required
def community_requests():
    if session['user']['level'] not in [supervisor_level, admin_level]: return authentication_error()
    if request.method == 'GET': return User.community_requests()
    elif request.method == 'POST': return User.community_requests_post()
    else: return alert_page('Error')

# user
@app.route("/dashboard/profile/", methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'GET': return render_template('profile.html')
    elif request.method == 'POST':
        return User.profile()

# global routes
@app.route("/", methods=['GET'])
def home():
    try:
        return User.home()
    except:
        session.clear()
        return render_template('index.html')
@app.route("/statistics/", methods=['GET'])
def statistics():
    return render_template('statistics.html')
@app.route("/community/<community_id>", methods=['GET','POST'])
def community(community_id):
    if request.method == "GET": 
        if community_id == "all":
            return User.communities()
        else: return User.community(community_id)
    elif request.method == "POST": return User.community_register(community_id)
    else: return jsonify({'error':"Identified Request Method."})
@app.route("/event/<event_id>", methods=['GET','POST'])
def event(event_id):
    if request.method == "GET": return User.event(event_id)
    elif request.method == "POST": return User.event_operation(event_id)
    else: authentication_error()

# user login & register & password forget & verification operations
@login_required
@app.route('/user/signout', methods=['GET'])
def signout():
    return User().signout()
@app.route("/register/", methods=['GET', 'POST'])
@logout_required
def register():
    if request.method == 'POST': return User().signup()
    return render_template('register.html')
@app.route("/login/", methods=['GET','POST'])
@logout_required
def login():
    if request.method == 'POST': 
        return User().login()
    return render_template('login.html')
@app.route("/reset/", methods=['GET','POST'])
@logout_required
def reset_password():
    if request.method == 'POST': 
        return User().reset()
    return render_template('reset_pass.html')
@app.route("/change_password/<token>", methods=['GET','POST'])
@logout_required
def change_password_route(token):
    if request.method == 'POST':
        return User().change_password(token)
    elif request.method == 'GET':
        user = User.verify_token(token)
        if user is None:  return redirect("/login/")
        else:
            return render_template('change_pass.html')
@app.route("/email_verification/<token>", methods=['GET'])
def email_verification(token):
    if request.method == 'GET':
        print(token)
        return User().email_verification(token)