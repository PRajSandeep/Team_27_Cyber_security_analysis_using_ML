__author__ = "home"
__date__ = "$26 Apr, 2021 6:30:58 PM$"

import Random_Integration as objRandomIntegration
from flask import Flask
from flask import flash
from flask import render_template
from flask import request
from flask import session
import numpy as np
import os
import pandas as pd
import pygal
import pymysql
from sklearn.model_selection import train_test_split
import urllib.parse as urlparse
from urllib.parse import parse_qs
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'D:/uploads'
ALLOWED_EXTENSIONS = set(['csv'])

app = Flask(__name__)
app.secret_key = "1234"
app.password = ""
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
class Database:
    def __init__(self):
        host = "localhost"
        user = "root"
        password = ""
        db = "cyberattackdetection"
        self.con = pymysql.connect(host=host, user=user, password=password, db=db, cursorclass=pymysql.cursors.DictCursor)
        self.cur = self.con.cursor()
    def getuserprofiledetails(self, username):
        strQuery = "SELECT PersonId,Firstname,Lastname,Phoneno,Address,Recorded_Date FROM personaldetails WHERE Username = '" + username + "' LIMIT 1"
        self.cur.execute(strQuery)
        result = self.cur.fetchall()
        print(result)
        return result
    def insertpersonaldetails(self, firstname, lastname, phone, email, address, username, password):
        print('insertpersonaldetails::' + username)
        strQuery = "INSERT INTO personaldetails(Firstname, Lastname, Phoneno, Emailid, Address, Username, Password, Recorded_Date) values(%s, %s, %s, %s, %s, %s, %s, now())"
        strQueryVal = (firstname, lastname, phone, email, address, username, password)
        self.cur.execute(strQuery, strQueryVal)
        self.con.commit()
        return ""
    def getpersonaldetails(self, username, password):
        strQuery = "SELECT COUNT(*) AS c, PersonId FROM personaldetails WHERE Username = '" + username + "' AND Password = '" + password + "'"        
        self.cur.execute(strQuery)        
        result = self.cur.fetchall()       
        return result
    def getuserpersonaldetails(self, name):
        strQuery = "SELECT PersonId, Firstname, Lastname, Phoneno, Address, Recorded_Date FROM personaldetails WHERE Username = '" + name + "' "
        self.cur.execute(strQuery)
        result = self.cur.fetchall()
        print(result)
        return result
    def insertkdddataset(self, PersonId, s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, s16, s17, s18, s19, s20, s21, s22, s23, s24, s25, s26, s27, s28, s29, s30, s31, s32, s33, s34, s35, s36, s37, s38, s39, s40, s41):
        print('insertkdddataset::' + str(PersonId))
        strQuery = "INSERT INTO kdddataset(PersonId, s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15,  s16, s17, s18, s19, s20, s21, s22, s23, s24, s25, s26, s27, s28, s29, s30, s31, s32, s33, s34, s35, s36, s37, s38, s39, s40, s41, Recorded_Date) values(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now())"
        strQueryVal = (str(PersonId), s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, s16, s17, s18, s19, s20, s21, s22, s23, s24, s25, s26, s27, s28, s29, s30, s31, s32, s33, s34, s35, s36, s37, s38, s39, s40, s41)
        self.cur.execute(strQuery, strQueryVal)
        self.con.commit()
        return ""   
    def deletekdddataset(self, loanId):
        print(loanId)
        strQuery = "DELETE FROM kdddataset WHERE Sno = (%s) " 
        strQueryVal = (str(loanId))
        self.cur.execute(strQuery, strQueryVal)
        self.con.commit()
        return ""
    def getkdddatasetuploadeddetails(self, PersonId):
        strQuery = "SELECT PersonId, Sno, s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15,  s16, s17, s18, s19, s20, s21, s22, s23, s24, s25, s26, s27, s28, s29, s30, s31, s32, s33, s34, s35, s36, s37, s38, s39, s40, s41, s42, Recorded_Date "
        strQuery += "FROM kdddataset "
        strQuery += "WHERE PersonId = '" + str(PersonId) + "'"
        strQuery += "ORDER BY Sno DESC "
        strQuery += "LIMIT 10"        
        self.cur.execute(strQuery)
        result = self.cur.fetchall()
        print(result)
        return result
    def getgraphdetails(self, dataownername):
        strQuery = "SELECT COUNT(*) AS c, Protocol, Service, Flag, $nc_bytes AS nc_bytes, de$_bytes AS de_bytes, Attack "        
        strQuery += "FROM kdddataset "        
        strQuery += "GROUP BY Protocol, Service, Flag, Attack "   
        print(strQuery)
        self.cur.execute(strQuery)
        result = self.cur.fetchall()
        print(result)
        return result
    def getallprotocoldetails(self, PersonId):
        strQuery = "SELECT DISTINCT(s1) AS Protocol "
        strQuery += "FROM kdddataset "
        strQuery += "WHERE PersonId = '" + str(PersonId) + "' "
        self.cur.execute(strQuery)
        result = self.cur.fetchall()
        print(result)
        return result
    def getkdddatasetdatabyname(self, protocol):
        strQuery = "SELECT Sno, Duration, Protocol, Service, Flag, $nc_bytes AS nc_bytes, de$_bytes AS de_bytes, Land, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15,  s16, s17, s18, s19, s20, s21, s22, s23, s24, s25, s26, s27, s28, s29, s30, s31, s32, s33, s34, Attack "
        strQuery += "FROM kdddataset "
        strQuery += "WHERE Protocol = '" + protocol + "'  "
        strQuery += "ORDER BY Sno DESC "
        strQuery += "LIMIT 10"        
        self.cur.execute(strQuery)
        result = self.cur.fetchall()
        print(result)
        return result
    def insertanalysisdetails(self, PersonId, Accuracy, Algorithm):
        print('insertanalysisdetails::' + Algorithm)
        strQuery = "INSERT INTO analysisdetails(PersonId, Accuracy, Algorithm, Recorded_Date) values(%s, %s, %s, now())"
        strQueryVal = (str(PersonId), str(Accuracy).encode('utf-8', 'ignore'), str(Algorithm).encode('utf-8', 'ignore'))
        self.cur.execute(strQuery, strQueryVal)
        self.con.commit()
        return ""  
    def getallrfdetails(self, PersonId):
        strQuery = "SELECT Accuracy as c FROM analysisdetails WHERE Algorithm = 'RF' AND PersonId = '" + str(PersonId) + "' ORDER BY Analysis_Id DESC LIMIT 1"
        self.cur.execute(strQuery)
        result = self.cur.fetchall()
        print(result)
        return result  
    def getallriadetails(self, PersonId):
        strQuery = "SELECT Accuracy as c FROM analysisdetails WHERE Algorithm = 'RIA' AND PersonId = '" + str(PersonId) + "' ORDER BY Analysis_Id DESC LIMIT 1"
        self.cur.execute(strQuery)
        result = self.cur.fetchall()
        print(result)
        return result  
    def getdatasetdetails(self, protocolname, PersonId):
        strQuery = "SELECT Sno, PersonId, s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15,  s16, s17, s18, s19, s20, s21, s22, s23, s24, s25, s26, s27, s28, s29, s30, s31, s32, s33, s34, s35, s36, s37, s38, s39, s40, s41, s42, Recorded_Date "
        strQuery += "FROM kdddataset "
        strQuery += "WHERE s1 = '" + protocolname + "'  "
        strQuery += "AND PersonId = '" + str(PersonId) + "'  "
        strQuery += "ORDER BY Sno DESC "
        strQuery += "LIMIT 10" 
        self.cur.execute(strQuery)
        result = self.cur.fetchall()
        print(result)
        return result     
    def getattackdetails(self, PersonId):
        strQuery = "SELECT COUNT( * ) AS c, s41 AS Attack "
        strQuery += "FROM kdddataset "
        strQuery += "WHERE PersonId = '" + str(PersonId) + "'  "
        strQuery += "GROUP BY s41 "        
        self.cur.execute(strQuery)
        result = self.cur.fetchall()
        print(result)
        return result     
    def getallsvmdetails(self, PersonId):
        strQuery = "SELECT Accuracy as c FROM analysisdetails WHERE Algorithm = 'SVM' AND PersonId = '" + str(PersonId) + "' ORDER BY Analysis_Id DESC LIMIT 1"
        self.cur.execute(strQuery)
        result = self.cur.fetchall()
        print(result)
        return result
    
@app.route('/', methods=['GET'])
def loadindexpage():
    return render_template('index.html')

@app.route('/index', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/codeindex', methods=['POST'])
def codeindex():
    username = request.form['username']
    password = request.form['password']
    
    print('username:' + username)
    print('password:' + password)
    
    try:
        if username is not "" and password is not "": 
            def db_query():
                db = Database()
                emps = db.getpersonaldetails(username, password)       
                return emps
            res = db_query()
            
            for row in res:
                print(row['c'])
                count = row['c']
                
                if count >= 1:      
                    session['x'] = username;
                    session['UID'] = row['PersonId'];
                    def db_query():
                        db = Database()
                        emps = db.getuserprofiledetails(username)       
                        return emps
                    profile_res = db_query()
                    return render_template('userprofile.html', sessionValue=session['x'], result=profile_res, content_type='application/json')
                else:
                    flash ('Incorrect Username or Password.')
                    return render_template('index.html')
        else:
            flash ('Please fill all mandatory fields.')
            return render_template('index.html')
    except NameError:
        flash ('Due to technical problem, your request could not be processed.')
        return render_template('index.html')
        
    return render_template('index.html')

@app.route('/usersignin', methods=['GET'])
def usersignin():
    return render_template('usersignin.html')

@app.route('/codeusersignin', methods=['POST'])
def codeusersignin():
    firstname = request.form['firstname']
    lastname = request.form['lastname']
    phone = request.form['phone']
    email = request.form['email']
    address = request.form['address']    
    username = request.form['username']
    password = request.form['password']
    
    print('firstname:', firstname)
    print('lastname:', lastname)
    print('phone:', phone)
    print('email:', email)
    print('address:', address)
    print('username:', username)
    print('password:', password)
    
    try:
        if firstname is not "" and lastname is not ""  and phone is not "" and email is not "" and address is not "" and username is not "" and password is not "": 
            def db_query():
                db = Database()
                emps = db.getpersonaldetails(username, password)       
                return emps
            res = db_query()

            for row in res:
                print(row['c'])
                count = row['c']

                if count >= 1:      
                    flash ('Entered details already exists.')
                    return render_template('usersignin.html')
                else:
                    def db_query():
                        db = Database()
                        emps = db.insertpersonaldetails(firstname, lastname, phone, email, address, username, password)    
                        return emps
                res = db_query()
                flash ('Dear Customer, Your registration has been done successfully.')
                return render_template('index.html')
        else:                        
            flash ('Please fill all mandatory fields.')
            return render_template('usersignin.html')
    except NameError:
        flash ('Due to technical problem, your request could not be processed.')
        return render_template('usersignin.html')
    
    return render_template('usersignin.html')

@app.route('/userprofile', methods=['GET'])
def userprofile():
    def db_query():
        db = Database()
        emps = db.getuserpersonaldetails(session['x'])       
        return emps
    profile_res = db_query()
    return render_template('userprofile.html', sessionValue=session['x'], result=profile_res, content_type='application/json')

@app.route('/signout', methods=['GET'])
def signout():    
    return render_template('signout.html')

@app.route('/logout', methods=['GET'])
def logout():
    del session['x']
    return render_template('index.html')

@app.route('/uploaddata', methods=['GET'])
def uploaddata():
    return render_template('uploaddata.html', sessionValue=session['x'], content_type='application/json')

@app.route('/codeuploaddata', methods=['POST'])
def codeuploaddata(): 
    file = request.files['filepath']
    
    print('filename:' + file.filename)
       
    if 'filepath' not in request.files:
        flash ('Please fill all mandatory fields.')
        return render_template('uploaddata.html', sessionValue=session['x'], content_type='application/json')
    
    if file.filename != '':

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            filepath = UPLOAD_FOLDER + "/" + file.filename

            print('filepath:' + filepath)
            
            data = pd.read_csv(filepath)
            
            # print info about columns in the dataframe 
            print(data.info()) 
            
            print(len(data.columns))
            
            # Dropped all the Null, Empty, NA values from csv file 
            txtrows = data.dropna(axis=0, how='any') 
            
            print("Dimensions of Dataset after Pre-processing : {}".format(txtrows.shape))
            
            txtrows.columns = ['s0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9', 's10',
                's11', 's12', 's13', 's14', 's15', 's16', 's17', 's18', 's19', 's20',
                's21', 's22', 's23', 's24', 's25', 's26', 's27', 's28', 's29', 's30',
                's31', 's32', 's33', 's34', 's35', 's36', 's37', 's38', 's39', 's40', 's41']

            count = len(txtrows);
            
            print('Length of Data::', count)
            
            for i in range(count): 
                
                print(str(np.array(txtrows['s0'])[i]))
                
                db = Database()
                db.insertkdddataset(session['UID'], str(np.array(txtrows['s0'])[i]), str(np.array(txtrows['s1'])[i]), str(np.array(txtrows['s2'])[i]), str(np.array(txtrows['s3'])[i]), str(np.array(txtrows['s4'])[i]), str(np.array(txtrows['s5'])[i]), str(np.array(txtrows['s6'])[i]), str(np.array(txtrows['s7'])[i]), str(np.array(txtrows['s8'])[i]), str(np.array(txtrows['s9'])[i]), str(np.array(txtrows['s10'])[i]), str(np.array(txtrows['s11'])[i]), str(np.array(txtrows['s12'])[i]), str(np.array(txtrows['s13'])[i]), str(np.array(txtrows['s14'])[i]), str(np.array(txtrows['s15'])[i]), str(np.array(txtrows['s16'])[i]), str(np.array(txtrows['s17'])[i]), str(np.array(txtrows['s18'])[i]), str(np.array(txtrows['s19'])[i]), str(np.array(txtrows['s20'])[i]), str(np.array(txtrows['s21'])[i]), str(np.array(txtrows['s22'])[i]), str(np.array(txtrows['s23'])[i]), str(np.array(txtrows['s24'])[i]), str(np.array(txtrows['s25'])[i]), str(np.array(txtrows['s26'])[i]), str(np.array(txtrows['s27'])[i]), str(np.array(txtrows['s28'])[i]), str(np.array(txtrows['s29'])[i]), str(np.array(txtrows['s30'])[i]), str(np.array(txtrows['s31'])[i]), str(np.array(txtrows['s32'])[i]), str(np.array(txtrows['s33'])[i]), str(np.array(txtrows['s34'])[i]), str(np.array(txtrows['s35'])[i]), str(np.array(txtrows['s36'])[i]), str(np.array(txtrows['s37'])[i]), str(np.array(txtrows['s38'])[i]), str(np.array(txtrows['s39'])[i]), str(np.array(txtrows['s40'])[i]), str(np.array(txtrows['s41'])[i])) 
                    
            flash('File successfully uploaded!')
            return render_template('uploaddata.html', sessionValue=session['x'], content_type='application/json')

        else:
            flash('Allowed file types are .txt')
            return render_template('uploaddata.html', sessionValue=session['x'], content_type='application/json')
    else:
        flash ('Please fill all mandatory fields.')           
        return render_template('uploaddata.html', sessionValue=session['x'], content_type='application/json')

@app.route('/viewuploadeddata', methods=['GET'])
def viewuploadeddata():
    def db_query():
        db = Database()
        emps = db.getkdddatasetuploadeddetails(session['UID'])       
        return emps
    profile_res = db_query()
    return render_template('viewuploadeddata.html', sessionValue=session['x'], result=profile_res, content_type='application/json')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/deletedata', methods=['GET'])
def deletedata():
    parsed = urlparse.urlparse(request.url)
    print(parse_qs(parsed.query)['index'])
    
    loanId = parse_qs(parsed.query)['index']
    print(loanId)
    
    try:
        if loanId is not "": 
            
            db = Database()
            db.deletekdddataset(loanId[0])
            
            def db_query():
                db = Database()
                emps = db.getkdddatasetuploadeddetails(session['UID'])    
                return emps
            profile_res = db_query()
            flash ('Dear Customer, Your request has been processed sucessfully!')
            return render_template('viewuploadeddata.html', sessionValue=session['x'], result=profile_res, content_type='application/json')
        else:
            flash ('Please fill all mandatory fields.')
            return render_template('viewuploadeddata.html', sessionValue=session['x'], result=profile_res, content_type='application/json')
    except NameError:
        flash ('Due to technical problem, your request could not be processed.')
        return render_template('viewuploadeddata.html', sessionValue=session['x'], result=profile_res, content_type='application/json')

@app.route('/searchknn', methods=['GET'])
def searchknn():    
    def db_query():
        db = Database()
        emps = db.getallprotocoldetails(session['UID'])       
        return emps
    protocolresult = db_query()
    return render_template('searchknn.html', sessionValue=session['x'], protocolresult=protocolresult, content_type='application/json')

def err_metric(CM): 
      
    TN = CM.iloc[0, 0]
    FN = CM.iloc[1, 0]
    TP = CM.iloc[1, 1]
    FP = CM.iloc[0, 1]
    #precision =(TP)/(TP+FP)
    accuracy_model  = (TP + TN) / (TP + TN + FP + FN)
    #recall_score  =(TP)/(TP+FN)
    
    #print("Accuracy value of the model: ",accuracy_model)
    #print("Precision value of the model: ",precision)
    #print("Recall value of the model: ",recall_score)

    return accuracy_model
    
@app.route('/codesearchknn', methods=['POST'])
def codesearchknn():  
    
    protocolname = request.form['protocol']
    
    print('protocolname:' + protocolname)
    
    def db_query():
        db = Database()
        emps = db.getallprotocoldetails(session['UID'])       
        return emps
    protocolresult = db_query()
    
    try:
        if protocolname is not "": 
 
            #Load the data-set
            dataset = pd.read_csv('D:/Dataset/kddcup.csv') 

            #Print the count of rows and coulmns in csv file
            print("Dimensions of Dataset: {}".format(dataset.shape))

            # Dropped all the Null, Empty, NA values from csv file 
            new_dataset = dataset.dropna(axis=0, how='any') 

            print("Dimensions of Dataset after Pre-processing : {}".format(new_dataset.shape))

            #Print the count of rows and coulmns in csv file
            print("Dimensions of Dataset: {}".format(dataset.shape))

            # Dropped all the Null, Empty, NA values from csv file 
            new_dataset = dataset.dropna(axis=0, how='any') 

            print("Dimensions of Dataset after Pre-processing : {}".format(new_dataset.shape))

            #Encoding categorical data values
            from sklearn.preprocessing import LabelEncoder

            labelencoder_Y = LabelEncoder()

            new_dataset.iloc[:, 1] = labelencoder_Y.fit_transform(new_dataset.iloc[:, 1].values)

            print("Encoding : {}".format(labelencoder_Y.fit_transform(new_dataset.iloc[:, 1].values)));

            new_dataset.iloc[:, 2] = labelencoder_Y.fit_transform(new_dataset.iloc[:, 2].values)

            print("Encoding : {}".format(labelencoder_Y.fit_transform(new_dataset.iloc[:, 2].values)));

            new_dataset.iloc[:, 3] = labelencoder_Y.fit_transform(new_dataset.iloc[:, 3].values)

            print("Encoding : {}".format(labelencoder_Y.fit_transform(new_dataset.iloc[:, 3].values)));

            #Data conversion for Url Column
            filter_dataset_url = new_dataset.drop_duplicates(subset=["S41"])

            print("Dimensions of Dataset after Filtering : {}".format(filter_dataset_url.shape))

            c = filter_dataset_url.iloc[:, 41:42];

            attack_types = ();
            attack_types = list(attack_types)

            for i in range(len(c)):
                attack_types.append(c.values[i]);

            attack_types = tuple(attack_types)

            print("attack_types: ", attack_types)

            filter_dataset_attack_types = pd.DataFrame(attack_types, columns=['S41'])

            # creating instance of labelencoder
            labelencoder = LabelEncoder()

            # Assigning numerical values and storing in another column
            filter_dataset_attack_types['S41_Category'] = labelencoder.fit_transform(filter_dataset_attack_types['S41'])

            print("filter_dataset_attack_types: ", filter_dataset_attack_types);

            filter_dataset_attack_types.to_csv('D:/Dataset/kddcup_attacks.csv', encoding='utf-8')

            new_dataset.iloc[:, 41] = labelencoder_Y.fit_transform(new_dataset.iloc[:, 41].values)

            print("Encoding : {}".format(labelencoder_Y.fit_transform(new_dataset.iloc[:, 41].values)));
            
            # you want all rows, and the feature_cols' columns
            X = new_dataset.iloc[:, 0: 42].values
            y = new_dataset.iloc[:, 42].values

            # Split into training and test set 
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=109) # 70% training and 30% test

            #Import svm model
            from sklearn import svm

            #Create a svm Classifier
            clf = svm.LinearSVR()

            #Train the model using the training sets
            clf.fit(X_train, y_train)

            #Predict the response for test dataset
            y_pred = clf.predict(X_test)

            # Model Accuracy, how often is the classifier correct?
            confusion_matrix = pd.crosstab(y_test, y_pred)
            
            result1 = err_metric(confusion_matrix)

            print("SVM Accuracy :", result1);
            
            
            algo = 'SVM'
            
            db = Database()
            db.insertanalysisdetails(session['UID'], result1, algo) 
            
            #Import scikit-learn metrics module for accuracy calculation
            from sklearn.ensemble import RandomForestClassifier

            #Create a Random Forest Classifier
            classifier = RandomForestClassifier(n_estimators=100)

            #Train the model using the training sets
            classifier.fit(X_train, y_train)

            #Predict the response for test dataset
            y_pred_1 = classifier.predict(X_test)

            # Model Accuracy, how often is the classifier correct?
            confusion_matrix = pd.crosstab(y_test, y_pred_1)
            
            result2 = err_metric(confusion_matrix)

            print("Random Forest Accuracy:", result2)
            
            
            algo = 'RF'
            
            db = Database()
            db.insertanalysisdetails(session['UID'], result2, algo) 
            
            #Create Fusion Classifier
            integration = objRandomIntegration.Random_Integration()

            #Train the model using the training sets
            integration.fit(X_train, y_train)

            #Predict the response for test dataset
            y_pred_2 = integration.predict(X_test)

            # Model Accuracy, how often is the classifier correct?
            confusion_matrix = pd.crosstab(y_test, y_pred_2)
            
            result3 = err_metric(confusion_matrix)

            print("Random Integration Accuracy:", result3)

            algo = 'RIA'
            
            db = Database()
            db.insertanalysisdetails(session['UID'], result3, algo) 
            
            def db_query6():
                db = Database()
                emps = db.getdatasetdetails(protocolname, session['UID'])
                return emps

            profile_res = db_query6()
            
            return render_template('codesearchknn.html', sessionValue=session['x'], result=profile_res, protocolresult=protocolresult, content_type='application/json')
        else:
            flash ('Please fill all mandatory fields.')
            return render_template('searchknn.html', sessionValue=session['x'])
    except NameError:
        flash ('Due to technical problem, your request could not be processed.')
        return render_template('searchknn.html', sessionValue=session['x'])
    
    return render_template('searchknn.html', sessionValue=session['x'])

@app.route('/comparisongraph', methods=['GET'])
def comparisongraph():
    
    labels = ["SVM ALGORITHM", "RANDOM FOREST ALGORITHM", "RANDOM INTEGRATION ALGORITHM"]
    
    def svm_query():
        db = Database()
        emps = db.getallsvmdetails(session['UID'])       
        return emps
    res1 = svm_query()

    svmcount = 0;

    for row in res1:
        print(row['c'])
        svmcount = row['c']
        
    def rf_query():
        db = Database()
        emps = db.getallrfdetails(session['UID'])       
        return emps
    res2 = rf_query()

    rfcount = 0;

    for row in res2:
        print(row['c'])
        rfcount = row['c']
        
    def ria_query():
        db = Database()
        emps = db.getallrfdetails(session['UID'])       
        return emps
    res3 = ria_query()

    riacount = 0;

    for row in res3:
        print(row['c'])
        riacount = row['c']
        
    values = [svmcount, rfcount, riacount]

    return render_template('comparisongraph.html', sessionValue=session['x'], values=values, labels=labels)

@app.route('/graph', methods=['GET'])
def graph():
    
    labels = ["Normal", "Buffer Overflow", "Loadmodule", "Perl", "Neptune", "Smurf"]
            
    def ria_query():
        db = Database()
        emps = db.getattackdetails(session['UID'])       
        return emps
    res = ria_query()

    buffer_overflow = 0;
    loadmodule = 0;
    neptune = 0;
    perl = 0;
    normal = 0;
    smurf = 0;

    for row in res:
        print(row['c'])
        
        if row['Attack'] == 'buffer_overflow.':
            buffer_overflow = row['c']
        elif row['Attack'] == 'loadmodule.':
            loadmodule = row['c']
        elif row['Attack'] == 'neptune.':
            neptune = row['c']
        elif row['Attack'] == 'perl.':
            perl = row['c']
        elif row['Attack'] == 'smurf.':
            smurf = row['c']
        else:
            normal = row['c']
                
    values = [normal, buffer_overflow, loadmodule, perl, neptune, smurf]

    return render_template('graph.html', sessionValue=session['x'], values=values, labels=labels)
