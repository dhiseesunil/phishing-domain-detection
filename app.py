'@author : Sunil Bharadhwaj'

import pandas as pd
import numpy as np
import joblib
import regex as re
import whois
import datetime
import streamlit as st

def master(url) :
    data = []
    domain, directories, file, parameters = split_url(url, data)
    tld_in_param(parameters, data)
    char(data, url, directories, file, parameters)
    email_in_url(url, data)
    create_exp(domain, data)
    return (np.array(data)).reshape(1, 77)

def split_url(url, data):
    protocol, _, rest = url.partition('://')
    domain, _, rest = rest.partition('/')
    path, _, parameters = rest.partition('?')
    
    directories = path.split('/')
    file = '' if '.' not in directories[-1] else directories[-1]
    directories = directories[:-1] if file else directories
    directories = '/'.join(directories)
    
    parameters = [param.split('=')[1] for param in parameters.split('&')] if parameters else []
    data.append(len(parameters))
    parameters = '/'.join(parameters)
    
    return domain, directories, file, parameters

def tld_in_param(parameters, data) :
    tld = joblib.load('top_level_domains.joblib')
    for i in tld :
        if i in url :
            data.append(1)
            return
    data.append(0)
    return

def char(data, url, directories, file, parameters) :
    components = [url, directories, file, parameters]

    special_characters = '.-_/?=@&! ~,+*#$%'

    for component in components:
        char_count = len(component)
        data.append(char_count)

        for char in special_characters:
            char_count = component.count(char)
            data.append(char_count)
    return

def email_in_url(url, data) :
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    match = re.search(email_pattern, url)
    if match:
        data.append(1)
    else:
        data.append(0)
    return

def create_exp(domain, data):
    try:
        whois_info = whois.whois(domain)
        try :
            data.append((datetime.datetime.today() - whois_info.get('creation_date')).days)
        except :
            data.append((datetime.datetime.today() - whois_info.get('creation_date')[0]).days)
        try :
            data.append((whois_info.get('expiration_date') - datetime.datetime.today()).days)
        except :
            data.append((whois_info.get('expiration_date')[0] - datetime.datetime.today()).days)
    except Exception as e:
        data.append(0)
        data.append(0)
    return

pipe = joblib.load('pipeline.joblib')

st.set_page_config(
page_title = "Phishing Domain Detection")
st.write('@author : Sunil Bharadhwaj')
st.title("Phishing Domain Detection")

st.write('##### Login/Signup')  
name = st.text_input("Enter Username/Email ID : ", key = "username")
password = st.text_input("Enter Password : ", type = "password", key = "password")
st.button("Login/Signup", key = "login")

if len(name) > 0 and len(password) > 0 :
    url = st.text_input("#### Hello {}!, please enter the URL : ".format(name), key = "url")
    if 'http' not in url :
        url = 'https://' + url
    predict = st.button("Predict", key = "predict")
    if  predict :
        pred = pipe.predict(master(url))
        if pred[0] == 0 :
            st.success('### May not a phishing website')
            st.balloons()
        elif pred[0] == 1 :
            st.error('### May be a phishing website')
else :
    st.write("Please enter valid username/email ID or password")

if st.button("About") :
    st.info('''This website has ability to identify probable harmful websites, 
            often called phishing domains, using XGBoost classification model. This considers different clues, 
            such as Sender Policy Frameworks, website respond time, how many characters, vowels it has, 
            and whether its top level domain exists or not. 
            It also checks if the website is trying to trick you with sneaky redirects. 
            Plus, it looks at when the website was created and expiration date. 
            All these checks help it decide if a website might be up to no good or not.''')
