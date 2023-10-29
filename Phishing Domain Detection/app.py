'@author : Sunil Bharadhwaj'

import numpy as np
import re
import requests
import tldextract
import whois
import joblib
import socket
import streamlit as st
import datetime
import time
import dns.resolver
from urllib.parse import urlparse
import warnings
warnings.filterwarnings('ignore')

def master(url, model) :
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lstrip("www.")
    data = []
    
    with st.spinner("Counting characters, vowels....") :
        count_characters_and_vowels(url, data)
    with st.spinner("Checking if email in URL....") :
        email_in_url(url, data)
    with st.spinner("Measuring response time....") :
        measure_response_time(url, data)
    with st.spinner("Checking for Sender Policy Framework....") :
        check_spf_record(domain, data)
    with st.spinner("Checking for creation and expiration dates....") :
        create_exp(url, data)
    with st.spinner("Checking for servers, redirects....") :
        get_ip_resolved(domain, data)
        get_nameservers(domain, data)
        get_mx_servers(domain, data)
        get_redirects(url, data)
    
    try :
        data = (np.array(data)).reshape(1, 104)
        pred = model.predict(data)
        #return pred[0]
        if pred[0] == 0 :
            st.success('### May not a phishing website')
            st.balloons()
        else :
            st.error('### May be a phishing website')
            
    except :
        st.warning('### Please enter proper complete URL')

def count_characters_and_vowels(url, data):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    directory, file = parsed_url.path.rsplit('/', 1) if '/' in parsed_url.path else ('', parsed_url.path)
    parameters = parsed_url.query
    
    tld_in_url_params(url, parameters, data)
    #print(data, len(data))

    components = [url, domain, directory, file, parameters]
    #print(components)

    special_characters = '.-_/?=@&! ~,+*#$%'

    for component in components:
        char_count = len(component)

        #print(f"Component: {component}")
        data.append(char_count)
        #print(len(data), 'charcount')
        
        if component == domain :
            vowel_count = len([c for c in component if c.lower() in 'aeiou'])
            data.append(vowel_count)
            #print(len(data), 'vowel')
            
            # is ip in domain
            ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            ipv6_pattern = r'^[0-9A-Fa-f:]+$'
            if re.match(ipv4_pattern, domain) or re.match(ipv6_pattern, domain):
                data.append(1)
            else:
                data.append(0)
            #print(len(data), 'ip in domain')

        # Count and print each special character separately
        for char in special_characters:
            char_count = component.count(char)
            data.append(char_count)
            #print(len(data), char)
                
    if parameters in components :
        param_qty = component.count('=')
        data.append(param_qty)
        #print(len(data), 'qty params')
    else :
        data.append(0)

def tld_in_url_params(url, parameters, data) :
    l = joblib.load(r'C:\Users\Sunil Bharadhwaj C\Documents\Internshala\Phishing Domain Detection\top_level_domains.joblib')
    for i in l :
        if i in url :
            data.append(1)
            if i in parameters :
                data.append(1)
                return
            else :
                data.append(0)
                return
    data.append(0)
    data.append(0)
        
def email_in_url(url, data) :
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    match = re.search(email_pattern, url)
    if match:
        data.append(1)
    else:
        data.append(0)

def measure_response_time(url, data):
    try :
        
        # Record the start time
        start_time = time.time()

        # Send an HTTP GET request to the URL
        user_agent = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/91.0.4472.124 Safari/537.36")
        headers = {
        'User-Agent': user_agent,
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        }
        response = requests.get(url, headers = headers)
        response_time_ms = time.time() - start_time
        data.append(response_time_ms)
    
    except :
        data.append(0)

def check_spf_record(domain, data):
    try:
        # Query the SPF record for the domain
        answers = dns.resolver.query(domain, 'TXT')
        
        for rdata in answers:
            if "v=spf1" in rdata.to_text():
                data.append(1)
            else :
                data.append(0)
            return
    except :
        data.append(0)

def create_exp(url, data):
    try:
        # Extract the domain from the URL
        domain_info = tldextract.extract(url)
        domain = f"{domain_info.domain}.{domain_info.suffix}"

        # Query WHOIS information for the domain
        whois_info = whois.whois(domain)
        try :
            data.append((datetime.datetime.today() - whois_info.get('creation_date')).days)
        except :
            data.append((datetime.datetime.today() - whois_info.get('creation_date')[0]).days)
        try :
            data.append((whois_info.get('expiration_date') - datetime.datetime.today()).days)
        except :
            data.append((whois_info.get('expiration_date')[0] - datetime.datetime.today()).days) 
    except :
        data.append(0)
        data.append(0)

def get_ip_resolved(domain, data):
    try:
        ip_addresses = socket.gethostbyname_ex(domain)
        data.append(len(ip_addresses[2]))
        return
    except :
        data.append(0)

def get_nameservers(domain, data):
    try:
        answers = dns.resolver.query(domain, 'NS')
        data.append(len(answers))
        return
    except Exception:
        data.append(0)

def get_mx_servers(domain, data):
    try:
        answers = dns.resolver.query(domain, 'MX')
        data.append(len(answers))
        return
    except Exception:
        data.append(0)

def get_redirects(url, data):
    try:
        response = requests.get(url, allow_redirects=False)
        data.append(len(response.history))
        return
    except requests.exceptions.RequestException:
        data.append(0)

model = joblib.load(r'C:\Users\Sunil Bharadhwaj C\Documents\Internshala\Phishing Domain Detection\phishing_model.joblib')

def main() :
    st.set_page_config(
    page_title = "Phishing Domain Detection")

    st.write('@author : Sunil Bharadhwaj')
    st.title("Phishing Domain Detection")

    st.write('##### Login/Signup')
    name = st.text_input("Enter Username/Email ID : ", key = "username")
    password = st.text_input("Enter Password : ", type = "password", key = "password")
    login = st.button("Login/Signup", key = "login")

    if len(name) > 0 and len(password) > 0 :
        url = st.text_input("#### Hello {}!, please enter the URL : ".format(name), key = "url")
        predict = st.button("Predict", key = "predict")
        if  predict :
            pred = master(url, model)
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

if __name__ == '__main__' :
    main()