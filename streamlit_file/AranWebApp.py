import pickle
import subprocess
import re
import streamlit as st 
import requests
import whois
from datetime import datetime 
from PIL import Image
img = Image.open('iconlogo-removebg-preview.png')

# st.markdown('<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-KK94CHFLLe+nY2dmCWGMq91rCGa5gtU4mk92HdvYe+M/SXH301p5ILy+dN9+nJOZ" crossorigin="anonymous">',unsafe_allow_html=True)

# st.markdown('<img src="file:///C:/Users/ARUN/Desktop/Malicious/StreamLit/aranlogo.png" alt="" width="50" height="50" >',unsafe_allow_html=True)

st.set_page_config(page_title="Aran",page_icon=img,layout="wide")


with open('style.css') as f:
    st.markdown(f'<style>{f.read()}</style>',unsafe_allow_html=True)

def makeTokens(f):
    total_tokens = re.split(r"[\./-:]",f)
    total_tokens = [token for token in total_tokens if token not in {"https","http",""}]  #remove redundant tokens
    return total_tokens

# def get_certificate(long_url):
#     try:
#         response = requests.get(long_url)
#         if response.ok:
#             value = "The SSL certificate is valid."

#     except:
#             value ="The SSL certificate is invalid or not found."
#     return value

def get_domain_age(domain_name):
    try:
        domain_info = whois.whois(domain_name)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age = (datetime.now() - creation_date).days / 365
        return round(age, 2)
    except Exception as e:
        return "Not Found"

def malipred(x_predict):
    with open("tf-idf-vectorizer.pkl","rb") as f:
        vectorizer = pickle.load(f)
    with open("logistic_regression_model.pkl","rb") as f:
        model = pickle.load(f)
    x_test = vectorizer.transform(x_predict)
    y_test = model.predict(x_test)
    status = ' '.join([str(elem) for elem in y_test])
    return status


def main():
    st.image('logowithname-removebg-preview.png')
    st.header("Free Online Website Checker")
    st.subheader('Place the URL Here 👇 and click Detect button')
    short_url = st.text_input('  ')
    cmd = ['curl', '-sL', '-w', '%{url_effective}', '-o', '/dev/null', short_url]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    output, error = process.communicate()
    long_url = output.decode('utf-8')
    x_predict = long_url.split()
    predict = ' '
    if st.button("Detect"):
        st.write("Input URL:",short_url)
        st.write("Expand URL:",long_url)
        # st.write("SSL Certificate:",get_certificate(long_url))
        domain_name=long_url.split('/')[2]
        st.write("Domain Age in Years:",get_domain_age(domain_name))
        predict = malipred(x_predict)
        if predict == 'good':
            st.success('GOOD - Safe to surf')
        else:
            st.error('BAD - Looks Malicious')
    st.info("Disclaimer: ARAN - Malicious Link Detector is a free website detector. 100% detection rate does not exist and no vendor in the market can guarantee it. ARAN has no responsibility for detecting or not detecting malicious code on your website or any other websites.")



if __name__ ==  "__main__":
    main()