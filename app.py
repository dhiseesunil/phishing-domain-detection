import streamlit as st
import pandas as pd
from storing_model import StoreModel
from training_model import Training
from database_operations import Database
import warnings

warnings.filterwarnings("ignore")

def get_user_input():
    one = st.text_input('1')
    two = st.text_input('2')
    three = st.text_input('3')
    four = st.text_input('4')
    five = st.text_input('5')
    six = st.text_input('6')
    seven = st.text_input('7')
    eight = st.text_input('8')
    return one, two, three, four, five, six, seven, eight

def main():
    st.title('My App')

    if st.button('Train'):
        cluster_model = train()
        st.write(f'Cluster Model: {cluster_model}')

    if st.button('Predict'):
        user_input = get_user_input()
        prediction = predict(*user_input)
        st.write(f'Prediction: {prediction}')

def predict(one, two, three, four, five, six, seven, eight):
    user_input = pd.DataFrame([[one, two, three, four, five, six, seven, eight]],
                              columns=['directory_length', 'qty_slash_url', 'qty_dot_directory', 'file_length',
                                       'qty_hyphen_directory', 'qty_percent_file', 'qty_hyphen_file',
                                       'qty_underline_directory'])

    read = StoreModel()
    k_means = read.read_model("k_means")
    cluster = k_means.predict(user_input)
    scale = read.read_model("Scale")
    user_input = pd.DataFrame(scale.transform(user_input), columns=user_input.columns)
    if cluster[0] == 0:
        model = read.read_model("gradient_boosting_cluster0")
        prediction = model.predict(user_input)
        if prediction[0] == 0:
            prediction = "The Domain is real..!"
        else:
            prediction = "The Domain is Fake..!"
    elif cluster[0] == 1:
        model = read.read_model("support_vector_classifier_cluster1")
        prediction = model.predict(user_input)
        if prediction[0] == 0:
            prediction = "The Domain is real..!"
        else:
            prediction = "The Domain is Fake..!"

    return str(prediction)

def train():
    try:
        path = r"dataset_full.csv"
        df = pd.read_csv(path)
    except Exception as e:
        data = Database()
        df = data.fetch_data()

    train_me = Training(df)
    cluster_model = train_me.train_model()
    return cluster_model

if __name__ == "__main__":
    main()
