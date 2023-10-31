# phishing-domain-detection
## Problem Statement
#### Phishing is a type of fraud in which an attacker impersonates a reputable company or person through email or other communication channels to obtain sensitive information such as login credentials or account details. Attackers prefer phishing because convincing someone to click a seemingly authentic malicious link is easier than bypassing a computer's security measures. The primary objective is to predict the authenticity of domains, distinguishing between genuine and malicious ones.

## Proposed Solution
#### This system relies on a set of critical features for phishing detection, encompassing Length of URL, Length of Directory, Length of File, Activation Domain Time, Expiration Domain Time, and sender policy framework (SPF). By leveraging these essential features, the system is equipped to make predictions regarding the authenticity of websites, differentiating between genuine and potentially malicious domains. The predictive model analyzes these features to determine whether a website is legitimate or malicious. It is this amalgamation of factors that empowers the system to safeguard users by providing timely alerts and ensuring their online security. The inclusion of these key features is essential to achieve optimal accuracy and to maximize the system's efficacy and value for the company and its users.

## Data Requirements
#### This data set consist of 88,647 websites labelled as legitimate or phishing having 111 features and allow the researchers to train their classification models, build phishing detection systems.
Research Paper link - https://www.sciencedirect.com/science/article/pii/S2352340920313202
Dataset link - https://data.mendeley.com/datasets/72ptz43s9v/1

## Conclusion
#### This project harnesses data-driven techniques, feature extraction, and machine learning to create a robust tool for detecting and guarding against phishing domains. The XGBoost model, trained on a diverse dataset, holds the potential to offer real-time, dependable protection against malicious websites, thereby enhancing the safety of online experiences for users. The results from phishing domain detection, utilizing the random forest model, are highly promising, showcasing an accuracy rate of 96.7%, precision of 95%. These metrics reflect the model's outstanding performance in accurately identifying phishing domains. They affirm the model's high accuracy in recognizing malicious domains and its reliability in distinguishing whether a domain is involved in phishing activities or not. Overall, this model serves as a valuable tool for shielding users against phishing threats. Its exceptional accuracy and precision make it a compelling choice for deployment in real-world scenarios. 
