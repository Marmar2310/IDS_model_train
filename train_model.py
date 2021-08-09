import pickle
import pandas as pd
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score, f1_score, recall_score, \
    precision_score
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import AdaBoostClassifier, RandomForestClassifier
from xgboost import XGBClassifier
from catboost import CatBoostClassifier
from lightgbm import LGBMClassifier
from sklearn.pipeline import Pipeline

columns = (['duration'
    , 'protocol_type'
    , 'service'
    , 'flag'
    , 'src_bytes'
    , 'dst_bytes'
    , 'land'
    , 'wrong_fragment'
    , 'urgent'
    , 'hot'
    , 'num_failed_logins'
    , 'logged_in'
    , 'num_compromised'
    , 'root_shell'
    , 'su_attempted'
    , 'num_root'
    , 'num_file_creations'
    , 'num_shells'
    , 'num_access_files'
    , 'num_outbound_cmds'
    , 'is_host_login'
    , 'is_guest_login'
    , 'count'
    , 'srv_count'
    , 'serror_rate'
    , 'srv_serror_rate'
    , 'rerror_rate'
    , 'srv_rerror_rate'
    , 'same_srv_rate'
    , 'diff_srv_rate'
    , 'srv_diff_host_rate'
    , 'dst_host_count'
    , 'dst_host_srv_count'
    , 'dst_host_same_srv_rate'
    , 'dst_host_diff_srv_rate'
    , 'dst_host_same_src_port_rate'
    , 'dst_host_srv_diff_host_rate'
    , 'dst_host_serror_rate'
    , 'dst_host_srv_serror_rate'
    , 'dst_host_rerror_rate'
    , 'dst_host_srv_rerror_rate'
    , 'attack'
    , 'level'])

data_train = pd.read_csv("KDD_NLS_Dataset/KDDTrain+.txt")
# data_test = pd.read_csv("KDD_NLS_Dataset/KDDTest+.txt")
data_train.columns = columns
# data_test.columns = columns
print(data_train)

print(data_train['protocol_type'])
for x in data_train['protocol_type']:
    if x == 'tcp':
        x = 0
    elif x == 'udp':
        x = 1
    else:
        x = 2

cleanup_nums = {"protocol_type": {"tcp": 0, "udp": 1, "icmp": 2},
                "service": {'aol': 0, 'auth': 1, 'bgp': 2, 'courier': 3, 'csnet_ns': 4, 'ctf': 5,
                            'daytime': 6, 'discard': 7, 'domain': 8, 'domain_u': 9, 'echo': 10,
                            'eco_i': 11, 'ecr_i': 12, 'efs': 13, 'exec': 14, 'finger': 15, 'ftp': 16,
                            'ftp_data': 17, 'gopher': 18, 'harvest': 19, 'hostnames': 20, 'http': 21,
                            'http_2784': 22, 'http_443': 23, 'http_8001': 24, 'imap4': 25, 'IRC': 26,
                            'iso_tsap': 27, 'klogin': 28, 'kshell': 29, 'ldap': 30, 'link': 31,
                            'login': 32, 'mtp': 33, 'name': 34, 'netbios_dgm': 35, 'netbios_ns': 36,
                            'netbios_ssn': 37, 'netstat': 38, 'nnsp': 39, 'nntp': 40, 'ntp_u': 41,
                            'other': 42, 'pm_dump': 43, 'pop_2': 44, 'pop_3': 45, 'printer': 46,
                            'private': 47, 'red_i': 48, 'remote_job': 49, 'rje': 50, 'shell': 51,
                            'smtp': 52, 'sql_net': 53, 'ssh': 54, 'sunrpc': 55, 'supdup': 56,
                            'systat': 57, 'telnet': 58, 'tftp_u': 59, 'tim_i': 60, 'time': 61,
                            'urh_i': 62, 'urp_i': 63, 'uucp': 64, 'uucp_path': 65, 'vmnet': 66,
                            'whois': 67, 'X11': 68, 'Z39_50': 69},
                "flag": {'OTH': 0, 'REJ': 1, 'RSTO': 2, 'RSTOS0': 3, 'RSTR': 4,
                         'S0': 5, 'S1': 6, 'S2': 7, 'S3': 8, 'SF': 9, 'SH': 10}}

data_train = data_train.replace(cleanup_nums)
print(data_train['protocol_type'])
print(data_train['flag'])
print(data_train['service'])

df_x = data_train.drop(columns=['attack', 'level'])
df_y = data_train['attack']
x_train, x_test, y_train, y_test = train_test_split(df_x, df_y, test_size=0.2)

DT_pipeline = Pipeline(steps=[('DT', DecisionTreeClassifier(random_state=42))])
# KNN_pipeline = Pipeline(steps=[('KNN', KNeighborsClassifier())])
# logreg_pipeline = Pipeline(steps=[('LR', LogisticRegression(random_state=42))])
# svm_pipeline = Pipeline(steps=[('scale', StandardScaler()), ('SVM', SVC(random_state=42))])
# XGBOOST = XGBClassifier(random_state=42)
# rf_pipeline = Pipeline(steps=[('RF', RandomForestClassifier(random_state=42))])
# Catboost = CatBoostClassifier(logging_level='Silent')
# LightGBM = LGBMClassifier(random_state=42)
Adaboost = AdaBoostClassifier(base_estimator=DecisionTreeClassifier(), n_estimators=100, learning_rate=0.5,
                              random_state=100)
print("pipelines are done")

DT_pipeline.fit(x_train, y_train)
# KNN_pipeline.fit(x_train, y_train)
# rf_pipeline.fit(x_train, y_train)
# svm_pipeline.fit(x_train, y_train)
# logreg_pipeline.fit(x_train, y_train)
# XGBOOST.fit(x_train, y_train)
# Catboost.fit(x_train, y_train)
# LightGBM.fit(x_train, y_train)
Adaboost.fit(x_train, y_train)
print("model fitting is done")

DT_pred = DT_pipeline.predict(x_test)
# KNN_pred = KNN_pipeline.predict(x_test)
# logreg_pred = logreg_pipeline.predict(x_test)
# rf_pred = rf_pipeline.predict(x_test)
# svm_pred = svm_pipeline.predict(x_test)
# XGB_pred = XGBOOST.predict(x_test)
# Catboost_pred = Catboost.predict(x_test)
# LightGBM_pred = LightGBM.predict(x_test)
Adaboost_pred = Adaboost.predict(x_test)
print("predictions are done")

DT_cm = confusion_matrix(y_test, DT_pred)
# KNN_cm = confusion_matrix(y_test, KNN_pred)
# logreg_cm = confusion_matrix(y_test, logreg_pred)
# rf_cm = confusion_matrix(y_test, rf_pred)
# svm_cm = confusion_matrix(y_test, svm_pred)
# XGB_cm = confusion_matrix(y_test, XGB_pred)
# Catboost_cm = confusion_matrix(y_test, Catboost_pred)
# LightGBM_cm = confusion_matrix(y_test, LightGBM_pred)
Adaboost_cm = confusion_matrix(y_test, Adaboost_pred)
print("confusion matrices")

print(classification_report(y_test, Adaboost_pred))
print('Accuracy Score: ', accuracy_score(y_test, Adaboost_pred))
print('F1 Score: ', f1_score(y_test, Adaboost_pred, average='weighted'))
print('Recall Score: ', recall_score(y_test, Adaboost_pred, average='weighted'))
print('Precision: ', precision_score(y_test, Adaboost_pred, average='weighted'))

print(classification_report(y_test, DT_pred))
print('Accuracy Score: ', accuracy_score(y_test, DT_pred))
print('F1 Score: ', f1_score(y_test, DT_pred, average='weighted'))
print('Recall Score: ', recall_score(y_test, DT_pred, average='weighted'))
print('Precision: ', precision_score(y_test, DT_pred, average='weighted'))

DT_filename = "DT_model.sav"
pickle.dump(DT_pipeline, open(DT_filename, "wb"))
Adaboost_filename = "Adaboost_model.sav"
pickle.dump(Adaboost, open(Adaboost_filename, "wb"))
