from pickle import load
from flask import Flask, render_template, request, redirect, url_for
import pandas as pd

# from train_model import columns

pipeline = load(open("Adaboost_model.sav", "rb"))

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


def predictAttacks(dataset):
    test = pd.read_csv(dataset)
    test.columns = columns
    test = test.replace(cleanup_nums)
    test2 = pd.read_csv(dataset)
    test2.columns = columns
    test2 = test2.replace(cleanup_nums)
    test['attack'] = pipeline.predict(test.drop(columns=['attack', 'level']))
    test.to_csv('out.csv')
    print(test)
    print(test2)
    print(test.compare(test2))
    # data = str(test.prediction.value_counts()) + '\n\n'
    return str(test)


app = Flask(__name__)


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/', methods=['POST', 'GET'])
def get_data():
    if request.method == 'POST':
        upload_file = request.form["file"]
        return redirect(url_for('success', dataset=upload_file))


@app.route('/success/<dataset>')
def success(dataset):
    return "<xmp>" + str(predictAttacks(dataset)) + "</xmp>"


if __name__ == '__main__':
    app.run(debug=True)
