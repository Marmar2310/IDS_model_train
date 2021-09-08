from pickle import load

from nfstream import NFStreamer
import random
import pandas as pd
from deploy import columns

online_streamer = NFStreamer(source='KakaoTalk_talk.pcap')
pipeline = load(open("Adaboost_model.sav","rb"))

for flow in online_streamer:
    d = {'duration': flow.bidirectional_duration_ms, 'protocol_type': random.randint(0,2),
         'service': random.randint(0,69),'flag': random.randint(1,10),
         'src_bytes': flow.src2dst_bytes,'dst_bytes': flow.dst2src_bytes,
         'land': random.randint(0,1),'wrong_fragment': random.randint(0,3),
         'urgent': random.randint(0,3), 'hot': random.randint(0,101),
         'num_failed_logins': random.randint(0,4), 'logged_in': random.randint(0,1),
         'num_compromised': random.randint(0,796), 'root_shell': random.randint(0,1),
         'su_attempted': random.randint(0,2), 'num_root': random.randint(0,878),
         'num_file_creations': random.randint(0,100), 'num_shells': random.randint(0,5),
         'num_access_files': random.randint(0,4), 'num_outbound_cmds': 0,
         'is_host_login': random.randint(0,1), 'is_guest_login': random.randint(0,1),
         'count': random.randint(0,511), 'srv_count': random.randint(0,511),
         'serror_rate': random.uniform(0,1), 'srv_serror_rate': random.uniform(0,1),
         'rerror_rate': random.uniform(0,1), 'srv_rerror_rate': random.uniform(0,1),
         'same_srv_rate': random.uniform(0,1), 'diff_srv_rate': random.uniform(0,1),
         'srv_diff_host_rate': random.uniform(0,1), '': random.randint(0,255),
         'dst_host_srv_count': random.randint(0,255), 'dst_host_same_srv_rate': random.uniform(0,1),
         'dst_host_diff_srv_rate': random.uniform(0,1), 'dst_host_same_src_port_rate': random.uniform(0,1),
         'dst_host_srv_diff_host_rate': random.uniform(0,1), 'dst_hostdst_host_count_serror_rate': random.uniform(0,1),
         'dst_host_srv_serror_rate': random.uniform(0,1), 'dst_host_rerror_rate': random.uniform(0,1),
         'dst_host_srv_rerror_rate': random.uniform(0,1)}
    netflow = pd.DataFrame(index=[0],data=d)
    netflow.insert(len(d)-1,'attack','Nan',True)
    netflow['attack'] = pipeline.predict(netflow.drop(columns=['attack']))
    print(netflow)
print(online_streamer.to_pandas())
