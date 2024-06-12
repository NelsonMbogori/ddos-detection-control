<<<<<<< HEAD
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

import switchm
from datetime import datetime

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score

class SimpleMonitor13(switchm.SimpleSwitch13):

    def __init__(self, *args, **kwargs):

        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        start = datetime.now()

        self.flow_training()

        end = datetime.now()
        print("Training time: ", (end-start))

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
=======
import csv
from collections import defaultdict
import os
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.ofproto import ofproto_v1_3
from ryu.base import app_manager
# from ryu.controller import ofp_event
# from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
# from ryu.controller.handler import set_ev_cls
# from ryu.lib import hub 
# from sklearn.neighbors import KNeighborsClassifier
# import pandas as pd
import joblib

class SimpleMonitor13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.flow_stats_file = 'PredictFlowStatsfile.csv'
        self.knn = KNeighborsClassifier(n_neighbors=3)
        self.train_data = None
        self.train_target = None
        self._load_training_data()
        self._flow_training()

    def _load_training_data(self):
        # Load training data
        self.train_data = pd.read_csv('Trainfile.csv')
        self.train_target = self.train_data['label']
        self.train_data = self.train_data.drop(columns=['label'])

    def _flow_training(self):
        # Train the KNN model
        self.knn.fit(self.train_data, self.train_target)
        # Save the model
        joblib.dump(self.knn, 'knn_model.pkl')

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
>>>>>>> 8ae5f11705b5dead16206668dfe5d9d0f068374b
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
<<<<<<< HEAD
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
=======
                self.logger.info('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == CONFIG_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('unregister datapath: %016x', datapath.id)
>>>>>>> 8ae5f11705b5dead16206668dfe5d9d0f068374b
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
<<<<<<< HEAD
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

            self.flow_predict()

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):

        timestamp = datetime.now()
        timestamp = timestamp.timestamp()

        file0 = open("PredictFlowStatsfile.csv","w")
        file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')
        body = ev.msg.body
        icmp_code = -1
        icmp_type = -1
        tp_src = 0
        tp_dst = 0

        for stat in sorted([flow for flow in body if (flow.priority == 1) ], key=lambda flow:
            (flow.match['eth_type'],flow.match['ipv4_src'],flow.match['ipv4_dst'],flow.match['ip_proto'])):
        
            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            ip_proto = stat.match['ip_proto']
            
            if stat.match['ip_proto'] == 1:
                icmp_code = stat.match['icmpv4_code']
                icmp_type = stat.match['icmpv4_type']
                
            elif stat.match['ip_proto'] == 6:
                tp_src = stat.match['tcp_src']
                tp_dst = stat.match['tcp_dst']

            elif stat.match['ip_proto'] == 17:
                tp_src = stat.match['udp_src']
                tp_dst = stat.match['udp_dst']

            flow_id = str(ip_src) + str(tp_src) + str(ip_dst) + str(tp_dst) + str(ip_proto)
          
            try:
                packet_count_per_second = stat.packet_count/stat.duration_sec
                packet_count_per_nsecond = stat.packet_count/stat.duration_nsec
            except:
                packet_count_per_second = 0
                packet_count_per_nsecond = 0
                
            try:
                byte_count_per_second = stat.byte_count/stat.duration_sec
                byte_count_per_nsecond = stat.byte_count/stat.duration_nsec
            except:
                byte_count_per_second = 0
                byte_count_per_nsecond = 0
                
            file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                .format(timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src,ip_dst, tp_dst,
                        stat.match['ip_proto'],icmp_code,icmp_type,
                        stat.duration_sec, stat.duration_nsec,
                        stat.idle_timeout, stat.hard_timeout,
                        stat.flags, stat.packet_count,stat.byte_count,
                        packet_count_per_second,packet_count_per_nsecond,
                        byte_count_per_second,byte_count_per_nsecond))
            
        file0.close()

    def flow_training(self):

        self.logger.info("Flow Training ...")

        flow_dataset = pd.read_csv('dataset.csv')

        flow_dataset.iloc[:, 2] = flow_dataset.iloc[:, 2].str.replace('.', '')
        flow_dataset.iloc[:, 3] = flow_dataset.iloc[:, 3].str.replace('.', '')
        flow_dataset.iloc[:, 5] = flow_dataset.iloc[:, 5].str.replace('.', '')

        X_flow = flow_dataset.iloc[:, :-1].values
        X_flow = X_flow.astype('float64')

        y_flow = flow_dataset.iloc[:, -1].values

        X_flow_train, X_flow_test, y_flow_train, y_flow_test = train_test_split(X_flow, y_flow, test_size=0.25, random_state=0)

        classifier = KNeighborsClassifier(n_neighbors=5, metric='minkowski', p=2)
        self.flow_model = classifier.fit(X_flow_train, y_flow_train)

        y_flow_pred = self.flow_model.predict(X_flow_test)
        y_flow_pred_train = self.flow_model.predict(X_flow_train)

        self.logger.info("------------------------------------------------------------------------------")

        self.logger.info("Confusion Matrix")
        cm = confusion_matrix(y_flow_test, y_flow_pred)
        self.logger.info(cm)

       #acc = accuracy_score(y_flow_test, y_flow_pred)

       # acc_train = accuracy_score(y_flow_train, y_flow_pred_train)
       # print("Training Accuracy: ",acc_train)

       # self.logger.info("Succes Accuracy = {0:.2f} %".format(acc*100))
       # fail = 1.0 - acc
       # self.logger.info("Fail Accuracy = {0:.2f} %".format(fail*100))
       # self.logger.info("------------------------------------------------------------------------------")

    def flow_predict(self):
        try:
            predict_flow_dataset = pd.read_csv('PredictFlowStatsfile.csv')

            predict_flow_dataset.iloc[:, 2] = predict_flow_dataset.iloc[:, 2].str.replace('.', '')
            predict_flow_dataset.iloc[:, 3] = predict_flow_dataset.iloc[:, 3].str.replace('.', '')
            predict_flow_dataset.iloc[:, 5] = predict_flow_dataset.iloc[:, 5].str.replace('.', '')

            X_predict_flow = predict_flow_dataset.iloc[:, :].values
            X_predict_flow = X_predict_flow.astype('float64')
            
            y_flow_pred = self.flow_model.predict(X_predict_flow)

            legitimate_trafic = 0
            ddos_trafic = 0

            for i in y_flow_pred:
                if i == 0:
                    legitimate_trafic = legitimate_trafic + 1
                else:
                    ddos_trafic = ddos_trafic + 1
                    victim = int(predict_flow_dataset.iloc[i, 5])%20
                    
                    
                    

            self.logger.info("------------------------------------------------------------------------------")
            if (legitimate_trafic/len(y_flow_pred)*100) > 80:
                self.logger.info("Traffic is Legitimate!")
            else:
                self.logger.info("NOTICE!! DoS Attack in Progress!!!")
                self.logger.info("Victim Host: h{}".format(victim))
                print("Mitigation process in progress!")
                self.mitigation = 1

            self.logger.info("------------------------------------------------------------------------------")
            
            file0 = open("PredictFlowStatsfile.csv","w")
            
            file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n')
            file0.close()

        except:
            pass
=======
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(10)

    # def _request_stats(self, datapath):
    #     self.logger.debug('send stats request: %016x', datapath.id)
    #     ofproto = datapath.ofproto
    #     parser = datapath.ofproto_parser

    #     req = parser.OFPFlowStatsRequest(datapath)
    #     datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        data = []
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)
            data.append({
                'datapath_id': ev.msg.datapath.id,
                'in_port': stat.match['in_port'],
                'eth_dst': stat.match['eth_dst'],
                'out_port': stat.instructions[0].actions[0].port,
                'packet_count': stat.packet_count,
                'byte_count': stat.byte_count,
                'packet_count_per_second': stat.packet_count / stat.duration_sec if stat.duration_sec > 0 else 0,
                'byte_count_per_second': stat.byte_count / stat.duration_sec if stat.duration_sec > 0 else 0,
                'flow_duration_sec': stat.duration_sec,
                'flow_duration_nsec': stat.duration_nsec,
                'ip_src': stat.match.get('ipv4_src', '0.0.0.0'),
                'ip_dst': stat.match.get('ipv4_dst', '0.0.0.0'),
                'tp_src': stat.match.get('tcp_src', stat.match.get('udp_src', 0)),
                'tp_dst': stat.match.get('tcp_dst', stat.match.get('udp_dst', 0)),
                'ip_proto': stat.match.get('ip_proto', 0),
                'icmp_type': stat.match.get('icmpv4_type', 0),
                'icmp_code': stat.match.get('icmpv4_code', 0),
                'timestamp': ev.msg.xid
            })
        
        with open(self.flow_stats_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
        
        self._predict_flows()

    def _predict_flows(self):
        data = pd.read_csv(self.flow_stats_file)
        X = data.drop(columns=['datapath_id', 'in_port', 'eth_dst', 'out_port', 'timestamp'])
        predictions = self.knn.predict(X)
        victim_host = defaultdict(int)

        attack_details = []

        for i, pred in enumerate(predictions):
            if pred == 'attack':
                victim_ip = data.iloc[i]['ip_dst']
                victim_host[victim_ip] += 1
                attack_details.append(data.iloc[i])

        if attack_details:
            most_common_victim = max(victim_host, key=victim_host.get)
            report = {
                'Victim Host': most_common_victim,
                'Attack Sources': defaultdict(set),
                'Protocols Used': defaultdict(int),
                'Packet Rate': 0,
                'Byte Rate': 0,
                'Duration': {
                    'Seconds': 0,
                    'Nanoseconds': 0
                },
                'Pattern': 'Continuous high-volume traffic'
            }

            for detail in attack_details:
                report['Attack Sources']['IPs'].add(detail['ip_src'])
                report['Attack Sources']['Ports'].add(f"{'TCP' if detail['ip_proto'] == 6 else 'UDP'}/{detail['tp_dst']}")
                report['Protocols Used']['TCP' if detail['ip_proto'] == 6 else 'UDP'] += 1
                report['Packet Rate'] += detail['packet_count_per_second']
                report['Byte Rate'] += detail['byte_count_per_second']
                report['Duration']['Seconds'] += detail['flow_duration_sec']
                report['Duration']['Nanoseconds'] += detail['flow_duration_nsec']

            total_attacks = len(attack_details)
            report['Packet Rate'] /= total_attacks
            report['Byte Rate'] /= total_attacks
            report['Protocols Used'] = {k: (v / total_attacks) * 100 for k, v in report['Protocols Used'].items()}

            with open('report.txt', 'w') as report_file:
                report_file.write("Detected DDoS Attack Details\n")
                report_file.write(f"Victim Host: {report['Victim Host']}\n")
                report_file.write("Attack Sources:\n")
                report_file.write("Source IPs:\n")
                for ip in report['Attack Sources']['IPs']:
                    report_file.write(f"{ip}\n")
                report_file.write("Source Ports:\n")
                for port in report['Attack Sources']['Ports']:
                    report_file.write(f"{port}\n")
                report_file.write("Protocols Used:\n")
                for proto, percentage in report['Protocols Used'].items():
                    report_file.write(f"{proto}: {percentage:.2f}%\n")
                report_file.write("Traffic Characteristics:\n")
                report_file.write(f"Packet Rate: {report['Packet Rate']:.2f} packets/second\n")
                report_file.write(f"Byte Rate: {report['Byte Rate']:.2f} bytes/second\n")
                report_file.write("Duration:\n")
                report_file.write(f"Seconds: {report['Duration']['Seconds']}\n")
                report_file.write(f"Nanoseconds: {report['Duration']['Nanoseconds']}\n")
                report_file.write(f"Pattern: {report['Pattern']}\n")
                report_file.write("Mitigation Actions:\n")
                report_file.write("Blocked Source IPs:\n")
                for ip in report['Attack Sources']['IPs']:
                    report_file.write(f"{ip}\n")
                report_file.write("Applied Rate Limiting\n")
>>>>>>> 8ae5f11705b5dead16206668dfe5d9d0f068374b
