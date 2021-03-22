from tkinter import *
from scapy.all import *
import json
import matplotlib.pyplot as plt
from scapy.layers.inet import TCP, UDP

#   !!!!Pentru o functionare optima inchideti fereastra cu graficul, respectiv fisierul json inainte de a face o noua
#   captura


class Captura:
    _instance = None

    @staticmethod
    def getCaptura(self):
        if Captura._instance is None:
            Captura(self)
        return Captura._instance

    def __init__(self, master):
        frame = Frame(master)
        frame.grid()
        self.num_tcp = 0
        self.num_udp = 0

        self.first_button = Button(frame, text='Start capture  ', font=('Courier', 10),
                                   command=self.capture_function)
        self.first_button.grid(row=0, column=0)

        self.first_label = Label(frame, text='Filter (optional):')
        self.first_label.grid(row=0, column=1)

        self.first_entry = Entry(frame)
        self.first_entry.grid(row=0, column=2)

        self.second_button = Button(frame, text='Save as JSON   ', font=('Courier', 10),
                                    command=self.save_function)
        self.second_button.grid(row=1, column=0)

        self.second_label = Label(frame, text='Type the path:')
        self.second_label.grid(row=1, column=1)

        self.second_entry = Entry(frame)
        self.second_entry.grid(row=1, column=2)

        self.third_button = Button(frame, text='Show statistics', font=('Courier', 10),
                                   command=self.show_function)
        self.third_button.grid(row=2, column=0)

        if Captura._instance is not None:
            raise Exception('This class is a singleton!')
        else:
            Captura._instance = self

    def capture_function(self):
        global capture
        self.num_tcp = 0
        self.num_udp = 0
        my_filter = self.first_entry.get()
        self.first_entry.delete(0, END)
        if my_filter:
            capture = sniff(count=100, filter=my_filter)
        else:
            capture = sniff(count=100)

        for package in capture:
            if TCP in package:
                self.num_tcp += 1
            if UDP in package:
                self.num_udp += 1
        label1 = Label(root_window, text='Pachetele capturate sunt %s de tip TCP si %s de tip UDP '
                                         % (self.num_tcp, self.num_udp))
        label1.grid(row=3, column=0)

    def save_function(self):
        path = self.second_entry.get()
        self.second_entry.delete(0, END)
        json_file = path + '\\json_file.json'

        lista_pachete = []
        for pachet in capture:

            if pachet.haslayer('TCP'):
                lista_pachete.append(
                    Pachet(pachet['Ethernet'].dst, pachet['Ethernet'].src, pachet['IP'].dst, pachet['IP'].src,
                           pachet['IP'].version, pachet['IP'].proto, pachet['TCP'].sport, pachet['TCP'].dport, "-",
                           "-"))

            elif pachet.haslayer('UDP'):
                lista_pachete.append(
                    Pachet(pachet['Ethernet'].dst, pachet['Ethernet'].src, pachet['IP'].dst, pachet['IP'].src,
                           pachet['IP'].version, pachet['IP'].proto, "-", "-", pachet['UDP'].sport,
                           pachet['UDP'].dport))
        for obj in lista_pachete:
            print(obj)
        json_final = []
        with open(json_file, 'w') as g:
            for pachet in lista_pachete:
                json_final.append(json.dump(pachet.__str__().split("\n"), g, ensure_ascii=False, indent=4))

    def show_function(self):
        slices = [self.num_tcp, self.num_udp]
        packages = ['TCP', 'UDP']
        cols = ['#8248BB', '#1CAF7C']
        plt.pie(slices, labels=packages, colors=cols, startangle=90, autopct='%.2f%%')
        plt.title('Package Statistics')
        plt.show()


class Pachet:

    def __init__(self, ethernet_dst, ethernet_src, ip_dst, ip_src, ip_version, ip_proto, TCP_sport,
                 TCP_dport, UDP_sport, UDP_dport):
        self.ethernet_dst = ethernet_dst
        self.ethernet_src = ethernet_src
        self.ip_dst = ip_dst
        self.ip_src = ip_src
        self.ip_version = ip_version
        self.ip_proto = ip_proto
        self.TCP_sport = TCP_sport
        self.TCP_dport = TCP_dport
        self.UDP_sport = UDP_sport
        self.UDP_dport = UDP_dport

    def __str__(self):
        if self.ip_proto == 6:
            return "{'Ethernet':{src:'" + str(self.ethernet_src) + "',\n\t\t\t dst:'" + str(self.ethernet_dst) + "',\n\t\t\t} \
                    \n 'IP':{src:'" + str(self.ip_src) + "',\n\t   dst:'" + str(self.ethernet_dst) + "',\n\t   version:" \
                                                                                                     "'" + str(
                self.ip_version) + "',\n\t   proto:'" + str(self.ip_proto) + "',\n\t  }\n'TCP':{TCP_sport:" \
                                                                             "'" + str(
                self.TCP_sport) + "',\n\t  TCP_dport:'" + str(self.TCP_dport) + "',\n\t  }\n}"
        elif self.ip_proto == 17:
            return "{'Ethernet':{src:'" + str(self.ethernet_src) + "',\n\t\t\t dst:'" + str(self.ethernet_dst) + "',\n\t\t\t} \
                                \n 'IP':{src:'" + str(self.ip_src) + "',\n\t   dst:'" + str(
                self.ethernet_dst) + "',\n\t   version:" \
                                     "'" + str(self.ip_version) + "',\n\t   proto:'" + str(
                self.ip_proto) + "',\n\t  }\n'UDP':{UDP_sport:" \
                                 "'" + str(self.UDP_sport) + "',\n\t  UDP_dport:'" + str(
                self.UDP_dport) + "',\n\t  }\n}"


root_window = Tk()
root_window.title("Project")
root_window.geometry('500x150')
c = Captura(root_window)

root_window.mainloop()
