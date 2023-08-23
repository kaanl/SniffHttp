import tkinter as tk # tkinter kütüphanesinden tk kısaltmasını kullanıyoruz
from scapy.layers import http # scapy kütüphanesinin http modülünü çağırıyoruz
from scapy.all import sniff, IP # scapy kütüphanesinin alt modülü olan sniff ve ıp modüllerini çağırırız
import argparse #argparse modülünü getirir argparse( kullanıcının girdilerini analiz eder)
import threading #threading aynı anda birden fazla işi yapmamızı sağlayan modüldür
from tkinter import filedialog #filedialog dosya seçme ile igili işlemler için kullanılır

class Application: #application adında bir sınıf oluşturduk
    def __init__(self, root): # init metodu bir sınıfın özelliklerinin başlatılması ve örnek verilerinin atanması için kullanılır
                              # self(sınıfın içinde tanımlı olan özellikleri belirtir)
                              # root(pencere üzerindeki bileşenlerin düzenlenmesi ve yönetimi için kullanılır)
        self.root = root # sınıfın içine root örneği atarız ve bu örneğe root değerini veririz 
        self.root.geometry("800x600") # 800*600 lük bir pencere oluştururuz
        self.root.title('Akış Kayıt Paneli') # bu pencerenin üst panelinde görünecek yazıyı yazarız
        self.ms_font1 = ('times', 18, 'bold') # örneklerin yazı özelliklerini seçeriz

        self.l1 = tk.Label(root, text='Dosya Kayıt Ve İzleme Sistemi', width=30, font=self.ms_font1)
        self.l1.grid(row=1, column=1) # label(bir etiket oluşturur),widh(panelin genişliği ayarlanır), grid(pencere konumlandırma için kullanılır) 

        self.t1 = tk.Text(root, width=80, height=20)# burada bir metin kutucuğu açıyoruz kaynak ve hedef ip lerimiz burada görünecektir
        self.t1.grid(row=2, column=1)

        self.b1 = tk.Button(root, text='kayit', command=self.save_file, width=20)# burada bir kayıt butonu açtık save_file fonksiyonu ile kayıt edeceğimiz yeri fiziken seçebiliyoruz
        self.b1.grid(row=3, column=1)

        self.b2 = tk.Button(root, text='exit', command=self.root.destroy, width=20)#çıkış butonu destroy komutu sayfayı kapatmaya yarar
        self.b2.grid(row=4, column=1)

        self.listen_thread = threading.Thread(target=self.listen_traffic)#threading modülünü kullanarak çalıştırılacak iş parçacığını belirtir
        self.listen_thread.daemon = True  # iş parçacığını arka planda çalıştıran ve program sonlandığında sona ermesini sağlar
        self.listen_thread.start() #iş parçacığını başlatır

    def save_file(self): # burada dosya kayıt fonksiyonunu tanımlıyoruz
        content = self.t1.get("1.0", tk.END) # t1 adlı metin kutusunun içindeki verileri baştan sona alır content adlı değişkende saklarız
        file = filedialog.asksaveasfile(filetypes=[('text file', '*.txt')], defaultextension='.txt', title='yakalananları kayıt et')
        # kullanıcının bir dosyayı belirli konumda kaydetmesini sağlar asksaveasfile(kaydetme konumunu seçmenizi sağlar) 
        # filedialog(dosya seçme ve kaydetme iletişim pencerelerini oluşturmanızı sağlar.)
        if file:                     #
            file.write(content)      # dosya seçilmişse content içeriği yazılır ve dosya kapatılır
            file.close()             #

    def get_interface(self): #get_interface adında bir fonksiyon tanımlanıyor
        parser = argparse.ArgumentParser() #komut satırı argümanlarını işlemek için kullanılır
        parser.add_argument("-i", "--interface", dest="interface", help="arayüzün nerede olduğunu belirtin")#-i veya --interface
        #parametreleri ile argüman alınabileceği belirtiliyor argümanın değeri interface adlı bir değişkene atılacak
        arguments = parser.parse_args()# bu nesne içerisinde argüman değeri saklanır
        return arguments.interface # argümanın değeri (interface) döndürülüyor

    def listen_traffic(self): # listen_trafic fonksiyonu tanımlanır
        iface = self.get_interface()#iface get_interfaceden ağ arayüzü bilgisini alır
        sniff( iface= iface,store=False, prn=self.process_packet)# ağ arayüzünü dinleyerek yakalanan paketleri işlemek üzere proces_packet
        #işlevi kullanılır ayrıca yakalanan paketler bellekte saklanmaz 

    def process_packet(self, packet): #process_packet tanımlanıyor
        request_info = "" # boş metin dizisi oluşturuluyor

        if IP in packet: # eğer pakette ıp katmanı varsa
            src_ip = packet[IP].src # kaynak ıp adresini src_ıp değişkenine atar
            dst_ip = packet[IP].dst # kedef ıp adrresini dst_ıp değişkenine atar

            if packet.haslayer(http.HTTPRequest):
                url = packet[http.HTTPRequest].Host.decode("utf-8")
                path = packet[http.HTTPRequest].Path.decode("utf-8")
                method = packet[http.HTTPRequest].Method.decode("utf-8")
                request_info = f"Method: {method} URL: {url}{path}"

            output = f"Kaynak IP: {src_ip}  Hedef IP: {dst_ip}  {request_info}\n" # output adlı bir metin oluşturuluyor işlenmiş paket 
            #bilgileri bulunuyor
            self.t1.insert(tk.END, output) #"t1" adlı bir metin kutusu bileşenine "output" metni ekleniyor
            self.t1.see(tk.END)  # Metin sonuna kaydırma.

if __name__ == "__main__": # bu betik ana program olarak çalıştırılıyorsa aşağıdaki kod çalışır
    ms_w = tk.Tk() #  tkinterin ana penceresi oluşur
    app = Application(ms_w) #application sınıfında örnek oluşturup ms_wyi içine aktarıyoruz
    ms_w.mainloop()# ana döngü başlar

