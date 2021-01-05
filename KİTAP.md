 



![1](https://user-images.githubusercontent.com/66878884/103525824-efc73880-4e90-11eb-9745-b719886d1826.jpg)





LINUX


















setxkbmap us(tr): Klavye dili değiştirir.

pwd: Hangi klasör içindeyiz onu gösterir.

ls: İçinde olduğumuz klasörün içinde görünen klasör ve dosyaları gösterir.

ls  -la: Ls’te görünmeyen detaylı dosyaları gösterir.

cd: Klasörün içine girmeye yarar.(cd Desktop/)

mkdir: Dizin içine yeni dosya açmaya yarar.

cd .. :Bir geri klasöre gider.

clear: Terminal ekranını temizler.

apt-get update: Linux sunucuna gerekli güncellemeleri yapar.

apt-get upgrade: Yapılan güncellemeleri sisteme yükler.

passwd: Şifreyi değiştirir.

ifconfig: ip’leri gösterir.

inet: İp’mizi gösterir.

ping google.com: İstenilen siteye ufak ufak istekler yapar, sitenin veya sunucunun bağlı olup olmadığını anlamamıza yarar.

unzip …. : Zipli dosyaları zip dosyası içinden çıkarır.

openvpn: İndirilen dosyayı (ovpn vs.) vpn’e bağlar.

cat: Herhangi bir dosyanın içeriğini okumamıza yarar. (cat/etc/resolv.conf=Kullanılan dns’i gösterir.)

nano: Txt, .c gibi veya başka uzantılı metin dizisi oluşturmamıza yarar.


MAC DEĞİŞTİRME
-ifconfig
  wlan0(ether=mac adı yazar)
-ifconfig wlan0down
-macchanger –random wlan0
-ifconfig wlan0up (MAC DEĞİŞMİŞ OLUR.)

DEĞİŞTİRDİKTEN SONRA MONİTÖR MODA GEÇMEK İÇİN;
-airmon-ng start wlan0(wlan0mon olduğu zaman monitör moda geçilmiş demektir.)

-iwconfig wlan0mod:Monitör modda olduğumuzu gösterir.
-airmon-ng stop wlan0mon(MONİTÖR MODU KAPATIR.)






MANUEL ŞEKİLDE MONİTOR MODA GEÇİŞ YAPIP – KAPATMAK
AÇMAK İÇİN
-ifconfig wlan0 down
-iwconfig wlan0mode monitör
-ifconfig wlan0 up
-iwconfig wlan0

KAPAMAK İÇİN
-ifconfig wlan0 down
-iwconfig wlan0mode managed
-ifconfig wlan0 up
-iwconfig wlan0

AĞLARI İNCELEMEK
-airodump-ng wlan0mon (ETRAFTA ULAŞABİLİR AĞLARI GÖSTERİR.)

-BSSID:MAC ADRESİDİR.  –PWR:SAYISI NE KADAR KÜÇÜKSE O KADAR YAKINDIR(-36 VS.)

	-BEACONS:SİNYAL.	 -#DATA:ELİMİZDE OLAN KULLANILABİLİR DATALAR.

	-CH:EN FAZLA KULLANILAN KANALI GÖSTERİR.     –ENC:VERİLERİN HANGİ ŞİFRELEME İLE ŞİFRELENDİĞİNİ GÖSTERİR.

	 ip_addr:Kendi adresimizi gösterir.

	BELLİ BİR AĞA ÖZEL BİLGİ EDİNMEK

	airodump-ng --channel (ch) --bssid (mac) –write test1 wlan0mon

Tarama tamamlanınca: ls test1 dosya gelir.(test1-01.cap uzantılı dosya gelir detaylı şekilde   incelenemesi yapılabilmesi için WİRESHARK uygulaması üzerinden açılıp bakılır.)

DEAUTHHENTICATION ATTACK (BELİRLİ KULLANICIYI AĞDAN ATMA)

aireplay-ng --deauth 1000(Gönderilecek saldırı sayısı) -a kendi bsssimiz -c station yerınde yazar wlan0mon


ŞİFRELEME MODELLERİ (ENCRYPTION/WEB/WPA/WPA2)
WEP CRACKING

-airodump-ng -channel <channel> -bssid <bssid> -write <file_name> <interface(mon0)>
-aircrack-ng <file_name>(aircrack-ng test01.cap) Şifreyi Bulunca[A1:B2:C3:D4](:’LARI KALDIR ŞİFRE)
 
WEP CRACKING-FAKE AUTH(SAHTE YETKİLENDİRME)
-aireplay-ng -fakeauth 0 -a <target-mac> -h <kali-mac> <interface>

-aireplay-ng --arpreplay -b <target-mac> -h <kali-mac> <interface>(ağa sızıp alıdığı paketleri enjekte eder.)


WPA SALDIRILARI(HANDSHAKE YAKALAMAK)
 	-airodump-ng --bssid <target-mac> --channel <channel> --write(isteğe bağlı) <interface>
	*Takibe alındığında kullanıcı girmesine beklenene kadar deauth saldırısı ile kendimizi          yetkilendirelim.

	WORDLIST YARATMAK(ŞİFRELERİN OLD. WORDLIST YARATIR)
            ./crunch <min> <max> <char> -t <pottern> - o file
	./crunch 8 10 123!é!’ -t m@@p -file wordlist

	
	BAĞLANTI SONRASI YAPILACAKLAR 
	-BAĞLANTI SONRASI AYARLAR-
 	DISCOVER
	-netdiscover -i <interface> -r <range>
	-netdiscover -i wlan0 -r 192.168.1.1/24

	NETDISCOVER 
	-netdiscover -r 10.0.2.10/24
	-nmap 10.0.2.0/24(daha detaylı sonuç)

	MAN IN THE MIDDLE(MITM)
	-arpspoof -i <interface> -t <target-IP> <AP-IP>
-arpspoof -i <interface> -t <AP-IP> <target-IP>

-arpspoof -i eth0 10.0.2.15 10.02.1
-arpspoof -i eth0(Başka birinin saldırı olacaksa wlan0 yazılır.) 10.0.2.1   10.0.2.15

*Windows’ta ipconfig yazınca mac adres ile altta diğer mac adresi aynıysa bir MITM saldırısı vardır.

MITM FREWORK(ALINAN VERİLERİN OKUNMASI)
-python mitm.py -i eth0 --arp --spoof --gateway 10.2.0.1(kendı-ip) --target 10.0.2.5
*Kendi pc’mizi sunucu olarak kullanabiliriz.
-start apache2 start(Linux içinde kendi sunucumuzu açar.Güncel ip ile.)(/var/www/html içindedir.)

-python kodunun sonuna --dns yazılınca dns saldırısı yapar.




BETTERCAP(yüklü değilse apt-get install bettercap)
-bettercap -iface eth0(kullanılan internet araç izi)
-net discover’da yaptığımız işleri yapmaya 

KABLOSUZ AĞ
Kablosuz Ağ Bağlanma Aşamaları Authentication(Kimlik doğrulama): Bir kullanıcı sisteminin AP’ye kimlik doğrulayarak ağa dahil olmasının ilk adımdır. Bu adımda iletilen frameler şifrelenmemektedir(Çünkü management framelerden birisidir). 2 çeşit kimlik doğrulama tanımlanmıştır: Open ve Shared Key.

 ● Open System Authentication: Bu tip kimlik doğrulamada istemciden içinde MAC adresinin olduğu bir istek gider ve AP’den isteğin kabul veya reddediğine dair bir cevap dönülür. 

● Shared Key Authentication: Kimlik doğrulama için ortak olarak bilinen bir anahtar(parola) kullanılır. Önce istemci AP’ye bir bağlantı isteğinde bulunur. AP kullanıcıya challenge text gönderir. İstemci bilinen anahtar bilgisiyle bu metini şifreler ve AP’ye gönderir. AP şifreli metini alır ve üzerinde belirlenen asıl anahtarla bu metinin şifresini çözer. Eğer şifresi çözülmüş olan metin, kullanıcıya ilk olarak gönderilen challenge text ile aynıysa parola doğru demektir. Kullanıcıya kimlik doğrulama için kabul veya ret içeren bir cevap dönülür.
Association (Ağa kayıt olma): İstemciler kimlik doğrulama adımını geçtikten sonra AP tarafından ağa kayıt edilmelidir(association). Bu işlem olmadan istemciden gelen/giden frameler AP tarafından yoksayılır. Bir istemci aynı anda sadece bir ağa kayıt olabilir ve kayıt işlemi sadece iletişim AP üzerinden gerçekleştiği Infrastructure modda gerçekleşir. İstemci association için bir istek gönderir, AP isteği değerlendirir ve olumlu yada olumsuz cevap döner. Eğer cevap olumluysa association cevabı içinde istemciyi daha sonra tanımak için atanan bir ID bulunur(Association ID(AID)).


![2](https://user-images.githubusercontent.com/66878884/103550702-5ca2f880-4eba-11eb-9913-f4957223930c.jpg)


 

WEP 
Hem şifreleme protokolünün hem de kimlik doğrulama işleminin adıdır. Bu güvenlik protokolünde ilk başlarda kısıtlamalardan dolayı 64 bitlik WEP key kullanılıyordu. 64 bitin, 24 biti verinin şifrelenmesi ve çözülmesi için kullanılan initialization vector(kısaca IV olarak anılır) ve 40 biti ise anahtardan(key) oluşur. Anahtar diye bahsedilen aslında o kablosuz ağ için girilen parola bilgisidir. 40 bitlik bir yer ayrıldığı için parola olarak en fazla 10 alfanumerik karakter kullanılabilir. Bu 64 bit, RC4 denilen kriptografik bir algoritmayla işleme sokulur ve başka bir değer elde edilir. Son olarak oluşturulan değer ve asıl veri XOR mantıksal işlemine sokulur. Böylece WEP koruması sağlanarak şifreli veri oluşturulur. Daha sonradan bazı kısıtlamalar kaldırılmış ve 128 bit,152 bit, 256 bit destekleyen WEP sistemleri bazı üreticiler tarafından sağlanmıştır. Bunlar içinde IV değeri 24 bittir.



![3](https://user-images.githubusercontent.com/66878884/103550708-5dd42580-4eba-11eb-846a-b9ce205e1f9c.jpg)

 

WPA/WPA2 WEP üzerindeki ciddi güvenlik zafiyetleri dolayısıyla geçici bir çözüm olarak, 2003 yılında 802.11 veri güvenliğinde ve şifreleme metodundaki geliştirmelerle ortaya çıkmıştır. TKIP şifreleme metodunu kullanan WPA tanıtılmıştır. Bu sadece geçici bir çözümdür. 2004 yılında ise 802.11i yayınlanmıştır. Bu yeni standartta veri güvenliği için AES şifreleme algoritması ve CCMP şifreleme metodunun kullanıldığı WPA2 ortaya çıkmıştır. Kimlik doğrulama metodu için ise 802.1X(kurumsal) ve Preshared Key(PSK)(kişisel ve küçük ölçekli kullanım için) metotları geliştirilmiştir. WPA2’de parolanın doğrulanma aşaması 4’lü el sıkışmayla(4 way handshake) tamamlanır. WPA’da şifreleme metodu olarak TKIP kullanılmaktadır. AES-CCMP ve WEP’i de bazı durumlarda destekler. WEP’teki zafiyetlere karşı 3 güvenlik önlemi ile gelmiştir. ● Birincisi, anahtar ve IV, kriptografik algoritmaya tabi tutulmadan önce bir fonksiyona sokulur ve o şekilde gönderilir. WEP
’te ise bu işlem hatırlanacağı üzere 24 bitlik IV ve 40 bitlik anahtarın normal olarak birleştirilip RC4 algoritmasına sokuluyordu. ● İkincisi paketler için bir sıra numarası(sequence number) koyar. Böylece ardarda sahte istek gönderilmesi durumunda(replay attack) AP bu paketleri yoksayacaktır. ● Üçüncü olarak ise paketlerin bütünlüğünü kontrol etmek amacıyla 64 bitlik Message Integrity Check (MIC) eklenmiştir. WEP’te içeriği bilinen bir paket, şifre çözülmese dahi değiştirilebilir.
TKIP 
Büyük ölçüde WEP’e benzerlik göstermektedir. WEP üzerinde etkili olan bir çok ataktan etkilenir. Beck-Tews atak olarak bilinen bir yöntemle, çözülebilen bir paket başına 7-15 paket ağa enjekte edilebilir. Bu yöntemle ARP zehirleme, servis dışı bırakma gibi saldırılar gerçekleştirilebilir. Ancak bu işlem WPA parolasının ortaya çıkarılması manası taşımamaktadır.

CCMP CCMP, AES alınarak verilerin şifrelenmesi için tasarlanan bir şifreleme protokolüdür. WEP ve TKIP’ye göre daha güvenlidir. Güvenlik adına getirdiği yenilikler; ● Veri güvenliği: Sadece yetkili kısımlar tarafından erişilebilir. ● Kimlik doğrulama: Kullanıcının ‘gerçekliğini’ doğrulama olanağı verir ● Erişim kontrolü: Katmanlar arası bağlantı/yönetim geliştirilmiştir.

802.1x Kablolu ve kablosuz ağlar için IEEE tarafından belirlenen bir standarttır. Ağa dahil olmak isteyen cihazlar için port bazlı bir denetim mekanizmasıdır. Bu denetim kimlik doğrulama(authentication) ve yetkilendirme(authorization) adımlarını kapsar. 3 bileşenden oluşur: 1- Supplicant; ağa dahil olmak isteyen sistem, 2- Authenticator; genelde switch veya AP(erişim noktası) 3- Authentication server; RADIUS, EAP gibi protokolleri destekleyen bir yazılımdır. Bir kullanıcı ağa dahil olmak istediğinde kullanıcı adı/parola veya dijital bir sertifikayı authenticator’a gönderir. Authenticator’da bunu Authentication server’a iletir. İletim işleminde EAP metotları kullanılır. Özellikle kurumsal ağlarda yüzlerce, binlerce kullanıcı için sadece bir tane parola bilgisiyle ağa dahil etmek beraberinde başka sıkıntılarda getirebilir. Bu nedenle büyük ağlarda WPA - Enterprise kullanılır. Çalışanlar Active Directory/LDAP’tan kontrol edilen kullanıcı adı/parola bilgileriyle ağa dahil olabilirler. 

EAP(Extensible Authentication Protocol) EAP kimlik denetimi için bir çok metot barındıran bir protokoldür. EAP çatısı altında en bilinen metotlar; EAP-PSK, EAP-TLS, LEAP, PEAP. EAP çeşitleri EAP-TLS: Kablosuz ağlarda kimlik doğrulama için standart ve en güvenli metottur. Sertifika veya akıllı kart kullanılan ağlar için elzemdir. LEAP: Cisco tarafından geliştirilmiş bir kimlik doğrulama metodudur. MS-CHAP’ın değiştirilmiş bir versiyonu gibidir. Zafiyet barındıran bir metottur ve ancak güçlü bir parola ile kullanılmalıdır. Asleap adlı araç bu metodun istismarı için kullanılabilir. Yerini yine Cisco tarafından geliştirilen EAP-FAST’e bırakmıştır. PEAP: Sadece sunucu taraflı PKI sertifikasına ihtiyaç duyar. Kimlik doğrulama güvenliği için TLS tunel üzerinden bilgiler iletilir.



Kablosuz Ağlarda Güvenlik Önlemleri Kablosuz ağlardaki en temel güvenlik problemi verilerin hava ortamında serbestçe   dolaşmasıdır. Normal kablolu ağlarda switch kullanarak güvenlik fiziksel olarak sağlanabiliyor ve switch’e fiziksel olarak bağlı olmayan makinelerden korunmuş olunuyordu. Oysaki kablosuz ağlarda tüm iletişim hava ortamında kurulmakta ve veriler gelişigüzel ortalıkta dolaşmaktadır.

Erişim noktası Öntanımlı Ayarlarının Değiştirilmesi Kablosuz ağlardaki en büyük risklerden birisi alınan erişim noktası cihazına ait öntanımlı ayarların değiştirilmemesidir. Öntanımlı ayarlar erişim noktası ismi, erişim noktası yönetim konsolunun herkese açık olması, yönetim arabirimine girişte kullanılan parola ve şifreli ağlarda ağın şifresidir. Yapılan araştırmalarda kullanıcıların çoğunun bu ayarları değiştirmediği görülmüştür. Kablosuz ağların güvenliğine dair yapılması gereken en temel iş öntanımlı ayarların değiştirilmesi olacaktır.

Erişim Noktası İsmini Görünmez Kılma: SSID Saklama Kablosuz ağlarda erişim noktasının adını(SSID) saklamak alınabilecek ilk temel güvenlik önlemlerinden biridir. Erişim noktaları ortamdaki kablosuz cihazların kendisini bulabilmesi için devamlı anons ederler. Teknik olarak bu anonslara “beacon frame” denir. Güvenlik önlemi olarak bu anonsları yaptırmayabiliriz ve sadece erişim noktasının adını bilen cihazlar kablosuz ağa dahil olabilir. Böylece Windows, Linux da dahil olmak üzere birçok işletim sistemi etraftaki kablosuz ağ cihazlarını ararken bizim cihazımızı göremeyecektir. SSID saklama her ne kadar bir önlem olsa da teknik kapasitesi belli bir düzeyin üzerindeki saldırganlar tarafından rahatlıkla öğrenilebilir. Erişim noktasının WEP ya da WPA protokollerini kullanması durumunda bile SSID’lerini şifrelenmeden gönderildiğini düşünürsek ortamdaki kötü niyetli birinin özel araçlar kullanarak bizim erişim noktamızın adını her durumda öğrenebilmesi mümkündür.

Erişim Kontrolü Standart kablosuz ağ güvenlik protokollerinde ağa giriş anahtarını bilen herkes kablosuz ağa dahil olabilir. Kullanıcılarınızdan birinin WEP anahtarını birine vermesi/çaldırması sonucunda WEP kullanarak güvence altına aldığımız kablosuz ağımızda güvenlikten eser kalmayacaktır. Zira herkeste aynı anahtar olduğu için kimin ağa dahil olacağını bilemeyiz. Dolayısı ile bu tip ağlarda 802.1x kullanmadan tam manası ile bir güvenlik sağlanamayacaktır. 802.1x kullanılan ağlarda şu an için en büyük atak vektörü sahte kablosuz ağ yayınlarıdır.


MAC tabanlı erişim kontrolü Piyasada yaygın kullanılan erisim noktası(AP) cihazlarında güvenlik amaçlı konulmuş bir özellik de MAC adresine göre ağa dahil olmadır. Burada yapılan kablosuz ağa dahil olmasını istediğimiz cihazların MAC adreslerinin belirlenerek erisim noktasına bildirilmesidir. Böylece tanımlanmamış MAC adresine sahip cihazlar kablosuz ağımıza bağlanamayacaktır. Yine kablosuz ağların doğal çalışma yapısında verilerin havada uçuştuğunu göz önüne alırsak ağa bağlı cihazların MAC adresleri -ağ şifreli dahi olsa- havadan geçecektir, "burnu kuvvetli koku alan" bir hacker bu paketleri yakalayarak izin verilmiş MAC adreslerini alabilir ve kendi MAC adresini kokladığı MAC adresi ile değiştirebilir.




 
![http](https://user-images.githubusercontent.com/66878884/103551114-ec48a700-4eba-11eb-829a-9240cd4521f6.jpg)



![5](https://user-images.githubusercontent.com/66878884/103550719-60367f80-4eba-11eb-923b-6d5d9c2bfee8.jpg)


![6](https://user-images.githubusercontent.com/66878884/103564254-405d8680-4ecf-11eb-8f10-7f6e5a75ccfe.jpg)

 

 
Yukarıdaki çıktıda SSL sertifika uyumsuzluğundan Firefox’un verdiği uyarılar serisi sıraadn bir kullanıcıyı bile sayfadan kaçıracak türdendir. Dikkatsiz, her önüne gelen linke tıklayan, çıkan her popup okumadan yes’e basan kullanıcılar için bu risk azalsa da hala devam ediyor ama bilinçli kullanıcılar bu tip uyarılarda daha dikkatli olacaklardır. Peki bilinçli kullannıcıların gözünden kaçabilecek ve HTTPS’I güvensiz kılabilecek başka açıklıklar var mıdır? Bu sorunun kısa cevabı evet, uzun cevabına gelecek olursak…


![7](https://user-images.githubusercontent.com/66878884/103564128-160bc900-4ecf-11eb-90ba-b9f6b4754ee8.jpg)

 
 
Firmaların neden sadece HTTPS kullanmadığı sorusuna verilecek en kısa cevap SSL’in sunucu tarafında ek kapasite gerektirmesidir. HTTP ile HTTPS arasındaki yük farkını görebilmek için aynı hedefe yapılmış iki farklı HTTP ve HTTPS isteğinin Wireshark gibi bir snifferla incelenmesi yeterli olacaktır. HTTP’de oturum bilgisi çoğunlukla cookie’ler üzerinden taşındığı düşünülürse eğer sunucu tarafında kod geliştirenler cookilere “secure” özelliği(cookielerin sadece güvenli bağlantı üzerinden aktarılması) eklememişlerse trafiği dinleyebilen birisi hesap bilgilerine ihtiyaç duymadan cookieler aracılığıyla sizin adınıza sistemlere erişebilir. Bunun için çeşitli yöntemler bulunmaktadır, internette “sidejacking” ve surfjacking anahtar kelimeleri kullanılarak yapılacak aramalar konu hakkında detaylı bilgi verecektir. Bu yazının konusu olmadığı için sadece bilinen iki yöntemin isimlerini vererek geçiyorum.
Göz Yanılgısıyla HTTPS Nasıl Devre Dışı Bırakılır? Bu yıl yapılan Blackhat konferanslarında dikkat çeken bir sunum vardı: New Tricks For Defeating SSL In Practice. Sunumun ana konusu yukarda anlatmaya çalıştığım HTTPS ile HTTP’nin birlikte kullanıldığı durumlarda ortaya çıkan riski ele alıyor. Sunumla birlikte yayınlanan sslstrip adlı uygulama anlatılanların pratiğe döküldüğü basit bir uygulama ve günlük hayatta sık kullandığımız banka, webmail, online alış veriş sitelerinde sorunsuz çalışıyor. Kısa kısa ssltrip’in nasıl çalıştığı, hangi ortamlarda tehlikeli olabileceği ve nasıl korunulacağı konularına değinelim.

SSLStrip Nasıl Çalışır? Öncelikle sslstrip uygulamasının çalışması için Linux işletim sistemine ihtiyaç duyduğu ve saldırganın MITM tekniklerini kullanarak istemcinin trafiğini üzerinden geçirmiş olması zorunlulugunu belirtmek gerekir. 
Şimdi adım adım saldırganın yaptığı işlemleri ve her adımın ne işe yaradığını inceleyelim; 
1.Adım: Saldırgan istemcinin trafiğini kendi üzerinden geçirir. Saldırgan istemcinin trafiğini üzerinden geçirdikten sonra trafik üzerinde istediği oynamaları yapabilir. Saldırgana gelen paketleri hedefe iletebilmesi için işletim sisteminin routing yapması gerekir. Linux sistemlerde bu sysctl değerleriyle oynayarak yapılabilir. (echo "1" > /proc/sys/net/ipv4/ip_forward) 
2. Adım: Saldırgan iptables güvenlik duvarını kullanarak istemciden gelip herhangi biryere giden tüm TCP/80 isteklerini lokalde sslstrip’in dinleyeceği 8000. Porta yönlendiriyor. İlgili Iptables komutu: iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8000 
3.Adım)Saldırgan sslstrip uygulamasını çalıştırarak 8000.portu dinlemeye alıyor ve istemci ve sunucudan gelecek tüm istek-cevapları “topla” isimli dosyaya logluyor. #sslstrip -w topla --all -l 8000 –f Şimdi şöyle bir senaryo hayal edelim: Masum kullanıcı ailesiyle geldiği alışveriş merkezinde ücretsiz bir kablosuz ağ bulmuş olmanın sevinciyle mutlu bir şekilde gelip bilgisayarını açsın ve ilk yapacağı iş maillerini kontrol etmek olsun. Ortama dahil olmuş masum bir kullanıcının yaşadığı süreç şu şekilde olacaktır: İstemci ağa bağlanıp internete erişmek istediğinde ortamdaki saldırgan el çabukluğu marifetle istemcinin trafiğini üzerinen geçirir(ARP Cache poisoning yöntemiyle). 
İstemci durumdan habersiz webmail uygulamasına bağlanmak için sayfanın adresini yazar. Araya giren saldırgan sunucudan dönen cevaplar içerisinde HTTPS ile başlayan satırları HTTP ile değiştirir ve aynen kullanıcıya gönderir. Hiçbir şeyden haberi olmayan kullanıcı gelen sayfada kullanıcı adı/parola bilgilerini yazarak Login’I tıklar.

 

SSH Tünelleme ile İçerik Filtreleyicileri Atlatmak İşimiz, mesleğimiz gereği çeşitli ortamlarda bulunup internete erişmek, bazı programları (Google Talk, MSN vs)kullanmak istiyoruz fakat bazen bulunduğumuz ortamın şartları bu tip isteklerimize izin vermeyebiliyor . Bazen de herkese açık kablosuz bir ağ ortamında bulunduğumuz için güvenilir tüneller kullanma ihtiyacı hissediyoruz. Bu tip durumlarda genelde ağ yöneticisine durumu izah ederek bağlantı izni talep edilir. Ağ yöneticisine ulaşılamayacak durumlarda ya da ağ yöneticisini rahatsız etmeden işinizi kendiniz halletmek istediğinizde aşağıda anlatılanları uygulayarak çoğu içerik filtreleme (En popüleri Websense olmak uzere)sistemini atlatabilirsiniz. (Kablosuz ağ ortamlarında trafiğinizin izlenmemesi için de kullanılabilir) Benzer şekilde ağ guvenliği yöneticileri kendi ağlarında bu tip gizli tünellerin çalıştırılmasını istemeyebilir. Burada anlatılan yöntemlerin sisteminizde çalışmaması için yazının son bölümündeki “Nasıl Engellerim” başlıklı kısmı inceleyebilirsiniz. Icerik filtreleme sistemlerini atlatmak icin kullanacağımız yöntem SSH Tünelleme(SSH’in SOCKS proxy ozelligini kullanacagiz). 
Kısaca bilgilerimizi tazeleyelim: 
• SSH servisi öntanımlı olarak 22/TCP portunda çalışır ve istenirse değiştirilebilir.
 • Proxy’ler CONNECT metodu ile http olmayan çeşitli bağlantılara izin verirler. Mesela HTTPS. Bunun için genelde Proxy yapılandırmalarında 443 TCP portu dışarıya doğru açıktır.
 • SSH protokolü Proxy’lerin CONNECT yöntemini kullanarak ssh sunuculara bağlanabilirler. Bu yazıda kullanacağımız yöntem de 443. porttan çalışan SSH sunucusu bulup kendi sistemimiz ile bu sunucu arasında tunnel kurarak web trafiğimizi bu tünelden geçirmek. Arada gidip gelen veri şifreli olduğu için içerik filtreleme yazılımları bize engel çıkarmayacaktır.

FTP ve Güvenlik Duvarları FTP Protokolü FTP, sık kullanılan protokoller(HTTP, SMTP, DNS vs) arasında en sorunlu protokoldür. Diğer protokoller tek bir TCP/UDP portu üzerinden çalışırken FTP birden fazla ve dinamik portlarla çalışır. (IRC’deki veri transferi ve iletisim portu gibi). Bu portlardan biri “Command port” diğeri DATA port olarak adlandırılır. Command portu üzerinden ftp iletişimine ait gerekli temel bilgiler aktarılır. Temel bilgiler; ftp sunucuya gönderilecek kullanıcı adı ve parola bilgileri, ftp sunucuya hangi porttan bağlanılacağı, hangi ftp çeşidinin kullanılacağı gibi bilgiler olabilir. Data portu ise veri transferi amaçlı kullanılır.
 FTP Çeşitleri FTP iki çeşittir: pasif ve aktif FTP. Her ikisininde farklı amaçlı kullanımları mevcuttur. Hangi FTP çeşidinin kullanılacağı ftp istemcisi tarafından belirlenir.
 Aktif FTP Bu FTP çeşidinde istemci aktif rol alır. Bilinenin aksine orjinal ftp aktif ftpdir fakat günümüz internet altyapısında çeşitli sorunlara yol açtığı için pasif ftp daha fazla tercih edilmektedir. Aktif ftp de çıkan sorunlar pasif ftpnin geliştirilmesini sağlamıştır. Adım adım Aktif FTP;




![8](https://user-images.githubusercontent.com/66878884/103564130-173cf600-4ecf-11eb-91e0-333258f9636e.jpg)


 
1)istemci FTP sunucuya Command portundan(21) bağlanır. 
2)FTP sunucu gerekli karşılama mesajı ve kullanıcı adı sorgulamasını gönderir. -istemci gerekli erişim bilgilerini girer. -Sunucu erişimi bilgilerini kontrol ederek istemciye yanıt döner. Eğer erişim bilgileri doğru ise istemciye ftp komut satırı açılır. Burada istemci veri transferi yapmak istediğinde(ls komutunun çalıştırılması da veri transferi gerçekleştirir)3. adıma geçilir. -İstemci kendi tarafında 1024’den büyük bir port açar ve bunu PORT komutu ile FTP sunucuya bildirir. 
3)FTP sunucusu , istemcinin bildirdiği port numarasından bağlantı kurar ve gerekli aktarım işlemleri başlar. 
4) İstemci Onay mesaji gönderir.

 

 
 ![9](https://user-images.githubusercontent.com/66878884/103564131-17d58c80-4ecf-11eb-9671-960175bcd20e.jpg)
 
 
 






Güvenlik Duvarlarında Yaşanabilecek FTP Sorunları 
Zaman zaman arkadaşlarınızın FTP ye bağlanıyorum ama ls çektiğimde bağlantı kopuyor ya da öylesine bekliyor dediğine şahit olmuşsunuzdur. Bu gibi istenmeyen durumlar FTP’nin karmaşık yapısı ve Firewall’ların protokolden anlamamasından kaynaklanır. 
Bir Firewall’da HTTP bağlantısını açmak için sadece 80. portu açmanız yeterlidir fakat FTP için 21. portu açmak yetmez.
 Bunun sebebi FTP’nin komutların gidip geldiği ve verinin aktığı port olmak üzere iki farklı port üzerinden çalışmasıdır.
 İlk port sabit ve bellidir:21. port fakat veri bağlantısının gerçekleştiği port olan diğer port kullanılacak ftp çeşidine (Aktif FTP veya PAsif FTP ) göre değişir ve eğer firewall FTP protokolünden anlamıyorsa genelde sorun yaşanır.
 Yeni nesil Firewall’larda bu sıkıntı büyük ölçüde giderilmiş olsa da ara ara eksik yapılandırmalardan aynı hataların yaşandığını görüyoruz. Linux Iptables’da ftp problemini aşmak için mod ip_conntrack_ftp modülünün sisteme yüklenmesi gerekir. OpenBSD Packet Filter ise bu tip aykırı protokoller için en uygun yapı olan proxy mantığını kullanır. FTP için ftp-proxy, upnp için upnp proxy, sip için sip-proxy vs. Aktif FTP ve Güvenlik Duvarı FTP istemcinin önünde bir Firewall varsa istemci kendi tarafında port açsa bile bu porta izin Firewall tarafından verilmeyeceği için problem yaşanacaktır.

 
![10](https://user-images.githubusercontent.com/66878884/103564134-1906b980-4ecf-11eb-9778-5716e3ccae04.jpg)





 

TCP/IP Ağlarda Parçalanmış Paketler
Parçalanmış Paketler 
Parçalanmış paketler(Fragmented Packets) konusu çoğu network ve güvenlik probleminin temelini teşkil etmektedir. Günümüzde tercih edilen NIDS/NIPS(Ağ tabanlı Saldırı Tespit ve Engelleme Sistemleri) sistemleri bu konuya bir çözüm getirse de hala eksik kalan, tam anlaşılmayan kısımlar vardır. Bu sebepledir ki günümüzde hala parçalanmış paketler aracılığıyla yapılan saldırılara karşı korunmasız olan popüler IPS yazılımları bulunmaktadır[1]. IP parçalamanın ne olduğu, hangi durumlarda nasıl gerçekleştiği, ikinci bölümde IP parçalamanın ne tip güvenlik zaafiyetlerine sebep olabileceği konuların üzerinde duracağız.



![11](https://user-images.githubusercontent.com/66878884/103564136-199f5000-4ecf-11eb-807c-c4f0310091b8.jpg)



![12](https://user-images.githubusercontent.com/66878884/103564139-1ad07d00-4ecf-11eb-86d6-2fe7dcb2518a.jpg)



![13](https://user-images.githubusercontent.com/66878884/103564141-1c01aa00-4ecf-11eb-8923-cef6957916f7.jpg)

 
 ![14](https://user-images.githubusercontent.com/66878884/103564147-1d32d700-4ecf-11eb-892f-2b4e8781667b.jpg)



 
 
Parçalanmış Paketler ve Saldırı Tespit Sistemleri 
Parçalanmış paketler konusunda en sıkıntılı sistemler IDS/IPS’lerdir. Bunun nedeni bu sistemlerin temel işinin ağ trafiği inceleme olmasıdır. Saldırı tespit sistemleri gelen bir paketin/paket grubunun saldırı içerikli olup olmadığını anlamak için çeşitli kontrollerden geçirir. Eğer bu kontrolleri geçirmeden önce paketleri birleştirmezse çok rahatlıkla kandırılabilir. Mesela HTTP trafiği içerisinde “/bin/bash” stringi arayan bir saldırı imzası olsun. IDS sistemi 80.porta gelen giden her trafiği inceleyerek içerisinde /bin/bash geçen paketleri arar ve bu tanıma uyan paketleri bloklar. Eğer IDS sistemimiz paket birleştirme işlemini uygun bir şekilde yapamıyorsa biz fragroute veya benzeri bir araç kullanarak /bin/sh stringini birden fazla paket olacak şekilde (1. Paket /bin, 2.paket /bash)gönderip IDS sistemini atlatabiliriz.

Snort ve Parçalanmış Paketler Açık kaynak kodlu IDS/IPS yazılımı Snort parçalanmış paketler için sağlam bir çözüm sunmaktadır. Snort ile birlikte frag3 önişlemcisi kullanılarak IDS sistemine gelen parçalanmış paketler detection engine(Snort’da kural karşilaştirmasinin yapildiği kısım)gelmeden birleştirilerek yapilmaya çalışılan ids atlatma tekniklerini işe yaramaz hale getirilebilir. Frag3 önişlemcisine ek olarak Stream5 önişlemcisi de kullanılarak stateful bir yapı kurulur. Bu ikili sağlıklı yapılandırılmazsa Snort bir çok saldırıya açık hale gelir ve gerçek işlevini yerine getiremez.

 
 
 ![15](https://user-images.githubusercontent.com/66878884/103564153-1dcb6d80-4ecf-11eb-9677-f6743b2178d1.jpg)


 ![16](https://user-images.githubusercontent.com/66878884/103564157-1f953100-4ecf-11eb-8193-16860bb37e51.jpg)









Sık Kullanılan Parametreler Arabirim Seçimi( -i ) 
Sistemimizde birden fazla arabirim varsa ve biz hangi arabirimini dinlemesini belirtmezsek tcpdump aktif olan ağ arabirimleri arasında numarası en düşük olanını dinlemeye alır, mesela 3 adet aktif Ethernet ağ arabirimimiz var; eth0, eth1, eth2[Linux için geçerlidir,diğer unix çeşitlerinde farklıdır, şeklinde biz bu makinede tcpdump komutunu yalın olarak kullanırsak tcpdump eth0 arabirimini dinlemeye alacaktır. Eğer ilk arabirimi değilde istediğimiz bir arabirimi dinlemek istiyorsak -i parametresi ile bunu belirtebiliriz 
# tcpdump -i eth2 komutu ile sistemimizdeki 3.Ethernet kartını dinlemeye alıyoruz. Sistemde bulunan ve tcpdump tarafından dinlemeye alınabilecek arabirimlerin listesini almak için –D parametresi kullanılabilir.
 [root@netdos1 ~]# tcpdump –D 
1.em0
 2.pflog0
 3.em1 
4.lo0

 İsim Çözümleme ( -n ) Eğer tcpdump ile yakalanan paketlerin dns isimlerinin çözülmesi istenmiyorsa -n parametresini kullanılabilir. Özellikle yoğun ağlarda tcpdump her gördüğü ip adresi-isim için dns sorgusu göndermeye çalışıp gelen cevabı bekleyeceği için ciddi yavaşlık hissedilir. 
Normal kullanım;
 # tcpdump 
17:18:21.531930 IP huzeyfe.32829 > erhan.telnet: S 3115955894:3115955894(0) win 5840 
17:18:21.531980 IP erhan.telnet > huzeyfe.32829: R 0:0(0) ack 3115955895 win 0

-n parametresi ile kullanım; 
# tcpdump -n 
17:18:53.802776 IP 192.168.0.100.32835 > 192.168.0.1.telnet: S 
3148097396:3148097396(0) win 5840 
17:18:53.802870 IP 192.168.0.1.telnet > 192.168.0.100.32835: R 0:0(0) ack 3148097397 win 0	

# tcpdump -nn 
yukarıda (-n için)verdiğimiz örnekte -n yerine -nn koyarsanız hem isim hemde port çözümlemesi yapılmayacaktır,yani telnet yerine 23 yazacaktır.

 -Zaman Damgası Gösterimi ( -t ) Eğer tcpdump'ın daha sade bir çıktı vermesini isteniyorsa ekrana bastığı satırların başındaki timestamp(zaman damgası, hangi paketin hangi zaman aralığında yakalandığını belirtir) kısmı iptal edilebilir. 
Çıktılarda timestamp[zaman damgası]leri istenmiyorsa -t parametresi kullanılabilir.
 
![17](https://user-images.githubusercontent.com/66878884/103564162-202dc780-4ecf-11eb-9068-8ebdb1065b3c.jpg)




Yakalanan Paketleri Kaydetme ( -w ) 
Tcpdump'ın yakaladığı paketleri ekradan değilde sonradan incelemek üzere bir uygun bir şekilde dosyaya yazması istenirse -w parametresi kullanılabilir. Kaydedilen dosya cap uyumlu olduğu için sadece tcpdump ile değil birçok network snifferi tarafından okunup analiz edilebilir.
 # tcpdump -w dosya_ismi
 -r /Kaydedilmiş Paketleri Okuma
 -w ile kaydedilen paketler -r parametresi kullanılarak okunabilir.
 # tcpdump -r dosya_ismi 
Not! -w ile herhangi bir dosyaya kaydederken filtreleme yapılabilir. Mesela sadece şu tip paketleri kaydet ya da timestampleri kaydetme gibi, aynı şekilde -r ile paketlerie okurken filtre belirtebiliriz. Bu filtrenin -w ile belirtilen filtre ile aynı olma zorunluluğu yoktur.

![18](https://user-images.githubusercontent.com/66878884/103564166-20c65e00-4ecf-11eb-8e4d-6055ba0eed05.jpg)


 
Yakalanacak Paket Sayısını Belirleme ( -c )
# tcpdump -i eth0 -c 5 
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
 listening on eth0, link-type EN10MB (Ethernet), capture size 96 bytes
 00:59:01.638353 IP maviyan.net.ssh > 10.0.0.2.1040: P 
1010550647:1010550763(116) ack 774164151 win 8576 
00:59:01.638783 IP 10.0.0.2.1040 > maviyan.net.ssh: P 1:53(52) ack 116 win 16520
 00:59:01.638813 IP maviyan.net.ssh > 10.0.0.2.1040: P 116:232(116) ack 53 win 8576
 00:59:01.639662 IP 10.0.0.2.1040 > maviyan.net.ssh: P 53:105(52) ack 232 win 16404 
00:59:01.640377 IP maviyan.net.ssh > 10.0.0.2.1040: P 232:380(148) ack 105 win 8576
 5 packets captured
 5 packets received by filter
 0 packets dropped by kernel

Tcpdump, -c sayı ile belirtilen değer kadar paket yakaladıktan sonra çalışmasını durduracaktır.

 Yakalanacak Paket Boyutunu Belirleme ( -s ) 
-s parametresi ile yakalancak paketlerin boyutunu byte olarak belirtilebilir. 
#tcpdump –s 1500 gibi. Öntanımlı olarak 96 byte kaydetmektedir. 

# tcpdump -i eth0 tcpdump: verbose output suppressed, use -v or -vv for full protocol decode 
listening on eth0, link-type EN10MB (Ethernet), capture size 96 bytes 

Detaylı Loglama (-v) -v parametresi ile tcpump'dan biraz daha detaylı loglama yapmasını istenebilir. Mesela bu parametre ile tcpdump çıktılarını TTL ve ID değerleri ile birlikte edinebilir.

![19](https://user-images.githubusercontent.com/66878884/103564169-215ef480-4ecf-11eb-9b2a-04b5794f1cad.jpg)

 
Tcpdump kullanarak ethernet başlık bilgileri de yakalanabilir. Özellikle yerel ağlarda yapılan trafik analizlerinde MAC adresleri önemli bilgiler vermektedir.

BPF(Berkley Packet Filter) Tcpdump ile gelişmiş paket yakalama için BPF kullanılabilir(sadece X hostunun Y portundan gelen paketleri yakala gibi). 
BPF üç ana kısımdan oluşur
 Type 
Host, net, port parametreleri. 
Direction 
Src, dst parametreleri.
 Protocol
 Ether, fddi, wlan, ip, ip6, arp, rarp parametreleri.
 Host Parametresi Sadece belli bir host a ait paketlerin izlenmesini isteniyorsa host parametresi kullanılabilir.
 # tcpdump host 10.0.0.21 bu komutla kaynak ya da hedef ip adresi 10.0.0.21 olan paketlerin alınmasını istiyoruz

dst host (Hedef Host Belirtimi) 
dst host ;hedef host olarak belirtilen adrese ait paketleri yakalar, 
# tcpdump -i eth0 dst host 10.0.0.1 
yukarıdaki komutla makinemizin eth0 arabirimine gelen ve hedefi 10.0.0.1 olan tüm paketler yakalanacaktır. 
# tcpdump -i eth0 dst host 10.0.0.1 
tcpdump: listening on eth0 10:47:20.526325 10.0.0.21 > 10.0.0.1: icmp: echo request ile de hedef ip si 10.0.0.1 olan ip adreslerini izlemiş oluyoruz.

# tcpdump host hotmail.com 
dst ve src i aynı komuttada kullanabiliriz.
 Örnek:
 kaynak ip si 10.1.0.59 hedef hostu 10.1.0.1 olan paketleri izlemek istersek 
# tcpdump src host 10.1.0.59 and dst host 10.1.0.1


 ![20](https://user-images.githubusercontent.com/66878884/103564170-21f78b00-4ecf-11eb-8fec-b6d026fe0ebd.jpg)




TCP/IP
Paket, protokol kavramlarının detaylı olaran anlaşılmasının en kolay yolu “Sniffer” olarak da adlandırılan ağ paket/protokol analiz programlarıyla pratik çalışmalar yapmaktır. Bu yazıda siber dünyada en sık kullanılan paket/protokol analiz programlarından Wireshark’ın komut satırı versiyonu kullanılarak ileri seviye paket, protokol analizi çalışmaları gerçekleştirilmiştir.



Paket Analizi 

Paket, Protokol Kavramları
 Paket ve protokol birbirleri yerine sık kullanılan ama gerçekte birbirinden farklı iki kavramdır. Paket kavramı protokol kavramına göre daha kuşatıcıdır(paket>protokol). Paket’den kastımız TCP/IP ağlarda tüm iletişimin temelidir, protokol ise paketlerin detayıdır.
 Gönderip alınan mailler, web sayfası ziyaretleri , -VOIP kullanılıyorsa- telefon konuşmaları vs arka planda hep paketler vasıtasıyla hedef sisteme ulaştırılır. Bu paketleri izleme ve inceleme “sniffer” adı verilen programlar vasıtasıyla mümkündür.
 Bir de bu paketler içerisinde gidip gelen protokoller vardır. Mesela web sayfalarına giriş için HTTP, 3G ya da GPRS bağlantıları için GTP, mail için SMTP gibi… Bu protokollere taşıyıcılık yapan daha alt seviye protokoller de vardır TCP, IP, UDP gibi. Tüm bu protokoller iletişime geçmek isteyen uçlar arasında azami standartları belirlemek için düşünülmüştür.
 Paket ve protokol analizi için sniffer araçları kullanılır. Bazı snifferlar kısıtlı protokol analizi yapabilirken bazı snifferlar detaylı paket ve protokol analizi yapmaya olanak sağlar. Kısıtlı paket ve protokol analizine imkan sağlayan sniffer olarak tcpdump’ı, gelişmiş paket ve protokol analizine örnek olarak da Wireshark/Tshark örnek verebilir.

Tshark Nedir? 
Tshark, açık kaynak kodlu güçlü bir ağ protokolleri analiz programıdır. Tshark komut satırından çalışır ve yine bir ağ trafik analiz programı olan Wireshark’da bulunan çoğu özelliği destekler.
 Akıllara Wireshark varken neden Tshark kullanılır diye bir soru takılabilir? Bu sorunun çeşitli cevapları olmakla birlikte en önemli iki cevabı Tshark’ın komut satırı esnekliği sağlaması ve Wireshark’a göre daha performanslı çalışmasıdır. 
Basit Tshark Kullanımı 
Tshark, çeşitli işlevleri olan bir sürü parametreye sahiptir. Eğer herhangi bir parametre kullanılmadan çalıştırılırsa ilk aktif ağ arabirimi üzerinden geçen trafiği yakalayıp ekrana basmaya başlar.
 cyblabs ~ # tshark 
Capturing on eth0 
0.000000 192.168.2.23 -> 80.93.212.86 ICMP Echo (ping) request
 0.012641 80.93.212.86 -> 192.168.2.23 ICMP Echo (ping) reply
 0.165214 192.168.2.23 -> 192.168.2.22 SSH Encrypted request packet len=52
 0.165444 192.168.2.22 -> 192.168.2.23 SSH Encrypted response packet len=52
 0.360152 192.168.2.23 -> 192.168.2.22 TCP pcia-rxp-b > ssh [ACK] Seq=53 Ack=53 Win=59896 Len=0
 0.612504 192.168.2.22 -> 192.168.2.23 SSH Encrypted response packet len=116 
1.000702 192.168.2.23 -> 80.93.212.86 ICMP Echo (ping) request 
1.013761 80.93.212.86 -> 192.168.2.23 ICMP Echo (ping) reply 
1.057335 192.168.2.23 -> 192.168.2.22 SSH Encrypted request packet len=52 16 packets captured

Eğer çıktıların ekrana değil de sonradan analiz için bir dosyaya yazdırılması isteniyorsa -w dosya_ismi parametresi kullanılır. cyblabs ~ # tshark -w home_labs.pcap 
Running as user “root” and group “root”. This could be dangerous.
 Capturing on eth0 
24 
Gerektiğinde home_labs.pcap dosyası libpcap destekli herhangi bir analiz programı tarafından okunabilir. Tshark ya da tcpdump ile kaydedilen dosyadan paket okumak için -r parametresi kullanılır.
Tshark çıktılarının anlaşılır text formatta kaydedilmesi isteniyorsa tshark komutu sonuna > dosya_ismi yazılarak ekranda görünen anlaşılır çıktılar doğrudan dosyaya yazdırılmış olur.

Dinleme Yapılabilecek Arabirimleri Listeleme 
root@cyblabs:~# tshark -D 
1. eth0 
2. usbmon1 (USB bus number 1) 
3. usbmon2 (USB bus number 2) 
4. any (Pseudo-device that captures on all interfaces) 
5. lo 
Arabirim Belirtme İstenilen arabirimi dinlemek için -i arabirim_ismi parametresi ya da “-i arabirim_sıra_numarası” parametresi kullanılır. #tshark -i eth12 veya #tshark –i 1 gibi. -n parametresi ile de host isimlerinin ve servis isimlerinin çözülmemesi sağlanır


 
![21](https://user-images.githubusercontent.com/66878884/103564177-22902180-4ecf-11eb-92e9-398854eead1e.jpg)



![22](https://user-images.githubusercontent.com/66878884/103564182-2328b800-4ecf-11eb-9f2a-7c8196ecfd2e.jpg)

 • Web sayfası/servislerinin isteklere geç cevap dönmesi 
            • Ağ performansında yavaşlama 
            • İşletim sistemlerinde CPU/Ram performans problemi
             • Uyarı sistemlerinin çökmesi


![23](https://user-images.githubusercontent.com/66878884/103564187-2459e500-4ecf-11eb-8136-891b7eee65de.jpg)

 


Synflood (D)DOS Saldırıları 
1 SYN paketi 60 byte, 50Mb bağlantısı olan biri saniyede teorik olarak 1.000.000 kadar paket gönderebilir. Bu değer günümüzde kullanılan çoğu güvenlik cihazının kapasitesinden yüksektir.

![24](https://user-images.githubusercontent.com/66878884/103564190-258b1200-4ecf-11eb-92e9-700a9d48be8e.jpg)

 
Internet’i durdurma(DNS DOS)Saldırıları 
İnternet’in çalışması için gerekli temel protokollerden biri DNS (isim çözme) protokolüdür. DNS ’in çalışmadığı bir internet, levhaları ve yönlendirmeleri olmayan bir yol gibidir. Yolu daha önceden bilmiyorsanız hedefinize ulaşmanız çok zordur. DNS protokolü ve dns sunucu yazılımlarında geçtiğimiz yıllarda çeşitli güvenlik açıklıkları çıktı. Bu açıklıkların bazıları doğrudan dns sunucu yazılımını çalışamaz hale getirme amaçlı DOS açıklıklarıdır. Özellikle internette en fazla kullanılan DNS sunucu yazılımı olan Bind’in bu açıdan geçmişi pek parlak değildir. DNS sunucular eğer dikkatli yapılandırılmadıysa gönderilecek rastgele milyonlarca dns isteğiyle zor durumda bırakılabilir. Bunun için internette çeşitli araçlar mevcuttur. DNS sunucunun loglama özelliği, eş zamanlı alabileceği dns istek sayısı, gereksiz rekursif sorgulamalara açık olması, gereksiz özelliklerinin açık olması (edns vs) vs hep DOS’a karşı sistemleri zor durumda bırakan sebeplerdir. DNS sunucularda çıkan DOS etkili zafiyetlere en etkili örnek olarak 2009 yılı Bind açıklığı gösterilebilir. Hatırlayacak olursak 2009 yılında Bind DNS yazılımında çıkan açıklık tek bir paketle Bind DNS çalıştıran sunucuların çalışmasını durdurabiliyor. DNS paketleri udp tabanlı olduğu için kaynak ip adresi de rahatlıkla gizlenebilir ve saldırganın belirlenmesi imkânsız hale gelir. Türkiye’de yaptığımız araştırmada sunucuların %70’nin bu açıklığa karşı korumasız durumda olduğu ortaya çıkmıştır. Kötü bir senaryo ile ciddi bir saldırgan Türkiye internet trafiğini beş dakika gibi kısa bir sürede büyük oranda işlevsiz kılabilir. Siber güvenlik üzerine çalışan ciddi bir kurumun eksikliği bu tip olaylarda daha net ortaya çıkmaktadır.
Korunma Yolları ve Yöntemleri DOS saldırılarından korunmanın sihirbazvari bir yolu yoktur. Korunmanın en sağlam yöntemi korumaya çalıştığınız network yapısının iyi tasarlanması, iyi bilinmesi ve bu konuyla görevli çalışanların TCP/IP bilgisinin iyi derecede olmasıdır. Çoğu DOS saldırısı yukarıda sayılan bu maddelerin eksikliği sebebiyle başarılı olur.
 Router (Yönlendirici) Seviyesinde Koruma Sınır koruma düzeninde ilk eleman genellikle router’dır. Sisteminize gelengiden tüm paketler öncelikle router’dan geçer ve arkadaki sistemlere iletilir. Dolayısıyla saldırı anında ilk etkilenecek sistemler router’lar olur. Kullanılan router üzerinde yapılacak bazı ayalar bilinen DOS saldırılarını engellemede, ya da en azından saldırının şiddetini düşürmede yardımcı olacaktır. Yine saldırı anında eğer gönderilen paketlere ait karakteristik bir özellik belirlenebilirse router üzerinden yazılacak ACL (Erişim Kontrol Listesi) ile saldırılar kolaylıkla engellenebilir. Mesela saldırganın SYN flood yaptığını ve gönderdiği paketlerde src.port numarasının 1024 olduğunu düşünelim (Türkiye’de yapılan dos saldırılarının çoğunluğu sabit port numarasıyla yapılır). Router üzerinde kaynak port numarası 1024 olan paketleri engellersek saldırıdan en az kayıpla kurtulmuş oluruz. Bu arada kaynak portunu 1024 olarak seçen ama saldırı yapmayan kullanıcılardan gelen trafiklerde ilk aşamada bloklanacak ama normal kullanıcılardaki TCP/IP stacki hemen port numarasını değiştirerek aynı isteği tekrarlayacaktır.
 
 ![25](https://user-images.githubusercontent.com/66878884/103564193-2623a880-4ecf-11eb-9fb8-1f3abb397015.jpg)

 
Web Sunuculara Yönelik Koruma Web sunucular şirketlerin dışa bakan yüzü olduğu için genellikle saldırıyı alan sistemlerdir. Web sunuculara yönelik çeşitli saldırılar yapılabil fakat en etkili saldırı tipleri GET flood saldırılarıdır. Bu saldırı yönteminde saldırgan web sunucunun kapasitesini zorlayarak normal kullanıcıların siteye erişip işlem yapmasını engeller. Bu tip durumlarda güvenlik duvarlarında uygulanan rate limiting özelliği ya da web sunucular önüne koyulacak güçlü yük dengeleyici/dağıtıcı(load balancer)cihazlar ve ters proxy sistemleri oldukça iyi koruma sağlayacaktır. Güvenlik duvarı kullanarak http GET isteklerine limit koyulamaz. Zira http keepalive özelliği sayesinde tek bir TCP bağlantısı içerisinden yüzlerce http GET komutu gönderebilir. Burada paket içeriğine bakabilecek güvenlik duvarı/ips sistemleri kullanılmalıdır. Mesela Snort saldırı tespit/engelleme sistemi kullanılarak aşağıdaki kuralla 3 saniyede 50’den fazla http GET isteği gönderen ip adresleri bloklanabilmektedir.


 ![26](https://user-images.githubusercontent.com/66878884/103564198-27ed6c00-4ecf-11eb-8f5b-d843cb3649ee.jpg)

![syn](https://user-images.githubusercontent.com/66878884/103568982-946c6900-4ed7-11eb-97c6-b5c087a0f1fe.jpg)

 
Temel TCP bilgisi OSI katmanına göre 4. Katta yer alan TCP günümüz internet dünyasında en sık kullanılan protokoldür. Aynı katta yer alan komşu protokol UDP’e göre oldukça karışık bir yapıya sahiptir. HTTP, SMTP, POP3, HTTPS gibi protokoller altyapı olarak TCP kullanırlar.
 TCP Bağlantılarında Bayrak Kavramı (TCP Flags) TCP bağlantıları bayraklarla (flags) yürütülür. Bayraklar TCP bağlantılarında durum belirleme konumuna sahiptir. Yani bağlantının başlaması, veri transferi, onay mekanizması ve bağlantının sonlandırılması işlemleri tamamen bayraklar aracılığı ile gerçekleşir (SYN, ACK, FIN, PUSH, RST, URG bayrak çeşitleridir). UDP’de ise böyle bir mekanizma yoktur. UDP’de güvenilirliğin (paketlerin onay mekanizması) sağlanması üst katmanlarda çalışan uygulamalar yazılarak halledilebilir. DNS protokolü UDP aracılığı ile nasıl güvenilir iletişim kurulacağı konusunda detay bilgi verecektir. UNIX/Windows sistemlerde bağlantılara ait en detaylı bilgi netstat (Network statistics) komutu ile elde edilir. Netstat kullanarak TCP, UDP hatta UNIX domain socketlere ait tüm bilgileri edinebiliriz. 
TCP’de bağlantıya ait oldukça fazla durum vardır. TCP bağlantılarında netstat aracılığı ile görülebilecek çeşitli durumlar: CLOSE_WAIT, CLOSED, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, LAST_ACK, LISTEN, SYN_RECEIVED, SYN_SEND ve TIME_WAIT

 
 ![27](https://user-images.githubusercontent.com/66878884/103564199-28860280-4ecf-11eb-92d5-ad59f1d71f03.jpg)

![28](https://user-images.githubusercontent.com/66878884/103564202-29b72f80-4ecf-11eb-8f30-a9234c1247a4.jpg)

![29](https://user-images.githubusercontent.com/66878884/103564209-2ae85c80-4ecf-11eb-937d-985beddcb501.jpg)


 

 
 



HTTP’e Giriş 
HTTP(Hypertext Transfer Protocol) OSI modelinde uygulama katmanında yer alan iletişim protokolüdür. Günümüzde zamanımızın çoğunu geçirdiğimiz sanal dünyada en sık kullanılan protokoldür.(%96 civarında) 
HTTP Nasıl Çalışır? Http’nin istemci-sunucu mantığıyla çalışan basit bir yapısı vardır. Önce TCP bağlantısı açılır, kullanıcı istek(HTTP isteği) gönderir sunucu da buna uygun cevap döner ve TCP bağlantısı kapatılır. İstemci(kullanıcı) tarafından gönderilen istekler birbirinden bağımsızdır ve normalde her HTTP isteği için bir TCP bağlantısı gerekir. HTTP’nin basitliğinin yanında günümüz web sayfaları sadece http sunuculardan oluşmaz, çoğu sistemin bilgilerini tutmak için kullanılan veri tabanları da artık web sayfalarının vazgeçilmez bileşeni olmuştur.

 
![30](https://user-images.githubusercontent.com/66878884/103564212-2c198980-4ecf-11eb-96ea-c56b4400f56e.jpg)


 
Kaba kuvvet DOS/DDOS Saldırıları Bu tip saldırılarda sunucu üzerinde ne çalıştığına bakılmaksızın eş zamanlı olarak binlerce istek gönderilir ve sunucunun kapasitesi zorlanır. Literatürde adı “GET Flood”, “POST Flood” olarak geçen bu saldırılar iki şekilde yapılabilir. Bir kişi ya da birden fazla kişinin anlaşarak belli bir hedefe eş zamanlı yüzlerce, binlerce istek gönderir ya da bu işi hazır kölelere(zombie) devredilerek etki gücü çok daha yüksek Dos saldırıları gerçekleştirilir. İlk yöntemde bir iki kişi ne yapabilir diye düşünülebilir fakat orta ölçekli çoğu şirketin web sayfası tek bir kişinin oluşturacağı eşzamanlı yüzlerce isteğe karşı uzun süre dayanamayacaktır. Güzel olan şu ki bu tip saldırıların gerçekleştirilmesi ne kadar kolaysa engellemesi de o kadar kolaydır (güvenlik duvarları/IPS’lerin rate limiting özelliği vs) İkinci yöntem yani Zombi orduları (BotNet’ler) aracılığıyla yapılan HTTP Flood saldırıları ise binlerce farklı kaynaktan gelen HTTP istekleriyle gerçekleştirilir. Gelen bağlantıların kaynağı dünyanın farklı yerlerinden farklı ip subnetlerinden gelebileceği için network seviyesinde bir koruma ya da rate limiting bir işe yaramayacaktır

Yazılımsal ya da tasarımsal eksikliklerden kaynaklanan DOS/DDOS Saldırıları Tasarımsal zafiyetler protokol düzenlenirken detaylı düşünülmemiş ya da kolaylık olsun diye esnek bırakılmış bazı özelliklerin kötüye kullanılmasıdır. Tasarımsal zafiyetlerden kaynaklanan DOS saldırılarına en iyi örnek geçtiğimiz aylarda yayınlanan Slowloris aracıdır. Bu araçla tek bir sistem üzerinden Apache HTTP sunucu yazılımını kullanan sistemler rahatlıkla devre dışı bırakılabilir. Benzeri şekilde Captcha kullanılmayan formlarda ciddi DOS saldırılarına yol açabilir. Mesela form üzerinden alınan bilgiler bir mail sunucu aracılığıyla gönderiliyorsa saldırgan olmayan binlerce e-posta adresine bu form üzerinden istek gönderip sunucunun mail sistemini kilitleyebilir. Zaman zaman da web sunucu yazılımını kullanan ve web sayfalarını dinamik olarak çalıştırmaya yarayan bileşenlerde çeşitli zafiyetler çıkmaktadır. Mesela yine geçtiğimiz günlerde yayınlanan bir PHP zafiyeti (PHP “multipart/formdata” denial of service)ni kullanılarak web sunucu rahatlıkla işlevsiz bırakabilir. Bu tip zafiyetler klasik sınır koruma araçlarıyla kapatılamayacak kadar karmaşıktır. Yazılımları güncel tutma, yapılandırma dosyalarını iyi bilme en iyi çözümdür. 
Web sunucularına yönelik performans test araçları DDOS korumasında web sunucularımızı olası bir DOS/DDOS’a maruz kalmadan test edip gerekli ayarlamaları, önlemleri almak yapılacak ilk işlemdir. Bunun için saldırganların hangi araçları nasıl kullanacağını bilmek işe yarayacaktır. Zira günümüzde saldırgan olarak konumlandırdığımız kişilerin eskisi gibi uzman seviyesinde bilgi sahibi olmasına gerek kalmamıştır, aşağıda ekran görüntüsünden görüleceği gibi sadece hedef ip/host girilerek etkili bir dos saldırısı başlatılabilir.

Web sunuculara yönelik DOS/DDOS saldırılarından korunma diğer DOS/DDOS yöntemlerine göre daha zordur(synflood, udp flood, smurf vs). Diğer saldırı yöntemleri genelde L4(TCP/UDP/ICMP) seviyesinde gerçekleştiği için ağ koruma cihazları( Router, Firewall, NIPS)tarafından belirli oranda engellenebilir fakat HTTP üzerinden yapılan DOS saldırılarında istekler normal kullanıcılardan geliyormuş gibi gözüktüğü için ağ güvenlik cihazları etkisiz kalmaktadır. Yine de web sunucular ve önlerine koyulacak ağ güvenlik cihazları iyi yapılandırılabilirse bu tip saldırılardan büyük oranda korunulabilir. • Kullanılan web sunucu yazılımı konfigürasyonunda yapılacak performans iyileştirmeleri • İstekleri daha rahat karşılayacak ve gerektiğinde belleğe alabilecek sistemler kullanılmalı Loadbalancer, reverseProxy kullanımı(Nginx gibi) • Firewall/IPS ile belirli bir kaynaktan gelebilecek max. İstek/paket sayısı sınırlandırılmalı (rate limiting kullanımı) • Saldırı anında loglar incelenerek saldırıya özel bir veri alanı belirlenebilirse (User-Agent, Refererer vs) IPS üzerinden özel imzalar yazılarak bu veri alanına sahip paketler engellenebilir fakat bunun normal kullanıcıları da etkileyeceği bilinmesi gereken nir konudur. • Web sunucunun desteklediği dos koruma modülleri kullanılabilir (Apache Mod_dosevasive) İyi yapılandırılmış bu modülle orta düzey DOS saldırılarının çoğu rahatlıkla kesilebilir. Fakat kullanırken dikkat edilmesi gereken bazı önemli noktalar vardır. Mesela DOS yaptığı şüphelenilen kullanıcılara HTTP 403 cevabı dönmek yerine doğrudan saldırı yapanları iptables(APF) ile bloklatmak sunucuyu gereksiz yere yormayacaktır.

DNS Hakkında Temel Bilgiler 
DNS Nedir? DNS(Domain Name System), temelde TCP/IP kullanılan ağ ortamlarında isimIP/IP-isim eşleşmesini sağlar ve e-posta trafiğinin sağlıklı çalışması için altyapı sunar. Günümüzde DNS’siz bir ağ düşünülemez denilebilir. Her yerel ağda –ve tüm internet ağında- hiyerarşik bir DNS yapısı vardır. Mesela bir e-postanın hangi adrese gideceğine DNS karar verir. Bir web sayfasına erişilmek istendiğinde o sayfanın nerede olduğuna, nerede tutulacağına yine DNS üzerinden karar verilir. Bir sistemin DNS sunucusunu ele geçirmek o sistemi ele geçirmek gibidir. 
DNS Protokol Detayı DNS, UDP temelli basit bir protokoldür. DNS başlık bilgisi incelendiğinde istek ve bu isteğe dönecek çeşitli cevaplar (kodlar kullanılarak bu cevapların çeşitleri belirlenmektedir)
 
 ![31](https://user-images.githubusercontent.com/66878884/103564215-2d4ab680-4ecf-11eb-8ed1-edfa4f4e994b.jpg)

 

Genellikle son kullanıcı – DNS sunucu arasındaki sorgulamalar Recursive tipte olur.
 Iterative dns sorgular Iterative sorgu tipinde, istemci dns sunucuya sorgu yollar ve ondan verebileceği en iyi cevabı vermesini bekler, yani gelecek cevap ya ben bu sorgunun cevabını bilmiyorum şu DNS sunucuya sor ya da bu sorgunun cevabı şudur şeklindedir. Genellikle DNS sunucular arasındaki sorgulamalar Iterative tipte olur. 
Genele Açık DNS Sunucular Herkese açık DNS sunucular (public dns) kendisine gelen tüm istekleri cevaplamaya çalışan türde bir dns sunucu tipidir. Bu tip dns sunucular eğer gerçekten amacı genele hizmet vermek değilse genellikle eksik/yanlış yapılandırmanın sonucu ortaya çıkar. Bir sunucunun genele açık hizmet(recursive DNS çözücü) verip vermediğini anlamanın en kolay yolu o DNS sunucusu üzerinden google.com, yahoo.com gibi o DNS sunucuda tutulmayan alan adlarını sorgulamaktır. Eğer hedef DNS sunucu genele açık bir DNS sunucu olarak yapılandırıldıysa aşağıdakine benzer çıktı verecektir.

Public DNS Sunucular Neden Güvenlik Açısından Risklidir? Public dns sunucuların özellikle DNS flood saldırılarına karşı sıkıntılıdırlar. Saldırgan public dns sunucuları kullanarak amplification dns flood saldırılarında size ait dns sunuculardan ciddi oranlarda trafik oluşturarak istediği bir sistemi zor durumda bırakabilir. 
NOT: DNS sunucu olarak ISC BIND kullanılıyorsa aşağıdaki tanımla recursive dns sorgularına –kendisi hariç- yanıt vermesi engellenebilir. options { allow-recursion { 127.0.0.1; };
 DNS Sunucu Yazılımları DNS hizmeti veren çeşitli sunucu yazılımlar bulunmaktadır. ISC Bind, DjbDNS, Maradns, Microsoft DNS yazılımları bunlara örnektir. Bu yazılımlar arasında en yoğun kullanıma sahip olanı ISC Bind’dır. Internetin %80 lik gibi büyük bir kısmı Bind dns yazılımı kullanmaktadır. [1] DNS Sunucu Tipini Belirleme DNS sunucu yazılımlarına gönderilecek çeşitli isteklerin cevapları incelenerek hangi tipte oldukları belirlenebilir. Bunun için temelde iki araç kullanılır: 
1. Nmap gibi bir port tarama/yazılım belirleme aracı 
2. Dig, nslookup gibi klasik sorgulama araçları
 
 ![32](https://user-images.githubusercontent.com/66878884/103564216-2e7be380-4ecf-11eb-8019-e9465099c5f4.jpg)

![33](https://user-images.githubusercontent.com/66878884/103564217-2f147a00-4ecf-11eb-8068-b733fcb5bae7.jpg)

 
 
DNS’e Yönelik DoS ve DDoS Saldırıları
 DNS hizmetine yönelik Dos/DDoS saldırılarını iki kategoride incelenebilir 
• Yazılım temelli DoS saldırıları 
• Tasarım temelli DoS saldırıları 
Yazılım Temelli DoS Saldırıları 
BIND 9 Dynamic Update DoS Zaafiyeti 28.07.2009 tarihinde ISC Bind yazılım geliştiricileri tüm Bind 9 sürümlerini etkileyen acil bir güvenlik zaafiyeti duyurdular. Duyuruya göre eğer DNS sunucunuz Bind9 çalıştırıyorsa ve üzerinde en az bir tane yetkili kayıt varsa bu açıklıktan etkileniyor demektir. Aslında bu zafiyet bind 9 çalıştıran tüm dns sunucularını etkiler anlamına gelmektedir. Bunun nedeni dns sunucunuz sadece caching yapıyorsa bile üzerinde localhost için girilmiş kayıtlar bulunacaktır ve açıklık bu kayıtları değerlendirerek sisteminizi devre dışı bırakabilir.
 Güvenlik Açığı Nasıl Çalışır? Açıklık dns sunucunuzdaki ilgili zone tanımı(mesela:www.lifeoverip.net) için gönderilen özel hazırlanmış dynamic dns update paketlerini düzgün işleyememesinden kaynaklanmaktadır.
 Açıklığın sonucu olarak dns servisi veren named prosesi durmakta ve DNS sorgularına cevap dönememektedir.

DNS Flood DoS/DDoS Saldırıları Bu saldırı tipi genelde iki şekilde gerçekleştirilir:
 ● Hedef DNS sunucuya kapasitesinin üzerinde (bant genişliği olarak değil) DNS istekleri göndererek, normal isteklere cevap veremeyecek hale gelmesini sağlamak 
● Hedef DNS sunucu önündeki Firewall/IPS’in “session” limitlerini zorlayarak Firewall arkasındaki tüm sistemlerin erişilemez olmasını sağlamak Her iki yöntem için de ciddi oranlarda DNS sorgusu gönderilmesi gerekir. Internet üzerinden edinilecek poc(proof of concept) araçlar incelendiğinde çoğunun perl/python gibi script dilleriyle yazıldığı ve paket gönderme kapasitelerinin max 10.000-15.000 civarlarında olduğu görülecektir


![34](https://user-images.githubusercontent.com/66878884/103564218-2fad1080-4ecf-11eb-8e51-8a288f17a8c5.jpg)

![35](https://user-images.githubusercontent.com/66878884/103564223-30de3d80-4ecf-11eb-86e3-dac0c5609199.jpg)


 
 
Bilinen DNS Sunucu IP Adreslerinden DNS Flood Gerçekleştirme
 Aynı şekilde subnet kullanımı da gerçekleştirilebilir. Tüm atak bir subnet ya da bir ip aralığı ya da bir ülke ip adresinden geliyormuş gibi gösterilebilir. Bu tip saldırılarda hedef DNS sunucunun önünde gönderilen paket sayısına göre rate limiting/karantina uygulayan IPS, DDoS Engelleme sistemi varsa paket gönderilen sahte ip adresleri bu cihazlar tarafından engellenecektir. Bu da saldırgana internet üzerinde istediği ip adreslerini engelletme lüksü vermektedir.


Bilgi Güvenliğinde Sızma Testleri 
Giriş Günümüz bilgi güvenliğini sağlamak için iki yaklaşım tercih edilmektedi. . Bunlardan ilki savunmacı yaklaşım(defensive) diğeri de proaktif yaklaşım (offensive)olarak bilinir. Bunlardan günümüzde kabul göreni proaktif yaklaşımdır. Pentest –sızma testleri– ve vulnerability assessment –zayıflık tarama- konusu proaktif güvenliğin en önemli bileşenlerinden biridir. Son yıllarda gerek çeşitli standartlara uyumluluktan gerekse güvenliğe verilen önemin artmasından dolayı sızma testleri ve bu konuda çalışanlara önem ve talep artmıştır. Bu yazıda sızma testleri ile ilgili merak edilen sorulara sektörün gözünden cevap verilmeye çalışılacaktır. Yazı, sızma testleri konusunda teknik detaylar içermemektedir. Sızma testleri konusunda teknik bilgiler için http://blog.bga.com.tr adresi takip edilebilir.




 
Sızma Testleri Lüks mü İhtiyaç mı? Sahip olduğunuz bilişim sistemlerindeki güvenlik zaafiyetlerinin üçüncü bir göz tarafından kontrol edilmesi ve raporlanması proaktif güvenliğin ilk adımlarındandır. Siz ne kadar güvenliğe dikkat ederseniz birşeylerin gözünüzden kaçma ihtimali vardır ve internette hackerlarin sayısı ve bilgi becerisi her zaman sizden iyidir. Hackerlara yem olmadan kendi güvenliğinizi bu konudaki uzmanlara (beyaz şapkalı hacker, ethical hacker, sızma test uzmanı vs)test ettirmek firmanın yararına olacaktır. Sağlam bir ekibe yaptırılacak sızma testleri internet üzerinden gelebilecek tehditlerin büyük bir kısmını ortaya çıkarıp kapatılmasını sağlayacaktır. Bununla birlikte bilişim güvenliğinin zamana bağımsız dinamik bir alan olduğu gözönünde bulundurulursa sızma testlerinin tek başına yeterli olmayacağı aşikardır. Sızma testlerinini bitimini takip eden günlerde ortaya çıkabilecek kritik bir güvenlik zafiyeti kurumları zor durumda bırakmak için yeterlidir. Dolayısıyla sızma testleri ile yetinmeyerek mutlaka katmanlı güvenlik mimarisinin kurum güvenlik politikalarında yerini alması önerilmektedir. Güvenlik açısından olduğu kadar çoğu kurum ve kuruluş için sızma testleri ISO 27001, PCI, HIPAA gibi standartlarla zorunlu hale getirilmiştir. Sızma testleri maliyetli bir iştir ve genellikle yöneticiler tarafındans ROI(Return of investment)si hesaplanamayan ya da hatalı hesaplanan bir projedir. Burada iş bilgi güvenliği uzmanlarına düşmektedir. Gerçekleştirilen sızma testlerinin sonuçları yöneticilerin anlayacağı uygun bir biçimde üst yönetime anlatılmalı ve yapılan işin şirkete uzun vadeli kazandırdıkları gösterilmelidir. Kısaca sızma testleri konusunda uzman ekiplere sahip firmalara yaptırılırsa değerli bir iştir, bunun haricinde sadece vicdani rahatlık sağlar ve standartlara uyumluluk kontrol listelerinden bir madde daha tamamlanmış olur.

Sızma Testlerinde Genel Kavramlar 
Pentest, Vulnerability Assessment ve Risk Asssessment Kavramları 
Sızma Testleri (Pentest): Belirlenen bilişim sistemlerine mümkün olabilecek ve müşteri tarafından onayı verilmiş her yolun denenerek sızılmaya çalışma işlemine pentest denir. Pentest de amaç güvenlik açıklığını bulmaktan öte bulunan açıklığı değerlendirip sistemlere yetkili erişimler elde etmek ve elde edilen erişimler kullanılarak tüm zafiyetlerin ortaya çıkarılmasıdır. 
Sızma Test Çeşitleri Gerçekleştirilme yöntemlerine göre sızma testleri üçe ayrılmaktadır. Bunlar aşağıdaki gibi listelenmektedir. 
• Whitebox 
• Blackbox 
• Graybox
 Black box Pentest – Kapalı Kutu Sızma Testleri Bunlardan blackbox bizim genelde bildiğimiz ve yaptırdığımız pentest yöntemidir. Bu yöntemde testleri gerçekleştiren firmayla herhangi bir bilgi paylaşılmaz. Firma ismi ve firmanın sahip olduğu domainler üzerinden firmaya ait sistemler belirlenerek çalışma yapılır. 
White box Pentest – Açık Kutu Sızma Testleri Bu sızma test yönteminde firma tüm bilgileri paylaşır ve olabildiğince sızma testi yapanlara bilgi verme konusunda yardımcı olur. 
Zafiyet Değerlendirme Testleri (Vulnerability Assessment): Belirlenen sistemlerde güvenlik zaafiyetine sebep olabilecek açıklıkların araştırılması. Bu yöntem için genellikle otomatize araçlar kullanılır(Nmap, Nessus, Qualys vs)gibi. Vulnerability assessment çalışmaları sızma testleri kadar tecrübe zaman gerektirmeyen çalışmalardır. Risk assessment tamamen farklı bir kavram olup pentest ve vuln. assessmenti kapsar. Zaman zaman technical risk assessment tanımı kullanılarak Vulnerability assessment kastedilir.

Sızma Testlerinde Proje Yönetimi Gerçekleştirilecek sızma testlerinden en yüksek verimi alabilmek için her işte olduğu gibi burada da plan yapmak gerekir. Pentest planı oluşturmaya başlamak için aşağıdaki temel sorular yeterli olacaktır: 
● Pentest’in kapsamı ne olacak? 
● Sadece iç ağ sistemlerimimi, uygulamalarımı mı yoksa tüm altyapıyı mı test ettirmek istiyorum 
● Testleri kime yaptıracağım 
● Ne kadar sıklıkla yaptırmalıyım
 ● Riskli sistem ve servisler kapsam dışı olmalı mı yoksa riski kabul edip sonucunu görmelimiyim. 
● DDOS denemesi yapılacak mı 
● Pentest sonuç raporundaki zafiyetleri kapatmak icin idari gücüm var mı?

 
![36](https://user-images.githubusercontent.com/66878884/103564225-320f6a80-4ecf-11eb-8cf5-935b60674e38.jpg)





Müşteri İçin Pentest Proje Zaman Çizelgesi 
1. Pentest yapmak için karar verilir 
2. Temel kapsam belirlenir . Hangi bileşenlerin test edileceği konusunda Kapsam Belirleme kısmı yardımcı olacaktır. 
3. Firma araştırması [Firma seçimi konusunda dikkat edilmesi gereken maddeler incelenmeli
4. Firmalardan teklif toplama 
5. Firmalardan kapsam önerilerini isteme 
6. Firmalardan örnek sızma test raporu isteme 
7. Gerekli durumda kapsam belirleme için firmayla ek toplantılar 8. Firmaya karar verme ve sızma testlerine başlama

Sızma Testlerinde Kapsam Belirleme Çalışması Sızma testinde ana amaçlardan biri tüm zafiyetlerin degerlendirilerek sisteme sızılmaya çalışılmasıdır. Bu amaç doğrultusunda gerçekleştirilecek sızma testlerinde kapsam pentest çalışmasının en önemli adımını oluşturmaktadır. Sistem/ağ yöneticileri ile hackerların bakış açısı farklıdır ve sitem/ağ yöneticisi tarafından riskli görülmeyen bir sunucu/sistem hacker için sisteme sızmanın ilk adımı olabilir. Bu nedenle kapsam çalışmalarında mutlaka pentest yaptırılacak kişi/firma ile ortaklaşa hareket edilmelidir. Aşağıdaki resim kapsam konusunun önemimi çok iyi göstermektedir.
 ![37](https://user-images.githubusercontent.com/66878884/103564226-320f6a80-4ecf-11eb-89dc-1c1ed86223ba.jpg)

Kapsam belirlemek için standart bir formül yoktur. Her firma ve ortam için farklı olabilmektedir. Genellikle sızma testleri aşağıdaki gibi alt bileşenlere ayrılmaktadır
. ● Web uygulama sızma testleri
 ● Son kullanıcı ve sosyal mühendislik testleri 
● DDoS ve performans testleri 
● Ağ altyapısı sızma testleri 
● Yerel ağ sızma testleri 
● Mobil uygulama güvenlik testleri
● Sanallaştırma sistemleri sızma testleri 
Kapsam belirleme konusunda sızma testini gerçekleştirecek firma ve hizmeti alacak firma birlikte karar vermelidir. Genellikle hizmet alan firma maliyetleri düşürmek için kapsamı olabildiğince daraltmaya çalışmakta ve kapsam olarak güvenli olduğu düşünülen sistemlerin ip adresleri verilmekte ya da örnekleme yapılmaya çalışılmaktadır. Oysa sızma testlerinde ana amaçlardan birisi en zayıf noktayı kullanarak sisteme sızmak, sızılabildiğini göstermektir. Kapsam konusunda sadece ip adresi alarak sızma testi yapılmaz. Bir web uygulamasını test etmek ile DNS sunucuyu, güvenlik duvarını test etmek çok farklıdır. Yine statik içerik barındıran bir web sitesi ile dinamik içerik barındıran web sayfasını test etmek de içerik ve üzerine harcanan emek açısından oldukça farklıdır.

 Firma Seçimi Sızma testleri sonuçları somut olmayan hizmetler kapsamındadır. Firmalar kendilerinin uzman olduklarını farklı şekilde ortaya koyabilirler. Bunlardan en önemlisi firmanın referansları ve bu konuda çalıştırdığı kişilerin yetkinliği ve firmanın sızma testlerine olan ilgisidir. Güvenlik ürün çözümleri sunup yanında sızma testleri yapan firmalar genellikle halihazırda sundukları ürünleri satabilmek için sızma testleri gerçekleştirir ve sonuçları daha çok ürün satmaya yönelik olur. Tek işi sızma testleri ve benzeri hizmetler vermek olan firmalar bu konuda daha öncelikli olarak değerlendirilmelidir. Firma seçimi konusunda yardımcı olabilecek bazı maddeler aşağıdaki gibi sıralanabilir. 
 Firmada test yapacak çalışanların CVlerini isteyin . Varsa testi yapacak çalışanların konu ile ilgili sertifikasyonlara sahip olmasını ercih edin. 
 Testi yapacak çalışanların ilgili firmanın elemanı olmasına dikkat edin. 
 Firmaya daha önceki referanslarını sorun ve bunlardan birkaçına memnuniyetlerini sorun.
  Mümkünse firma seçimi öncesinde teknik kapasiteyi belirlemek için tuzak sistemler kurarak firmaların bu sistemlere saldırması ve sizin de bildiğiniz açıklığı bulmalarını isteyin. 

 Firmadan daha önce yaptığı testlerle ilgili örnek raporlar isteyin.
 Testlerin belirli ip adreslerinden yapılmasını ve bu ip adreslerinin size bildirilmesini talep edin.
  Firmaya test için kullandıkları standartları sorun. 
 Firmanın test raporunda kullandığı tüm araçları da yazmasını isteyin.
  Pentest teklifinin diğerlerine göre çok düşük olmaması En önemli maddelerden biri Penetration test firmanın özel işi mi yoksa oylesine yaptığı bir iş mi? Bu sorgu size firmanın konu hakkında yetkinliğine dair ipuçları verecektir. Ücretiz sızma testi hizmeti veren firmalar genellikle sızma testi konusunu yan iş olarak yapmaktadır ve bu konuda alınacak hizmetin kalitesi sıfıra yakın olacaktır. Sızma testleri tamamen uzmanlık alanı bu olan kişi/firmalara bırakılmalıdır. Genellikle ürün satmak için ücretsiz sızma testleri gerçekleştiren firmaların yapacağı sızma testleri otomatik araçlarla taramanın ötesine geçememektedir.

Sızma Test Metodolojisi Kullanımı İşinin ehli bir hacker kendisine hedef olarak belirlediği sisteme sızmak için daha önce edindiği tecrübeler ışığında düzenli bir yol izler. Benzeri şekilde sızma testlerini gerçekleştiren uzmanlar da çalışmalarının doğrulanabilir, yorumlanabilir ve tekrar edilebilir olmasını sağlamak için metodoloji geliştirirler veya daha önce geliştirililen bir metodolojiyi takip ederler. Metodoloji kullanımı bir kişilik olmayan sızma test ekipleri için hayati önem taşımaktadır ve sızma testlerinde daha önce denenmiş ve standart haline getirilmiş kurallar izlenirse daha başarılı sonuçlar elde edilir Internet üzerinde ücretsiz olarak edinilebilecek çeşitli güvenlik testi kılavuzları bulunmaktadır. 
Bunların başında ; 
• OWASP(Open Web Application Security Project) 
• OSSTMM(The Open Source Security Testing Methodology Manual)
 • ISSAF(Information Systems Security Assessment Framework) 
• NIST SP800-115 gelmektedir. Internetten ücretsiz edinilebilecek bu test metodojileri incelenerek yapılacak güvenlik denetim testlerinin daha sağlıklı ve tekrar edilebilir sonuçlar üretmesi sağlanabilir. Metodoloji hazırlanmasında dikkat edilmesi gereken en önemli hususlardan biri sızma test metodolojisinin araç tabanlı (X adımı icin Y aracı kullanılmalı gibi) olmamasına dikkat edilmesidir.

BGA Sızma Test Metodolojisi Sızma testlerinde ISSAF tarafından geliştirilen metodoloji temel alınmıştır. Metodolojimiz üç ana bölümde dokuz alt bölümden oluşmaktadır.
 
 ![38](https://user-images.githubusercontent.com/66878884/103564228-32a80100-4ecf-11eb-99c8-ac4bd3511e6e.jpg)


1.1 [Bilgi Toplama] Amaç, hedef sistem hakkında olabildiğince detaylı bilgi toplamaktır. Bu bilgiler firma hakkında olabileceği gibi firma çalışanları hakkında da olabilir. Bunun için internet siteleri haber gruplari e-posta listeleri , gazete haberleri vb., hedef sisteme gönderilecek çeşitli paketlerin analizi yardımcı olacaktır.



Bilgi toplama ilk ve en önemli adımlardan biridir. Zira yapılacak test bir zaman işidir ve ne kadar sağlıklı bilgi olursa o kadar kısa sürede sistemle ilgili detay çalışmalara geçilebilir. Bilgi toplamada aktif ve pasif olmak üzere ikiye ayrılır. Google, pipl, Shodan, LinkedIn, facebook gibi genele açık kaynaklar taranabileceği gibi hedefe özel çeşitli yazılımlar kullanılarak DNS, WEB, MAIL sistemlerine yönelik detaylı araştırmalar gerçekleştirilir. Bu konuda en iyi örneklerden biri hedef firmada çalışanlarından birine ait e-posta ve parolasının internete sızmış parola veritabanlarından birinden bulunması ve buradan VPN yapılarak tüm ağın ele geçirilmesi senaryosudur. 
Sızma testlerinde bilgi toplama adımı için kullanılabilecek temel araçlar: 
• FOCA 
• theharvester 
• dns 
• Google arama motoru
 • Shodan arama motoru 
• E-posta listeleri, LinkedIn, Twitter ve Facebook

1.2 [Ağ Haritalama] Amaç hedef sistemin ağ yapısının detaylı belirlenmesidir. Açık sistemler ve üzerindeki açık portlar, servisler ve servislerin hangi yazılımın hangi sürümü olduğu bilgileri, ağ girişlerinde bulunan VPN, Firewall, IPS cihazlarının belirlenmesi, sunucu sistemler çalışan işletim sistemlerinin ve versiyonlarının belirlenmesi ve tüm bu bileşenler belirlendikten sonra hedef sisteme ait ağ haritasının çıkartılması Ağ haritalama adımlarında yapılmaktadır. Ağ haritalama bir aktif bilgi toplama yöntemidir. Ağ haritalama esnasında hedef sistemde IPS, WAF ve benzeri savunma sistemlerinin olup olmadığı da belirlenmeli ve gerçekleştirilecek sızma testleri buna göre güncellenmelidir. Ağ Haritalama Amaçlı Kullanılan Temel Araçlar • Nmap, • unicornscan 
1.3 [Zafiyet/Zayıflık Tarama Süreci] Bu sürecin amacı belirlenen hedef sistemlerdeki açıklıkların ortaya çıkarılmasıdır. Bunun için sunucu servislerdeki bannerler ilk aşamada kullanılabilir. Ek olarak birden fazla zayıflık tarama aracı ile bu sistemler ayrı ayrı taranarak oluşabilecek false positive oranı düşürülmeye çalışılır.

Bu aşamada hedef sisteme zarar vermeycek taramalar gerçekleştirilir. Zayıflık tarama sonuçları mutlaka uzman gözler tarafından tekrar tekrar incelenmeli, olduğu gibi rapora yazılmamalıdır. Otomatize zafiyet tarama araçlar ön tanımlı ayarlarıyla farklı portlarda çalışan servisleri tam olarak belirleyememktedir.
 Zafiyet Tarama Amaçlı Kullanılan Temel Araçlar 
• Nessus 
• Nexpose 
• Netsparker 
2.1 [Penetrasyon(Sızma) Süreci] Belirlenen açıklıklar için POC kodları/araçları belirlenerek denelemeler başlatılır. Açıklık için uygun araç yoksa ve imkan varsa ve test için yeteri kadar zaman verilmişse sıfırdan yazılır. Genellikle bu tip araçların yazımı için Python, Ruby gibi betik dilleri tercih edilir. Bu adımda dikkat edilmesi gereken en önemli husus çalıştırılacak exploitlerden önce mutlaka yazılı onay alınması ve mümkünse lab ortamlarında önceden denenmesidir. 
Sızma Sürecinde Kullanılan Temel Araçlar
 • Metasploit, Metasploit Pro 
• Core Impact, Immunity Canvas 
• Sqlmap 
• Fimap 
2.2 [Erişim Elde Etme ve Hak Yükseltme] Sızma sürecinde amaç sisteme bir şekilde giriş hakkı elde etmektir. Bu süreçten sonra sistemdeki kullanıcının haklarının arttırılması hedeflenmelidir. Linux sistemlerde çekirdek (kernel) versiyonunun incelenerek priv. escelation zafiyetlerinin belirlenmesi ve varsa kullanılarak root haklarına erişilmesi en klasik hak yükseltme adımlarından biridir. Sistemdeki kullanıcıların ve haklarının belirlenmesi, parolasız kullanıcı hesaplarının belirlenmesi, parolaya sahip hesapların uygun araçlarla parolalarının bulunması bu adımın önemli bileşenlerindendir.

Hak Yükseltme Amaç edinilen herhangi bir sistem hesabı ile tam yetkili bir kullanıcı moduna geçişttir.(root, administrator, system vs) Bunun için çeşitli exploitler denenebilir. Bu sürecin bir sonraki adıma katkısı da vardır. Bazı sistemlere sadece bazı yetkili makinelerden ulaşılabiliyor olabilir. Bunun için rhost, ssh dosyaları ve mümkünse history’den eski komutlara bakılarak nerelere ulaşılabiliyor detaylı belirlemek gerekir.

 2.3 [Detaylı Araştırma] Erişim yapılan sistemlerden şifreli kullanıcı bilgilerinin alınarak daha hızlı bir ortamda denenmesi. Sızılan sistemde sniffer çalıştırılabiliyorsa ana sisteme erişim yapan diğer kullanıcı/sistem bilgilerinin elde edilmesi. Sistemde bulunan çevresel değişkenler ve çeşitli network bilgilerinin kaydedilerek sonraki süreçlerde kullanılması. Linux sistemlerde en temel örnek olarak grep komutu kullanılabilir. grep parola|password|sifre|onemli_kelime -R / 




3.1 [Erişimlerin Korunması] Sisteme girildiğinin başkaları tarafından belirlenmemesi için bazı önlemlerin alınmasında fayda vardır. Bunlar giriş loglarının silinmesi, çalıştırılan ek proseslerin saklı olması , dışarıya erişim açılacaksa gizli kanalların kullanılması(covert channel), backdoor, rootkit yerleştirilmesi vs. 
3.2 [İzlerin silinmesi ] Hedef sistemlere bırakılmış arka kapılar, test amaçlı scriptler, sızma testleri için eklenmiş tüm veriler not alınmalı ve test bitiminde silinmelidir. 
3.3 [Raporlama] Raporlar bir testin müşteri açısından en önemli kısmıdır. Raporlar ne kadar açık ve detaylı/bilgilendirici olursa müşterinin riski değerlendirmesi ve açıklıkları gidermesi de o kadar kolay olur. Testler esnasında çıkan kritik güvenlik açıklıklarının belgelenerek sözlü olarak anında bildirilmesi test yapan takımın görevlerindendir. Bildirimin ardından açıklığın hızlıca giderilmei için çözüm önerilerinin de birlikte sunulması gerekir. Ayrıca raporların teknik, yönetim ve özet olmak üzere üç farklı şekilde hazırlanmasında fayda vardır. Teknik raporda hangi uygulama/araçların kullanıldığı, testin yapıldığı tarihler ve çalışma zamanı, bulunan açıklıkların detayları ve açıklıkların en hızlı ve kolay yoldan giderilmesini amaçlayan tavsiyeler bulunmalıdır.

Zamanlama Hedef sistemlerin kritiklik durumlarına göre sızma testlerinin zamanlaması ayarlanmalıdır. DDoS testlerinin genellikle hafta sonu ve gece yarısı gerçekleştirilmesi önerilmektedir. Bunun haricinde diğer testlerin gün içinde veya mesai saatleri sonrası yapılması tamamen müşterinin talebine bağlı değişkenlik göstermektedir. Fakat hedef sistemi performans açısından zorlayabilecek taramalar mesai saatleri dışında yapılması tercih edilmelidir.

Exploit Denemeleri Sızma testlerinin en önemli adımlarıdan biri exploiting aşamasıdır. Bu adımla hedef sistem üzerinde bulunan güvenlik zafiyetleri istismar edilir ve sisteme sızılacak yollar belirlenebilir. Test yapan firmanın kalitesinin göstergelerinden biri de bu adımıdaki başarılarıdır. Exploit çalıştırma denemelerinde mutlaka müşteri tarafı ile koordinasyon içinde olunmalı. Aksi hale hedef sistemi ele geçirmek amacıyla çalıştırılan bir exploit hedef sistemin bir daha açılmamasına, yeniden başlamasına ya da veri kaybına sebep olabilir. BGA olarak genellikle test yapılacak firmalara ait bilişim sistemlerinin bir kopyaları kendi lab ortamımızda kurulu ve exploit öncesi denemeler gerçekleştirilir. 
Pentest Çalışmasının Kayıt Altına Alınması Bazı durumlarda hedef sistemde istenmeyen, beklenmeyen sonuçlar yaşanabilir. Testler esnasında hedef sistemden verilerin silinmesi, test yapılan ağın çökmesi, veya müşteri bilgilerinin internet ortamına sızması gibi. Bu gibi durumlarda sızma testlerini gerçekleştiren firmanın kendini sağlama alması açısından tüm sızma test adımlarının raw paket olarak kayıt altına alması önemlidir. Yaşanabilecek herhangi bir olumsuz durumda kayıt altına alınan paketlerden problem çözümü kolaylıkla sağlanabilir. Pentest yapacak firma ne kadar güvenili olsa da-aranizda muhakkak imzalı ve maddeleri açık bir NDA olmalı- siz yine de kendinizi sağlama alma açısından firmanın yapacağı tüm işlemleri loglamaya çalışın.

Raporlama Sızma testlerinin en önemli bileşenlerinden biri raporlamadır. Ticari açıdan yaklaşıldığında pentest yaptıran müşteri rapora para vermektedir. Dolayısıyla pentest raporunun olabildiğince detaylı ve müşteriyi doğru yönlendirecek nitelikte olması gerekir. Doğrudan otomatik analiz ve tarama araçlarının çıktılarını rapora eklemek müşterinin karşılaşmak istemediği durumların başında gelmektedir.

 Raporun İletimi Raporun mutlaka şifreli bir şekilde müşteriye ulaştırılması gerekir. Raporu açmak için gerekli olan parolanın e-posta harici başka bir yöntemle müşteriye ulaştırılabilir. Sık tercih edilen yöntem SMS kullanımıdır.




![39](https://user-images.githubusercontent.com/66878884/103564231-33409780-4ecf-11eb-9d7b-c3d00976bab6.jpg)




 
● Sistem yöneticileri/yazılımcılarla toplantı yapıp sonuçların paylaşılması 
● Açıklıkların kapatılmasının takibi 
● Bir sonraki pentestin tarihinin belirlenmesi 
Sızma Testlerinde Kullanılan Araçlar: Öncelikle sızma test kavramının araç bağımsız olduğunu belirtmek gerekir. Bu konudaki yazılımlar Açık kodlu bilinen çoğu pentest yazılımı Backtrack güvenlik CDsi ile birlikte gelir. Bu araçları uygulamalı olarak öğrenmek isterseniz Backtrack ile Penetrasyon testleri eğitimine kayıt olabilirsiniz. 

Ticari Pentest Yazılımları: Immunity Canvas, Core Impact, HP Webinspect, Saint Ssecurity Scanner 

Sızma Testleri Konusunda Uzmanlık Kazanma Pentest konusunda kendinizi geliştirmek için öncelikle bu alana meraklı bir yapınızın olmasın gerekir. İçinizde bilişim konularına karşı ciddi merak hissi , sistemleri bozmaktan korkmadan kurcalayan bir düşünce yapınız yoksa işiniz biraz zor demektir. Zira pentester olmak demek başkalarının düşünemediğini düşünmek, yapamadığını yapmak ve farklı olmak demektir. Bu işin en kolay öğrenimi bireysel çalışmalardır, kendi kendinize deneyerek öğrenmeye çalışmak, yanılmak sonra tekrar yanılmak ve doğrsunu öğrenmek. Eğitimler bu konuda destekci olabilir. Sizin 5-6 ayda katedeceğiniz yolu bir iki haftada size aktarabilir ama hiçbir zaman sizi tam manasıyla yetiştirmez, yol gösterici olur. Pentest konularının konuşulduğu güvenlik listelerine üyelik de sizi hazır bilgi kaynaklarına doğrudan ulaştıracak bir yöntemdir. Linux öğrenmek, pentest konusunda mutlaka elinizi kuvvetlendirecek, rakiplerinize fark attıracak bir bileziktir. Bu işi ciddi düşünüyorsanız mutlaka Linux bilgisine ihtiyaç duyacaksınız.
 Sızma Testleri Konusunda Verilen Eğitimler
 ● Bilgi Güvenliği AKADEMİSİ Pentest Eğitimleri
 ● Ec-Council Pentest Eğitimleri ● SANS Pentest Eğitimleri ● Offensive Security Pentest Eğitimleri





Nmap
 
 
Nmap Nmap, bilgisayar ağları uzmanı Gordon Lyon (Fyodor) tarafından C/C++ ve Python programlama dilleri kullanılarak geliştirilmiş bir güvenlik tarayıcısıdır. Taranan ağın haritasını çıkarabilir ve ağ makinalarında çalışan servislerin durumlarını, işletim sistemlerini, portların durumlarını gözlemleyebilir. 
Nmap kullanarak ağa bağlı herhangi bir bilgisayarın işletim sistemi, çalışan fiziksel aygıt tipleri, çalışma süresi, yazılımların hangi servisleri kullandığı, yazılımların sürüm numaraları, bilgisayarın ateşduvarına sahip olup olmadığı, ağ kartının üreticisinin adı gibi bilgiler öğrenilebilmektedir. 
Nmap tamamen özgür GPL ( General Public Licence ) lisanslı yazılımdır ve istendiği takdirde sitesinin ilgili bölümünden kaynak kodu indirilebilmektedir. 
Nmap kullanım alanları :
 • Herhangi bir ağ hazırlanırken gerekli ayarların test edilmesinde. 
• Ağ envanteri tutulması, haritalaması, bakımında ve yönetiminde. 
• Bilinmeyen yeni sunucuları tanımlayarak, güvenlik denetimlerinin yapılması. 
Nmap Çalışma Prensibi Nmap çok güçlü bir uygulama olmasına rağmen, yeni başlayanlar için anlaşılması zordur. Nmap yaklaşık 15 farklı tarama yöntemine ve her tarama için yaklaşık 20 farklı seçeneğe (çıktı seçenekleri dahil) sahiptir. Nmap tarama süreci ile ilgili bilgiler aşağıda belirtilmiştir :
 1. Taranılacak olan hedef makinanın ismi girilirse, Nmap öncellikle DNS lookup işlemi yapar. Bu aslında bir Nmap fonksiyonu değil, ancak DNS sorguları network trafiğinde gözüktüğünden beri, her durum loglanır. Bu yüzden isim ile tarama yapmadan önce bunun bilinmesinde fayda vardır. Eğer isim yerine IP girilirse, DNS lookup işlemi yapılmayacaktır. DNS lookup işleminin iptal edilmesinin bir yolu bulunmuyor, sadece Nmapin üzerinde bulunduğu makinanın host veya lmhost dosyalarının içinde IP – DNS eşleşmesi varsa DNS lookup yapılmaz. 
2. Nmap hedef makinayı “ping”ler. Ancak bu bilinen ICMP ping işlemi değildir. Nmap farklı bir ping işlemi kullanır. Bu işlem hakkında bilgi ilerleyen bölümlerde verilecektir. Eğer ping işlemini iptal edilmek isteniyorsa –P0 seçeneği kullanılmalıdır. 
3. Eğer hedef makinanın IP adresi belirtildiyse, Nmap reverse DNS lookup yaparak IP – Hostname eşleşmesi yapar. Bu 1. Adımda gerçekleştirilen olayın tersidir. Bu işlem, ilk adımda DNS lookup yapılmasına rağmen gereksiz gözükebilir. Ancak IP-Hostname sonuçları ile Hostname-IP sonuçları farklı çıkabilir. 
 
 ![40](https://user-images.githubusercontent.com/66878884/103564233-3471c480-4ecf-11eb-912c-00c4cd08ae94.jpg)


Yetki Yükseltme Nmap seçeneklerinin hepsi ve işletim sistemi kontrollerini gerçekleştiren yapıları bypass etmek için özelleştirilmiş “raw” paketler, sadece yüksek yetkilere sahip kullanıcıların taramalarında bulunabilir. Unix,Linux için root, Windows için Administrator olmak gerekir.
 Sunucuları/İstemcileri Keşfetme Organizasyon içerisindeki hostları bulmak için çok önemli bir yöntemdir. Keşfetme işlemi için birçok seçenek kullanılabilir. En basit yolu bir ping scan gerçekleştirmektir : ( Ping Scan hakkında detaylı bilgi Tarama bölümünde mevcuttur. )




#nmap -sP 192.168.2.0/24 
Host 192.168.2.1 appears to be up.
 Host 192.168.2.3 appears to be up. 
Host 192.168.2.4 appears to be up. 
Nmap done: 256 IP addresses (3 hosts up) scanned in 1.281 seconds 
Ping scan belirtilen hedef veya hedeflerin 80. portuna ICMP echo request ve TCP ACK ( root veya Administrator değilse SYN ) paketleri gönderir. Hedef veya hedeflerden dönen tepkilere göre bilgiler çıkartılır. Hedef/hedefler Nmap ile aynı yerel ağda bulunuyorsa, Nmap hedef/hedeflerin MAC adreslerini ve ilgili üreticiye ait bilgileri (OUI ) sunar. Bunun sebebi, Nmap varsayılan olaran ARP taraması, -PR, yapar. Bu özelliği iptal etmek için- -send-ip seçeneği kullanılabilir. Ping scan portları taramaz yada başka tarama tekniklerini gerçekleştirmez. Ping scan network envanteri vb. işlemler için idealdir.

Keşfetme işlemleri için bazı seçenekler aşağıda sunulmuştur :


 • -sL: List Scan – Hedefleri ve DNS isimlerinin bir listesini çıkarır.
 • -sn: Ping Scan - Port scan seçeneğini iptal eder. 
• -Pn: Host discovery yapılmaz, bütün hostlar ayakta gözükür.
 • -n/-R: Asla DNS Çözümlemesi yapılmaz/Herzaman DNS çözümlemesi yapılır *varsayılan: bazen]
 • --dns-servers : Özel DNS serverlerı belirtmek için kullanılır. 
• --system-dns: OS e ait DNS çözümleyici kullanılır. 
• --traceroute: Traceroute özelliğini aktif hale getirir. TCP Connect ve Idle Scan dışındaki tarama türleri ile yapılmaz.
• -p : port veya port aralıklarını belirtmek için kullanılır. -p22; -p1-65535; -p U:53,111,137,T:21- 25,80,139,8080,S:9
 • -F: Fast mode, varsayılan taramalarda belirlenen portlardan biraz daha azı kullanılır.
 • -r: Portları sırayla tarar. Rastgele tarama kullanılmaz.
 • --top-ports : ile belirtilen ortak portları taranır.
 • p--port-ratio : Belirtilen üzerinden ortak portlar taranır.
 • - -randomize_hosts, -rH : Listede belirtilen taranılacak hostları rastgele bir şekilde seçer.
 • - -source_port, -g : Taramayı yapacak olan makinanın kaynak portunu belirlemek amacıyla kullanılır.
 • -S : Kaynak IP yi belirlemek amacıyla kullanılır. 
• -e : Network arayüzünü belirlemek amacıyla kullanılır.
Tarama Nmap herhangi bir client veya serverı birçok farklı şekilde tarama yeteneğine sahiptir. Nmapin asıl gücü farklı tarama tekniklerinden gelir. Protokol bazlı ( Tcp, Udp vb. ) tarayabileceğiniz gibi, belirli aralıklardaki ipler, subnetler ve üzerlerinde çalışan port ve servisleride taranabilir. 
Portların Taramalara Verebileceği Cevaplar Tarama sonuçlarında ortaya çıkabilecek port durumları aşağıdaki gibidir :
 • Open : Portlar açık ve aktif olarak TCP veya UDP bağlantısı kabul eder. 
• Closed : Portlar kapalı ancak erişilebilir. Üzerlerinde dinlenilen aktif bir bağlantı yoktur. 
• Filtered : Dönen tepkiler bir paket filtreleme mekanizması tarafından engellenir. Nmap portun açık olduğuna karar veremez.
 • Unfiltered : portlar erişilebilir ancak Nmap portların açık veya kapalı olduğuna karar Pveremez. (Sadece ACK scan için ) 
• Open|filtered : Nmap portların açık veya filtrelenmiş olduğuna karar veremez. (UDP, IP Proto, FIN, Null, Xmas Scan için )
 • Closed|filtered : Nmap portların kapalı yada filtreli olduğuna karar veremez. ( Sadece Idle Scan için ) Taramalar esnasında Nmapin performansının düşmemesi ve çıktıların daha düzenli olmasıyla amacıyla –v yada –vv seçenekleri kullanılabilir. Bu seçenekler vasıtasıyla Nmap bize sunacağı çıktıları limitler. –vv kullanılırsa, Nmape ait istatistikler görülmez ve en sade çıktı alınır.
 
 ![42](https://user-images.githubusercontent.com/66878884/103570238-cbdc1500-4ed9-11eb-8118-baf478389306.jpg)

Bu taramayı gerçekleştirmek için aşağıdaki komut kullanılmalıdır :  nmap -sT -v [Hedef_IP]

 





XMas Tree Scan
 
 
 ![43](https://user-images.githubusercontent.com/66878884/103570406-19588200-4eda-11eb-9f96-a5791ebd18cd.jpg)



Ping Scan 
![44](https://user-images.githubusercontent.com/66878884/103570415-1b224580-4eda-11eb-9961-a377e2d0d658.jpg)



 
UDP Scan Kaynak makinanın göndereceği UDP paketine ICMP Port Unreachable cevabı döndüren hedef makina kapalı kabul edilecektir. :
 
![45](https://user-images.githubusercontent.com/66878884/103570418-1c537280-4eda-11eb-8878-92d65b28e7c1.jpg)

 

ACK Scan
Kaynak makinanın hedef makinaya TCP ACK bayraklı paket göndereceği bu tarama türünde, hedef makina tarafından ICMP Destination Unreachable mesajı dönerse yada herhangi bir tepki oluşmazsa port “filtered” olarak kabul edilir :
 
![46](https://user-images.githubusercontent.com/66878884/103570421-1cec0900-4eda-11eb-9810-e9cf6f3cf184.jpg)

![47](https://user-images.githubusercontent.com/66878884/103570587-718f8400-4eda-11eb-9338-072b83516c34.jpg)

![48](https://user-images.githubusercontent.com/66878884/103571383-d4354f80-4edb-11eb-9aaf-f6e56ac8ee82.jpg)

![49](https://user-images.githubusercontent.com/66878884/103571696-6c333900-4edc-11eb-9d59-6aaa9d79472e.jpg)


![50](https://user-images.githubusercontent.com/66878884/103571788-8ff67f00-4edc-11eb-871f-5be552623565.jpg)

![51](https://user-images.githubusercontent.com/66878884/103571793-91c04280-4edc-11eb-999f-ef439c6a00f2.jpg)
![53](https://user-images.githubusercontent.com/66878884/103571798-92f16f80-4edc-11eb-809e-027153606e2b.jpg)

![54](https://user-images.githubusercontent.com/66878884/103571801-94bb3300-4edc-11eb-9a4b-e661dc9917b2.jpg)
![55](https://user-images.githubusercontent.com/66878884/103571809-9684f680-4edc-11eb-9ead-26684f7c3f32.jpg)
![56](https://user-images.githubusercontent.com/66878884/103571814-97b62380-4edc-11eb-82d8-a204543ba7eb.jpg)
![57](https://user-images.githubusercontent.com/66878884/103571750-81a86300-4edc-11eb-8756-97fe4ed5e696.jpg)
![58](https://user-images.githubusercontent.com/66878884/103571751-83722680-4edc-11eb-9770-3f0ee30b917f.jpg)
![59](https://user-images.githubusercontent.com/66878884/103571760-85d48080-4edc-11eb-946f-7090d461a4ef.jpg)
![60](https://user-images.githubusercontent.com/66878884/103571767-879e4400-4edc-11eb-8957-bccf6884c76f.jpg)
![61](https://user-images.githubusercontent.com/66878884/103571771-88cf7100-4edc-11eb-990b-94225e142487.jpg)
![62](https://user-images.githubusercontent.com/66878884/103571774-8a993480-4edc-11eb-9c4a-381e2a46321d.jpg)
![63](https://user-images.githubusercontent.com/66878884/103571778-8c62f800-4edc-11eb-85d0-57ff04ee5111.jpg)
![64](https://user-images.githubusercontent.com/66878884/103571782-8e2cbb80-4edc-11eb-8840-757a71b271c2.jpg)

![65](https://user-images.githubusercontent.com/66878884/103571455-f202b480-4edb-11eb-8229-d32174b4ee59.jpg)
![66](https://user-images.githubusercontent.com/66878884/103571460-f333e180-4edb-11eb-8d2f-28271cdb5034.jpg)
![67](https://user-images.githubusercontent.com/66878884/103571462-f4fda500-4edb-11eb-9b52-c90c9da32834.jpg)
![68](https://user-images.githubusercontent.com/66878884/103571465-f62ed200-4edb-11eb-8b9e-9bdbf4ccdded.jpg)
![69](https://user-images.githubusercontent.com/66878884/103571469-f75fff00-4edb-11eb-90f3-8e8a9c5f68e8.jpg)
![70](https://user-images.githubusercontent.com/66878884/103571472-fb8c1c80-4edb-11eb-962e-084a90d65cbf.jpg)
![71](https://user-images.githubusercontent.com/66878884/103571474-fd55e000-4edb-11eb-9344-ce9efb8029ec.jpg)
![72](https://user-images.githubusercontent.com/66878884/103571476-fe870d00-4edb-11eb-9201-b0c92ffa6e77.jpg)
![73](https://user-images.githubusercontent.com/66878884/103571481-0050d080-4edc-11eb-8fb3-a6ce732e160b.jpg)
![74](https://user-images.githubusercontent.com/66878884/103571483-0181fd80-4edc-11eb-8b87-88bf4155a76c.jpg)




12 
  TCP/IP ve Bileşenleri 
Şu ana kadar bilgisayar ağı kavramları ve ağ yapısının fiziksel katmanları hakkında genel bir fikir edindik. Bu noktada bilgisayarlar arası iletişimi sağlayan temel protokol katmanlarına gelmiş bulunuyoruz. Burada okuyucuya alt yapı protokolleri ile ilgili detaylı ancak çok teknik olmayan bilgiler verilecek ve sistemin temel çalışma prensipleri açıklanmaya çalışılacaktır. 
 Genel Tanımlar 
TCP/IP OSI modelinin de tanımlandığı gibi katmanlardan oluşan bir protokoller kümesidir. Ancak OSI modelinde  tanımlanan tüm katmanlar birebir TCP/IP katmanlarında bulunmamaktadır. OSI’nin sunum ve oturum katmanları burada uygulama katmanında yer almakta,  yönlendirme katmanı da diğer alt katmanları kapsamaktadır.  
TCP/IP’de  her katman değişik görevlere sahip olup altındaki ve üstündeki katmanlar ile gerekli bilgi alışverişini sağlamakla yükümlüdür. Aşağıdaki şekilde bu katmanlar bir blok şema halinde gösterilmektedir. 
 
 	Çizim 12-1 TCP/IP katmanları 
TCP/IP katmanlarının tam olarak ne olduğu, nasıl çalıştığı konusunda bir fikir sahibi olabilmek için bir örnek üzerinde inceleyelim:   
TCP/IP’nin kullanıldığı en önemli servislerden birisi elektronik postadır (e-posta). Eposta servisi için bir uygulama protokolu belirlenmiştir  (SMTP).  Bu   protokol  eposta’nın bir bilgisayardan bir başka  bilgisayara nasıl iletileceğini belirler. Yani epostayı gönderen ve  alan kişinin adreslerinin belirlenmesi, mektup içeriğinin hazırlanması  vb. gibi. Ancak e-posta servisi bu mektubun bilgisayarlar arasında  nasıl  iletileceği ile ilgilenmez, iki bilgisayar arasında  bir  iletişimin olduğunu varsayarak mektubun yollanması görevini TCP ve IP  katmanlarına bırakır. TCP katmanı komutların karşı tarafa ulaştırılmasından sorumludur. Karşı tarafa  ne yollandığı ve hatalı yollanan mesajların tekrar yollanmasının  kayıtlarını tutarak  gerekli kontrolleri yapar. Eğer gönderilecek mesaj bir kerede gönderilemeyecek kadar büyük ise (Örneğin uzunca bir e-posta  gönderiliyorsa) TCP onu uygun boydaki segment’lere (TCP katmanlarının iletişim için kullandıkları birim bilgi miktarı) böler ve bu  segment’lerin  karşı tarafa doğru sırada, hatasız olarak ulaşmalarını  sağlar. Internet üzerindeki tek servis e-posta olmadığı için ve  segment’lerin karşı tarafa hatasız ulaştırılmasını sağlayan iletişim yöntemine  tüm diğer servisler de ihtiyaç duyduğu için TCP ayrı bir katman olarak  çalışmakta ve tüm diğer servisler onun üzerinde yer almaktadır.  Böylece  yeni  bir  takım  uygulamalar  da  daha   kolay  geliştirilebilmektedir. Üst seviye uygulama protokollerinin TCP katmanını çağırmaları gibi  benzer şekilde TCP de IP katmanını çağırmaktadır. Ayrıca  bazı  servisler TCP katmanına ihtiyaç duymamakta ve bunlar direk olarak IP katmanı  ile görüşmektedirler. Böyle belirli görevler için belirli hazır yordamlar  oluşturulması  ve protokol seviyeleri  inşa  edilmesi  stratejisine ‘katmanlaşma’ adı verilir. Yukarıda verilen örnekteki e- posta servisi (SMTP), TCP ve IP ayrı katmanlardır ve her katman altındaki diğer  katman ile konuşmakta diğer bir deyişle onu çağırmakta ya da onun sunduğu sevisleri kullanmaktadır. En genel haliyle TCP/IP uygulamaları 4 ayrı katman kullanır. Bunlar: 
-	Bir uygulama protokolü, mesela e-posta   
-	Üst seviye uygulama protokollerinin gereksinim duyduğu TCP gibi bir protokol  katmanı 
-	IP  katmanı. Gönderilen bilginin  istenilen  adrese   yollanmasını sağlar.    
-	Belirli bir fiziksel ortamı sağlayan protokol katmanı.   Örneğin Ethernet, seri hat, X.25 vb.    
Internet birbirine geçiş yolları (gateway) ile bağlanmış çok sayıdaki  bağımsız bilgisayar ağlarından oluşur ve buna “catenet model” adı  verilir. Kullanıcı bu ağlar üzerinde yer alan herhangi bir bilgisayara  ulaşmak isteyebilir. Bu işlem esnasında kullanıcı farkına varmadan bilgiler, düzinelerce ağ üzerinden geçiş yapıp varış yerine ulaşırlar. Bu kadar işlem esnasında kullanıcının bilmesi gereken tek şey ulaşmak istediği noktadaki bilgisayarın ‘Internet adresi’ dir. Bu  adres toplam 32 bit uzunluğunda bir sayıdır. Fakat bu sayı 8 bitlik 4  ayrı ondalık sayı şeklinde kullanılır (144.122.199.20 gibi). Bu 8  bitlik gruplara ‘octet’ ismi de verilir. Bu adres yapısı genelde  karşıdaki sistem hakkında bilgi de verir. Mesela 144.122 ODTÜ için  verilmiş bir numaradır. ODTÜ üçüncü octet’i kampüs içindeki birimlere dağıtmıştır. Örneğin,  144.122.199  bilgisayar  merkezinde bulunan bir  Ethernet  ağda  kullanılan bir adrestir. Son octet ise bu Ethernete 254  tane  bilgisayar bağlanmasına izin verir (0 ve 255 bilgisayar adreslemesinde kullanılmayan özel amaçlı adresler olduğu için 254  bilgisayar  adreslenebilir).  
IP bağlantısız “connectionless” ağ teknolojisini kullanmaktadır ve bilgi “datagramlar” (TCP/IP temel bilgi birim miktarı) dizisi halinde bir noktadan diğerine iletilir.  Büyük bir bilgi grubunun (büyük bir dosya veya e-posta gibi)  parçaları olan “datagram” ağ üzerinde tek başına yol alır. Mesela  15000 octet’lik bir kütük pek çok ağ tarafından bir kere de  iletilemeyecek kadar büyük olduğu için protokoller bunu 30 adet 500  octetlik datagramlara böler. Her datagram ağ üzerinden tek tek  yollanır ve bunlar karşı tarafta yine 15000 octet lik bir kütük olarak  birleştirilir. Doğal olarak önce yola çıkan bir datagram kendisinden  sonra yola çıkan bir datagramdan sonra karşıya varabilir veya ağ  üzerinde oluşan bir hatadan dolayı bazı datagramlar yolda kaybolabilir.  Kaybolan veya yanlış sırada ulaşan datagramların sıralanması veya  hatalı gelenlerin yeniden alınması hep üst seviye protokollerce  yapılır.  Bu arada “paket” ve “datagram” kavramlarına bir açıklama getirmek  yararlı olabilir. TCP/IP ile ilgili kavramlarda “datagram” daha doğru  bir terminolojidir. Zira datagram TCP/IP de iletişim için kullanılan birim  bilgi miktarıdır. Paket ise fiziksel ortamdan (Ethernet, X.25 vb.)  ortama değişen bir büyüklüktür. Mesela X.25 ortamında datagramlar 128  byte’lık paketlere dönüştürülüp fiziksel ortamda böyle taşınırlar ve  bu işlemle IP seviyesi hiç ilgilenmez. Dolayısıyla bir IP datagramı X.25  ortamında birden çok paketler halinde taşınmış olur.           
 TCP Katmanı   
TCP’nin (“transmission control protocol-iletişim kontrol protokolü”)  temel işlevi, üst katmandan (uygulama katmanı) gelen bilginin segment’ler haline dönüştürülmesi, iletişim ortamında kaybolan bilginin tekrar  yollanması ve ayrı sıralar halinde gelebilen bilginin doğru sırada  sıralanmasıdır.  IP (“internet protocol”) ise tek tek datagramların  yönlendirilmesinden sorumludur. Bu açıdan bakıldığında TCP katmanının  hemen hemen tüm işi üstlendiği görülmekle beraber (küçük ağlar için bu  doğrudur) büyük ve karmaşık ağlarda IP katmanı en önemli görevi  üstlenmektedir. Bu gibi durumlarda değişik fiziksel katmanlardan geçmek, doğru yolu  bulmak çok karmaşık bir iş halini almaktadır.  
Şu ana kadar sadece Internet adresleri ile bir noktadan diğer noktaya  ulaşılması konusundan bahsettik ancak birden fazla kişinin aynı  sisteme ulaşmak istemesi durumunda neler olacağı konusuna henüz bir  açıklık getirmedik. Doğal olarak bir segment’i doğru varış noktasına  ulaştırmak tek başına yeterli değildir. TCP bu segment’in  kime ait olduğunu da  bilmek zorundadır. “Demultiplexing” bu soruna çare bulan yöntemdir.  TCP/IP‘de değişik seviyelerde “demultiplexing” yapılır. Bu işlem için  gerekli bilgi bir seri “başlık” (header) içinde bulunmaktadır. Başlık,  datagram’a eklenen basit bir kaç octet’den oluşan bir bilgiden  ibarettir. Yollanmak istenen mesajı bir mektuba benzetecek olursak  başlık o mektubun zarfı ve zarf üzerindeki adres bilgisidir. Her  katman kendi zarfını ve adres bilgisini yazıp bir alt katmana  iletmekte ve o alt katmanda onu daha büyük bir zarfın içine koyup  üzerine adres yazıp diğer katmana iletmektedir. Benzer işlem varış  noktasında bu sefer ters sırada takip edilmektedir.  
Bir örnek vererek  açıklamaya çalışırsak: Aşağıdaki noktalar ile gösterilen satır bir noktadan diğer bir noktaya  gidecek olan bir dosyayı temsil etsin,  ............... 
TCP katmanı bu dosyayı taşınabilecek büyüklükteki parçalara ayırır (Üçer üçer ayrılmış noktalar): 
  	...  ...  ...  ...  ... 
Her segment’in  başına TCP bir başlık koyar. Bu başlık bilgisinin en  önemlileri ‘port numarası’ ve ‘sıra numarası’ dır. Port numarası, örneğin  birden fazla kişinin aynı anda dosya yollaması veya karşıdaki bilgisayara bağlanması durumunda TCP’nin herkese  verdiği farklı bir numaradır. Üç kişi aynı anda dosya transferine  başlamışsa TCP, 1000, 1001 ve 1002 “kaynak” port numaralarını bu üç  kişiye verir böylece herkesin paketi birbirinden ayrılmış olur. Aynı  zamanda varış noktasındaki TCP de ayrıca bir “varış” port numarası  verir. Kaynak noktasındaki TCP’nin varış port numarasını bilmesi  gereklidir ve bunu iletişim kurulduğu anda TCP karşı taraftan öğrenir. Bu bilgiler  başlıktaki “kaynak” ve “varış” port numaraları olarak belirlenmiş  olur. Ayrıca her segment  bir “sıra” numarasına sahiptir. Bu numara  ile karşı taraf doğru sayıdaki segmenti  eksiksiz alıp almadığını  anlayabilir. Aslında TCP segmentleri  değil octet leri numaralar.  Diyelim ki her datagram içinde 500 octet bilgi varsa ilk datagram  numarası 0, ikinci datagram numarası 500, üçüncüsü 1000 şeklinde  verilir. Başlık içinde bulunan üçüncü önemli bilgi ise “kontrol toplamı”  (Checksum) sayısıdır. Bu sayı segment  içindeki tüm octet’ler  toplanarak hesaplanır ve sonuç başlığın içine konur. Karşı noktadaki  TCP  kontrol toplamı hesabını tekrar yapar. Eğer  bilgi  yolda  bozulmamışsa kaynak noktasındaki hesaplanan sayı ile varış noktasındaki hesaplanan sayı aynı  çıkar. Aksi takdirde segment yolda bozulmuştur bu durumda bu datagram  kaynak noktasından tekrar istenir.  Aşağıda bir TCP segmenti  örneği verilmektedir.  
 
Kaynak Portu 	Varış Portu 
                               Sıra numarası 
 	Onay (Acknowledgement) 
								
Data Offset 	 Reserve 	U
R 
G	A
C 
K	P 
S 
H	R 
S 
T 	S 
Y
N	F 
I 
N	Pencere (Window)
   Kontrol Toplamı	   Acil işareti (Urgent Pointer) 
  
       Bilgi ........  diğer 500 octet 
 
 	Çizim 12-2 TCP Segmenti 
Eğer TCP başlığını “T” ile gösterecek olursak yukarda noktalarla  gösterdiğimiz dosya aşağıdaki duruma gelir:  
 	    T...  T...  T...  T...  T...    
Başlık içinde bulunan diğer bilgiler genelde iki bilgisayar arasında  kurulan bağlantının kontrolüne yöneliktir. Segment’in  varışında alıcı  gönderici  noktaya  bir  “onay” (acknowledgement) yollar. Örneğin  kaynak noktasına yollanan “onay numarası” (Acknowledgement number)  1500 ise octet numarası 1500 e kadar tüm bilginin alındığını gösterir.  Eğer  kaynak noktası belli bir zaman içinde bu bilgiyi  varış  noktasından alamazsa o bilgiyi tekrar yollar. “Pencere” bilgisi bir  anda ne kadar bilginin gönderileceğini kontrol etmek için kullanılır.  Burada amaç her segment’in  gönderilmesinden sonra karşıya ulaşıp  ulaşmadığı ile ilgili onay (ack) beklenmesi yerine segment’leri  onay  beklemeksizin pencere bilgisine göre yollamaktır. Zira yavaş hatlar  kullanılarak yapılan iletişimde onay beklenmesi iletişimi çok daha  yavaşlatır. Diğer taraftan çok hızlı bir şekilde sürekli segment   yollanması karşı tarafın bir anda alabileceğinden fazla bir trafik  yaratacağından yine problemler ortaya çıkabilir. Dolayısıyla her iki  taraf o anda ne kadar bilgiyi alabileceğini “pencere” bilgisi içinde  belirtir. Bilgisayar bilgiyi aldıkça pencere alanındaki boş yer azalır  ve sıfır olduğunda yollayıcı bilgi yollamayı durdurur. Alıcı nokta  bilgiyi işledikçe pencere artar ve bu da yeni bilgiyi karşıdan kabul  edebileceğini gösterir. “Acil işareti” ise bir kontrol karakteri veya  diğer bir komut ile transferi kesmek vb. amaçlarla kullanılan bir  alandır. Bunlar dışında ki alanlar TCP protokolünün detayları ile ilgili olduğu  için burada anlatılmayacaktır.    
 IP Katmanı    
TCP katmanına  gelen bilgi segmentlere ayrıldıktan sonra  IP katmanına yollanır. IP katmanı, kendisine gelen TCP segment’i  içinde ne olduğu ile ilgilenmez. Sadece kendisine verilen bu bilgiyi ilgili IP adresine yollamak amacındadır. IP katmanının görevi bu segment  için ulaşılmak istenen  noktaya gidecek bir “yol” (route) bulmaktır. Arada geçilecek sistemler ve geçiş yollarının bu paketi doğru yere geçirmesi için kendi başlık bilgisini TCP katmanından gelen segment’e ekler. TCP katmanından gelen segment’lere IP başlığının eklenmesi ile oluşturulan IP paket birimlerine “datagram” adı verilir. IP başlığı eklenmiş bir datagram aşağıdaki çizimde  gösterilmektedir:  
Versiyon  	 IHL	    Servis tipi   	   Toplam uzunluk 
 	Tanımlama               	  Bayrak   	  Fragment offset 
 Yaşam süresi (TTL)	   Protokol	      Başlık kontrol toplamı
 	Kaynak Adresi 
 	Varış Adresi 
 
 	TCP başlığı ve iletilen bilgi  
 
 	Çizim 12-3 IP Datagram 
Bu başlıktaki temel bilgi kaynak ve varış Internet adresi (32-bitlik adres, 144.122.199.20 gibi), protokol numarası ve kontrol  toplamıdır. Kaynak  Internet  adresi  tabiiki  sizin  bilgisayarınızın Internet adresidir. Bu sayede varış noktasındaki  bilgisayar bu paketin nereden geldiğini anlar. Varış Internet adresi  ulaşmak istediğiniz bilgisayarın adresidir. Bu bilgi sayesinde aradaki  yönlendiriciler veya geçiş yolları (gateway) bu datagram’ı nereye yollayabileceklerini  bilirler. Protokol numarası IP’ye karşı tarafta bu datagram’ı TCP’ye  vermesi gerektiğini söyler. Her ne kadar IP trafiğinin çoğunu TCP  kullansa  da  TCP dışında  bazı  protokollerde  kullanılmaktadır  dolayısıyla protokoller arası bu ayrım protokol numarası ile belirlenir. Son olarak  kontrol toplamı IP başlığının yolda bozulup bozulmadığını kontrol  etmek için kullanılır. Dikkat edilirse TCP ve IP ayrı ayrı kontrol  toplamları kullanmaktalar. IP kontrol toplamı başlık  bilgisinin  bozulup bozulmadığı veya mesajın yanlış yere gidip gitmediğini kontrol  için kullanılır. Bu protokollerin tasarımı sırasında TCP’nin ayrıca bir  kontrol toplamı hesaplaması ve kullanması daha verimli ve güvenli  bulunduğu için iki ayrı kontrol toplamı alınması yoluna gidilmiştir. 
IP başlığını “I” ile gösterecek olursak IP katmanından çıkan ve TCP verisi taşıyan bir  datagram şu hale gelir:  
 	IT...IT...IT...IT...IT... 
Başlıktaki “Yaşam süresi” (Time to Live) alanı IP paketinin yolculuğu  esnasında geçilen her sistemde bir azaltılır ve sıfır olduğunda bu  paket yok edilir. Bu sayede oluşması muhtemel sonsuz döngüler ortadan  kaldırılmış olur.  IP katmanında artık başka başlık eklenmez ve iletilecek bilgi  fiziksel iletişim ortamı üzerinden yollanmak üzere alt katmana (bu  Ethernet, X.25, telefon hattı vb. olabilir) yollanır.     
 Fiziksel Katman 
 
Fiziksel katman gerçekte “Data Link Connection” (DLC) ve Fiziksel ortamı içermektedir. Ancak biz burada bu ara katmanları genelleyip tümüne Fiziksel katman adını vereceğiz. Günümüzde pek çok bilgisayar ağının Etherneti temel iletişim ortamı     olarak kullanmasından dolayı da Ethernet teknolojisini örnek olarak anlatacağız. Dolayısıyla burada Ethernet ortamının  TCP/IP ile olan iletişimini açıklayacağız.  
Ethernet kendine has bir ağ adresleme yöntemi kullanır. Ethernet teknolojisi tasarlanırken  dünya üzerinde  herhangi bir yerde kullanılan bir Ethernet kartının tüm  diğer  kartlardan ayrılmasını sağlayan bir mantık izlenmiştir. Ayrıca,  kullanıcının Ethernet adresinin ne olduğunu düşünmemesi için her Ethernet kartı  fabrika çıkışında kendisine has bir adresle piyasaya verilmektedir.  Her Ethernet kartının kendine has numarası olmasını sağlayan tasarım 48 bitlik  fiziksel adres yapısıdır. Ethernet kart üreticisi firmalar merkezi  bir  otoriteden  üretecekleri kartlar için belirli büyüklükte  numara  blokları alır ve üretimlerinde bu numaraları kullanırlar. Böylece  başka bir üreticinin kartı ile bir çakışma meydana gelmez.   
Ethernet teknoloji olarak yayın teknolojisini (broadcast medium)  kullanır. Yani bir istasyondan Ethernet ortamına yollanan bir paketi o  Ethernet ağındaki tüm istasyonlar görür. Ancak doğru varış noktasının  kim olduğunu,  o ağa bağlı makinalar Ethernet başlığından anlarlar. Her  Ethernet paketi 14 octet’lik bir başlığa sahiptir. Bu başlıkta kaynak  ve varış Ethernet adresi ve bir tip kodu vardır. Dolayısıyla ağ  üzerindeki her makina bir paketin kendine ait olup olmadığını bu  başlıktaki  varış noktası bilgisine bakarak anlar (Bu  Ethernet  teknolojisindeki en önemli güvenlik boşluklarından birisidir). Bu  noktada Ethernet adresleri ile Internet adresleri arasında  bir  bağlantı olmadığını belirtmekte yarar var. Her makina hangi Ethernet  adresinin hangi Internet adresine karşılık geldiğini tutan bir tablo  tutmak  durumundadır  (Bu  tablonun  nasıl  yaratıldığı  ilerde  açıklanacaktır). Tip kodu alanı aynı ağ üzerinde farklı protokollerin  
kullanılmasını sağlar. Dolayısıyla aynı anda TCP/IP, DECnet, IPX/SPX  gibi protokoller aynı ağ üzerinde çalışabilir. Her protokol başlıktaki  tip alanına kendine has numarasını koyar. Kontrol toplamı (Checksum)  alanındaki değer ile komple paket kontrol edilir. Alıcı ve vericinin  hesapladığı değerler birbirine uymuyorsa paket yok edilir. Ancak  burada kontrol toplamı başlığın içine değilde paketin sonuna konulur.  Ethernet katmanında işlenip gönderilen mesaj ya da bilginin (Bu bilgi paketlerine frame adı verilir) son hali aşağıdaki duruma gelir:  
 
 
 
 
 
 
 
 
 
 
  	Ethernet varış adresi (İlk 32 bit) 
Ethernet varış  (İlk 16 bit)     Ethernet kaynak (ilk16 bit) 
 	Ethernet kaynak adresi (son 32 bit) 
 	Tip Kodu 
 
 	IP başlık, TCP başlık, iletilen bilgi 
 ................................................ 
 	bilginin sonu 
 	Ethernet kontrol toplamı (checksum) 
 
 	Çizim 12-4 Ethernet Paketi 
Ethernet başlığını “E” ile ve Kontrol toplamını “C” ile gösterirsek  yolladığımız dosya şu şekli alır:  
 	EIT...C  EIT...C  EIT...C  EIT...C  EIT...C 
Bu paketler (frame) varış noktasında alındığında bütün başlıklar  uygun  katmanlarca atılır. Ethernet arayüzü Ethernet başlık ve kontrol  toplamını atar. Tip koduna bakarak protokol tipini belirler ve  Ethernet cihaz sürücüsü (device driver) bu datagram’ı IP katmanına  geçirir. IP katmanı kendisi ile ilgili katmanı atar ve  protokol  alanına bakar, protokol alanında TCP olduğu için segmenti TCP  katmanına geçirir. TCP sıra numarasına bakar, bu bilgiyi ve diğer  bilgileri iletilen dosyayıyı orijinal durumuna getirmek için kullanır.  Sonuçta bir bilgisayar diğer bir bilgisayar ile iletişimi tamamlar.      
 Ethernet Encapsulation: ARP 
Yukarıda Ethernet üzerinde IP datagramların nasıl yer aldığından  bahsettik. Fakat açıklanmadan kalan bir nokta bir Internet adresi ile  iletişime geçmek için hangi Ethernet adresine ulaşmamız gerektiği  idi. Bu amaçla kullanılan  protokol ARP’dir  (“Address  Resolution Protocol”). ARP aslında bir IP protokolü değildir ve  dolayısıyla ARP datagramları IP başlığına sahip değildir. Varsayalımki  bilgisayarınız 128.6.4.194 IP adresine sahip ve siz de 128.6.4.7 ile  iletişime geçmek istiyorsunuz. Sizin sisteminizin ilk kontrol edeceği  nokta 128.6.4.7 ile aynı ağ üzerinde olup olmadığınızdır. Aynı ağ üzerinde yer alıyorsanız, bu Ethernet  üzerinden direk olarak haberleşebileceksiniz anlamına gelir.  Ardından  128.6.4.7 adresinin ARP tablosunda olup olmadığı ve Ethernet adresini  bilip bilmediği kontrol edilir. Eğer tabloda bu adresler varsa  Ethernet başlığına eklenir ve paket yollanır. Fakat tabloda adres  yoksa paketi yollamak için bir yol yoktur. Dolayısıyla burada ARP  devreye girer. Bir ARP istek paketi ağ üzerine yollanır ve bu paket  içinde “128.6.4.7” adresinin Ethernet adresi nedir sorgusu vardır. Ağ  üzerindeki  tüm  sistemler  ARP isteğini  dinlerler  bu  isteği  cevaplandırması gereken istasyona bu istek ulaştığında cevap ağ  üzerine yollanır. 128.6.4.7 isteği görür ve bir ARP cevabı ile  “128.6.4.7’nin Ethernet adresi 8:0:20:1:56:34” bilgisini istek yapan  istasyona yollar. Bu bilgi, alıcı noktada ARP tablosuna işlenir ve daha  sonra benzer sorgulama yapılmaksızın iletişim mümkün kılınır.  Ağ üzerindeki bazı istasyonlar sürekli ağı dinleyerek ARP sorgularını  alıp kendi tablolarını da güncelleyebilirler.     
 TCP Dışındaki Diğer Protokoller: UDP ve ICMP 
Yukarıda sadece TCP katmanını kullanan bir iletişim türünü açıkladık.  TCP gördüğümüz gibi mesajı segment’lere  bölen ve bunları  birleştiren bir katmandı. Fakat bazı uygulamalarda yollanan mesajlar  tek bir datagram’ın içine girebilecek büyüklüktedirler. Bu cins  mesajlara en güzel örnek adres kontrolüdür (name lookup). Internet  üzerindeki bir bilgisayara ulaşmak için kullanıcılar Internet adresi  yerine o bilgisayarın adını kullanırlar. Bilgisayar sistemi bağlantı  kurmak için çalışmaya başlamadan önce bu ismi Internet adresine  çevirmek  durumundadır. Internet adreslerinin isimlerle  karşılık  tabloları belirli bilgisayarlar üzerinde tutulduğu için kullanıcının sistemi bu bilgisayardan bu adresi sorgulayıp öğrenmek durumundadır.  Bu sorgulama çok kısa bir işlemdir ve tek bir segment  içine sığar.  Dolayısıyla bu iş için TCP katmanının kullanılması gereksizdir. Cevap  paketinin yolda kaybolması durumunda en kötü ihtimalle bu sorgulama  tekrar  yapılır. Bu cins kullanımlar için TCP’nin  alternatifi  protokoller vardır. Böyle amaçlar için en çok kullanılan protokol ise UDP’dir (“User  Datagram Protocol”).  
UDP datagramların belirli sıralara konmasının  gerekli olmadığı uygulamalarda kullanılmak üzere tasarlanmıştır.  TCP’de olduğu gibi UDP’de de bir başlık vardır. Ağ yazılımı bu UDP  başlığını iletilecek bilginin başına koyar. Ardından UDP bu bilgiyi IP  katmanına yollar. IP katmanı kendi başlık bilgisini ve protokol  numarasını yerleştirir (bu sefer protokol numarası alanına UDP’ye ait  değer yazılır). Fakat UDP TCP’nin yaptıklarının hepsini yapmaz. Bilgi  burada datagramlara bölünmez ve yollanan paketlerin kayıdı tutulmaz.  UDP’nin tek sağladığı port numarasıdır. Böylece pek çok program UDP’yi  kullanabilir. Daha az bilgi içerdiği için doğal olarak UDP başlığı TCP  başlığına göre daha kısadır. Başlık, kaynak ve varış port numaraları ile  kontrol toplamını içeren tüm bilgidir.   
Diğer bir  protokol ise  ICMP’dir  (“Internet  Control  Message Protocol”).   ICMP, hata mesajları ve TCP/IP yazılımının  bir takım kendi mesaj trafiği amaçları için kullanılır. Mesela bir  bilgisayara bağlanmak istediğinizde sisteminiz size “host unreachable”  ICMP mesajı ile geri dönebilir. ICMP ağ hakkında bazı bilgileri  toplamak amacı ile de kullanılır. ICMP yapı olarak UDP’ye benzer bir protokoldür.  ICMP de mesajlarını sadece bir datagram içine koyar. Bununla beraber  UDP’ye göre daha basit bir yapıdadır. Başlık bilgisinde port numarası  bulundurmaz.  Bütün  ICMP mesajları  ağ  yazılımının  kendisince  yorumlanır, ICMP mesajının nereye gideceği ile ilgili bir port  numarasına gerek yoktur.  ICMP ‘yi  kullanan en popüler Internet uygulaması PING komutudur. Bu komut yardımı ile Internet kullanıcıları  ulaşmak istedikleri herhangi bir bilgisayarın açık olup olmadığını, hatlardaki sorunları anında test etmek imkanına sahiptirler 
 .
Şu ana kadar gördüğümüz katmanları ve bilgi akışının nasıl olduğunu aşağıdaki şekilde daha açık izleyebiliriz. 
 
 
 	Çizim 12-5 Katmanlar arası bilgi akışı 
 Internet Adresleri   
Daha  önce de gördüğümüz gibi Internet adresleri 32-bitlik  sayılardır ve   noktalarla  ayrılmış  4  octet  (ondalık  sayı   olarak)   olarak gösterilirler.  Örnek  vermek gerekirse,  128.10.2.30  Internet  adresi 10000000 00001010 00000010 00011110 şeklinde 32-bit olarak gösterilir. Temel problem bu bilgisayar ağı adresinin hem bilgisayar ağını ve  hem de  belli  bir  bilgisayarı  tek  başına  gösterebilmesidir.    
Internet’te değişik büyüklükte  bilgisayar ağlarının bulunmasından dolayı  Internet  adres yapısının tüm bu ağların adres sorununu çözmesi gerekmektedir. Tüm  bu ihtiyaçları  karşılayabilmek amacı ile Internet  tasarlanırken  32bitlik  adres  yapısı seçilmiş ve bilgisayar ağlarının  çoğunun  küçük ağlar  olacağı  varsayımı ile yola çıkılmıştır.   
32-bit Internet adresleri, 'Ağ Bilgi Merkezi (NIC) Internet Kayıt Kabul' tarafından yönetilmektedir. Yerel yönetilen bir ağ uluslararası platformda daha büyük bir ağa bağlanmadığında adres rastgele olabilir. Fakat, bu tip adresler ileride Internet'e bağlanılması durumunda  sorun çıkartabileceği için önerilmemektedir. Ağ yöneticisi bir diğer IP-tabanlı sisteme, örneğin NSFNET'e bağlanmak istediğinde tüm yerel adreslerin  'Uluslararası Internet Kayıt Kabul' tarafından belirlenmesi zorunludur. 
Değişik  büyüklükteki ağları adreslemek amacı ile 3 sınıf adres kullanılmaktadır:  
 
A	Sınıfı adresler: İlk byte 0 'la 126 arasında değişir. İlk byte ağ numarasıdır. Gerisi  bilgisayarların adresini belirler. Bu tip adresleme, herbiri 16,777,216 bilgisayardan oluşan 126  ağın adreslenmesine izin verir. 
 
B	Sınıfı adresler: İlk byte 128 'le 191 arasında değişir. İlk iki byte ağ numarasıdır. Gerisi bilgisayar adresini belirler. Bu tip adresleme, herbiri 65,536 bilgisayardan oluşan 16,384  ağın adreslenmesine izin verir. 
 
C	Sınıfı adresler: İlk byte 192 ile 223 arasında değişir. İlk üç byte ağ numarasıdır. Gerisi  bilgisayarların adresini belirler. Bu tip adresleme, herbiri 254 bilgisayardan oluşan 2,000,000 ağın adreslenmesine izin verir. 
 
A Sınıfı Adresler 
0 1  	 	 	8 	 	16 	 	24 	 	31 
0 	 Ağ Numarası     	   Bilgisayar  Numarası 
 
 
B Sınıfı Adresler 
0 	1 	16 	31 
1 	0 	   Ağ Numarası      	   Bilgisayar Numarası 
 
 
C Sınıfı Adresler 
0 	1 2 	24 	31  
1 	1 	0 	  Ağ Numarası   	Bilgisayar Num. 
 
127  ile başlayan  adresler Internet tarafından özel amaçlarla (“localhost”  tanımı için) kullanılmaktadır. 
223'ün üzerindeki adresler gelecekte kullanılmak üzere D-sınıfı ve  E-sınıfı adresler olarak ayrılmış olarak tutulmaktadır.  
A sınıfı adresler, NSFNET, MILNET gibi büyük ağlarda kullanılır. C sınıfı adresler, genellikle üniversite yerleşkelerinde kurulu yerel ağlarla, ufak devlet kuruluşlarında kullanılır. NIC sadece ağ numaralarını yönetir. Bölgede olması beklenen  bilgisayar  sayısına göre A, B veya C sınıfı adresleme seçilir. Bir bölgeye ağ numarası verildikten sonra  bilgisayarların nasıl adresleneceğini bölge yönetimi belirler.   IP adres alanı özellikle son yıllarda artan kullanım talebi sonucunda hızla tükenmeye başlamıştır. Bu nedenle yapılan IP adres taleplerinin gerçekçi olmasının sağlanması için gerekli kontroller yapılmaktadır.  
 Alt Ağlar (Subnet) 
Subnet ya da alt ağ kavramı, kurumların ellerindeki Internet adres yapısından daha verimli yararlanmaları için geliştirilen bir adresleme yöntemidir. Pek  çok büyük organizasyon kendilerine verilen Internet  numaralarını alt ağlara  bölerek kullanmayı daha uygun  bulmaktadırlar.  “Subnet” kavramı  aslında  'Bilgisayar numarası' alanındaki bazı  bitlerin  'Ağ numarası' olarak kullanılmasından ortaya çıkmıştır. Böylece, elimizdeki bir adres ile  tanımlanabilecek bilgisayar sayısı düşürülerek,  tanımlanabilecek ağ sayısını yükseltmek mümkün olmaktadır.   
Nasıl bir alt ağ  yapısının kullanılacağı  kurumların ağ alt yapılarına ve topolojilerine  bağımlı olarak  değişmektedir. Alt ağ kullanılması  durumunda  bilgisayarların adreslenmesi  kontrolü  merkezi olmaktan çıkmakta  ve  yetki  dağıtımı yapılmaktadır.  Alt ağ  yapısının   kullanılması   yanlızca  o adresi kullanan kurumun    kendisini ilgilendirmekte ve  bunun  kurum dışına hiçbir etkisi de bulunmamaktadır. Herhangi bir dış kullanıcı altağ kullanılan bir  ağa ulaşmak  istediğinde o ağda kullanılan altağ yönteminden haberdar  olmadan istediği  noktaya ulaşabilir. Kurum sadece kendi  içinde  kullandığı geçiş  yolları  ya da yönlendiriciler üzerinde  hangi  alt ağa  nasıl gidilebileceği tanımlamalarını yapmak durumundadır. 
Bir  Internet ağını alt ağlara bölmek, alt ağ maskesi denilen  bir  IP adresi kullanılarak yapılmaktadır. Eğer maske adresteki adres bit'i  1 ise  o  alan  ağ adresini göstermektedir, adres bit'i  0 ise o alan  adresin bilgisayar  numarası  alanını göstermektedir.  Konuyu  daha  anlaşılır kılmak için bir örnek üzerinde inceleyelim:  
ODTÜ kampüsü  için bir B-sınıfı adres olan 144.122.0.0 kayıtlı olarak kullanılmaktadır. Bu adres ile  ODTÜ 65.536 adet bilgisayarı adresleyebilme yeteneğine  sahiptir. Standart  B-sınıfı  bir adresin maske adresi  255.255.0.0  olmaktadır. Ancak  bu adres alındıktan sonra ODTÜ'nün teknik ve idari  yapısı  göz önünde tutularak farklı alt ağ yapısı uygulanmasına karar verilmiştir. Adres içindeki üçüncü octet'inde ağ alanı 
adreslemesinde  kullanılması ile ODTÜ'de 254 adede kadar farklı bilgisayar ağının  tanımlanabilmesi mümkün  olmuştur. Maske adres olarak  255.255.255.0  
kullanılmaktadır. İlk  iki  octet (255.255) B-sınıfı adresi, üçüncü octet  (255)  alt ağ adresini  tanımlamakta,  dördüncü octet (0) ise  o  alt ağ  üzerindeki bilgisayarı tanımlamaktadır.  
 
144.122.0.0 ODTÜ için  kayıtlı adres  
 
255.255.0.0  Standart B-Sınıfı adres maskesi 	Bir ağ, 65536 bilgisayar 
255.255.255.0 Yeni maske 	254 ağ, her ağda 254 bilgisayar 
 
ODTÜ de uygulanan adres maskesi ile alt ağlara   bölünmüş  olan ağ   adresleri   merkezi   olarak   bölümlere dağıtılmakta  ve  her  bir  alt ağ  kendi  yerel  ağı  üzerindeki   ağ parçasında   254  taneye  kadar  bilgisayarını   adresleyebilmektedir. Böylece tek bir merkezden tüm üniversitedeki makinaların IP adreslerinin tanımlanması gibi bir  sorun  ortadan kaldırılmış ve adresleme  yetkisi  ayrı  birimlere verilerek  onlara  kendi  içlerinde  esnek  hareket  etme   kabiliyeti tanınmıştır. Bir örnek verecek olursak: Bilgisayar   Mühendisliği   bölümü  için  71 alt ağı ayrılmış ve 144.122.71.0  ağ  adresi  kullanımlarına ayrılmıştır. Böylece,  bölüm içinde 144.122.71.1  den 144.122.71.254 'e  kadar  olan  adreslerin dağıtımı   yetkisi  bölümün  kendisine  bırakılmıştır.  Aynı   şekilde Matematik bölümü için 144.122.36.0, Fizik bölümü için 144.122.30.0  ağ adresi ayrılmıştır.    
C-sınıfı  bir adres  üzerinde  yapılan  bir  alt ağ  için  örnek   verecek olursak:  
 
Elinde C-sınıfı 193.140.65.0  adres olan bir kurum  subnet adresi olarak  
255.255.255.192  kullandığında  
 
 	193.140.65.0 	11000001 10001100 01000001 00000000 
 	255.255.255.192 	11111111 11111111 11111111 11000000 
 
 	    Ağ numarası alanı
 	Bilgisayar numarası 
 
elindeki bu adresi dört  farklı  parçaya bölebilir. Değişik alt ağ maskeleri ile nasıl sonuçlar edinilebileceği  ile ilgili örnek bir tablo verecek olursak :  
 
IP adres 
 	Maske 	Açıklama  
128.66.12.1  	255.25.255.0 	128.66.12  subneti  üzerindeki   
 		1.  bilgisayar   
130.97.16.132 	255.255.255.192 	130.97.16.128 subneti üzerindeki 
 		 4. bilgisayar.  
192.178.16.66 	255.255.255.192 	192.178.16.64 subneti  üzerindeki  
 		2. bilgisayar  
132.90.132.5 	255.255.240.0 	132.90.128 subnetindeki 4.5 inci  
 		bilgisayar. 
18.20.16.91 	255.255.0.0 	18.20.0.0 subnetindeki 16.91 inci bilgisayar  
 
 Özel Adresler 
Internet  adreslemesinde  0  ve 255'in özel bir  kullanımı  vardır.  0 adresi,  Internet üzerinde kendi adresini bilmeyen bilgisayarlar  için (Belirli   bazı   durumlarda  bir  makinanın   kendisinin bilgisayar  numarasını  bilip hangi ağ üzerinde olduğunu bilmemesi gibi bir  durum olabilmektedir)    veya   bir   ağın kendisini    tanımlamak için kullanılmaktadır (144.122.0.0 gibi). 255  adresi genel duyuru  "broadcast" amacı ile  kullanılmaktadır.  Bir  ağ üzerindeki  tüm istasyonların duymasını istediğiniz bir  mesaj  genel duyuru "broadcast"  mesajıdır.  Duyuru  mesajı  genelde  bir  istasyon  hangi istasyon  ile  konuşacağını  bilemediği  bir  durumda  kullanılan  bir mesajlaşma  yöntemidir. Örneğin ulaşmak istediğiniz  bir  bilgisayarın adı  elinizde  bulunabilir ama onun IP adresine ihtiyaç  duydunuz,  bu çevirme  işini  yapan en yakın "name server" makinasının  adresini  de bilmiyorsunuz.  Böyle bir durumda bu isteğinizi yayın mesajı yolu  ile yollayabilirsiniz.  Bazı durumlarda birden fazla sisteme bir  bilginin gönderilmesi  gerekebilir böyle bir durumda her bilgisayara ayrı  ayrı mesaj  gönderilmesi  yerine tek bir yayın mesajı yollanması  çok  daha kullanışlı bir yoldur. Yayın  mesajı  yollamak  için  gidecek  olan  mesajın  IP  numarasının bilgisayar adresi alanına 255 verilir. Örneğin 144.122.99 ağı üzerinde  yer  alan  bir bilgisayar yayın mesajı  yollamak  için  144.122.99.255 adresini  kullanır.  Yayın mesajı yollanması birazda  kullanılan  ağın fiziksel katmanının özelliklerine bağlıdır. Mesela bir Ethernet ağında yayın mümkün iken noktadan noktaya (point-to-point) hatlarda bu mümkün olmamaktadır.  
Bazı eski sürüm TCP/IP protokolüne sahip bilgisayarlarda yayın  adresi olarak  255  yerine  0 kullanılabilmektedir.  Ayrıca  yine  bazı  eski sürümler alt ağ  kavramına hiç sahip olmayabilmektedir.  
Yukarıda  da  belirttiğimiz gibi 0 ve 255'in  özel  kullanım  alanları olduğu    için  ağa bağlı   bilgisayarlara   bu   adresler kesinlikle verilmemelidir. Ayrıca adresler asla 0 ve 127 ile ve 223'ün  üzerindeki  bir sayı ile başlamamalıdır. 
 
***ZAMANIM OLURSA ELİMDE OLAN LİNUX'TE KULLANILAN ARAÇLARIN DETAYLI KULLANIMI VE NE İŞE YARADIKLARI İLE DE İLGİLİ BİLGİLERİ DEVAMINA EKLEYECEĞİM...

****DEVAMINDA OLAN ŞEYLER CAN ABİNİN PAYLAŞTIĞI LİNKLERLE AYNI OLAN ŞEYLER ELİNİZDE YOKTUR DİYE BURAYADA EKLİYORUM RAHATLIKLA DEVAMI NİTELİKTE KULLANABİLİRSİNİZ:


https://www.firatboyan.com/ip-ve-subnetting-kavrami.aspx

http://volkanaltintas.com/wp-content/uploads/2015/11/Ag_Temelleri14.04.2014.pdf


***SAĞLICAKLA VE SEVGİYLE KALIN...

***KAYNAKÇALAR
BİLGİ GÜVENLİĞİ AKADEMİSİ-www.bga.com
AHMET BİRKAN
ATIL SAMANCIOĞLU
HUZEYFE ÖNAL-http://www.lifeoverip.net/
YRD.DOÇ.DR.HİLMİ KUŞÇU
MUSA ŞANA-MUSASANA.NET




