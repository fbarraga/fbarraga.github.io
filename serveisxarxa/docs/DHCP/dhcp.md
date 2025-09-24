# DHCP

## Introducció

Per poder pertànyer a una xarxa, hem de tenir certs paràmetres configurats.Com a mínim, dins el model TCP/IP, s'ha de configurar:

* IP
* màscara de subxarxa.

Aquests poden ser assignats de forma **estàtica** o **dinàmica**. L’assignació estàtica d’adreces IP ens implica tenir una IP dedicada sempre a un mateix dispositiu, prèviament configurada al propi dispositiu. D’aquesta manera, servidors, routers, impressores, i d’altres elements clau i fixes de la xarxa quedaran perfectament identificats.

No obstant, cal anar un per un a configurar-los prèviament de forma manual. Un canvi a la xarxa pot implicar la reconfiguració del dispositiu, habitualment amb la necessitat 	d’accés presencial. 
A més, pot comportar problemes de seguretat, ja que pot esdevenir una porta d’accés important per atacants al ser un punt conegut. Es necessita	una	manera en que «algú» li assigni	sempre la mateixa IP i alhora ens permeti aplicar la configuració de forma automatizada.

Cal trobar un sistema que ens identifiqui de forma única cada element de la xarxa per tal d’assignar-li la seva corresponent configuració.

A més, dins la xarxa, hi ha molts més elements (per exemple, estacions de treball),	alguns dels	quals no estan	permanentment connectats o permeten mobilitat física (portàtils, mòbils, tauletes, etc.)

També hem de tenir en compte que depenent de les dimensions de la xarxa, el nombre d’adreces disponibles pot ser limitat.Per tant, ens pot interessar no assignar estàticament ni de forma permanent una adreça IP a un dispositiu.
L’assignació dinàmica ens permet, de forma automàtica, assignar al dispositiu una adreça IP lliure dins un rang preestablert, i així evitar la feina manual de configuració a l’administrador de la xarxa.
Ho veurem implementat gràcies al servei DHCP.

## El servei DHCP

El servei DHCP implementa el protocol **DHCP (Dynamic Host Configuration Protocol)**  o  protocol  de  configuració  dinàmica  d’equips)  que  permet  la configuració d’adreces IP, màscares, passarel·les per defecte i moltes altres opcions de configuració de manera totalment dinàmica.

De forma automàtica cada equip rep una configuració amb la informació necessària per poder treballar en xarxa i poder accedir a altres equips i altres xarxes.

Els seus múltiples paràmetres de configuració permeten donar solució a les diferents situacions de xarxa que us podeu trobar.Qualsevol canvi a la xarxa s’aplica i es distribueix de forma centralitzada als clients connectats.

El protocol DHCP es troba dins la capa d’aplicació (capa 7 del model OSI).

Treballa amb arquitectura C/S.
Els ports associats al protocol son el 67 UDP per part del servidor i el 68 UDP per part del client.
Cal configurar el nodes com a client de DHCP per tal que llancin la petició.
DHCP utilitza una llista centralitzada d’adreces IP per tal d’assignar, de manera dinàmica, la configuració de xarxa als diferents nodes que la formen.
El servidor de DHCP assigna temporalment (lease time) aquestes adreces IP als nodes que ho sol·liciten, i el temps d’assignació està en funció de la configuració concreta del servidor.
Quan aquest finalitza, el client pot sol·licitar una renovació.
El protocol DHCP es troba dins la capa d’aplicació (capa 7 del model OSI).
Treballa amb arquitectura C/S.
Els ports associats al protocol son el 67 UDP per part del servidor i el 68 UDP per part del client.
Cal configurar el nodes com a client de DHCP per tal que llancin la petició.
DHCP utilitza una llista centralitzada d’adreces IP per tal d’assignar, de manera dinàmica, la configuració de xarxa als diferents nodes que la formen.
El servidor de DHCP assigna temporalment (lease time) aquestes adreces IP als nodes que ho sol·liciten, i el temps d’assignació està en funció de la configuració concreta del servidor.
Quan aquest finalitza, el client pot sol·licitar una renovació.
Per  utilitzar  correctament  el  servei,  s’han  de  reservar  prèviament  les adreces que estaran disponibles per tal que cap altre dispositiu dins la mateixa xarxa local se’ls pugui assignar i hi hagi un conflicte d’IP.
De forma general, el funcionament és molt senzill:

* El client sol·licita una IP.
* El servidor li ofereix.
* El client l’accepta.
* El servidor la confirma, ho registra, i li proporciona la resta de configuració de xarxa.
* El client però, com “coneix” el servidor?
* Com pot fer la petició inicial si encara no té IP?

Recordeu que l’assignació de la IP és per un temps determinat.Aquest temps el determina la configuració del servidor.Passat el temps, el client haurà de renovar la concessió de la IP.

Inicialment la petició del client no es fa a una IP en concret, ja que en aquell moment el client és un nou membre a la xarxa i desconeix com aquesta funciona.
Per això la petició que fa el client es fa a l’adreça MAC de broadcast.Això vol dir que tots els membres de la xarxa el veuran, però només haurà de respondre aquell o aquells que tinguin el servei de DHCP configurat i actiu.

## El procés d'assignació d'IP

El procés d’assignació d’adreces es resumeix en:

* Quan un dispositiu client es connecta a la xarxa en mode dinàmic, envia un missatge de difusió (broadcast) a la xarxa sol·licitant una adreça IP. En el missatge s’inclou l’adreça MAC del client.
  
* El servidor DHCP veu la petició i anota la MAC a la seva llista, i li respon un missatge on li ofereix una IP, una màscara, i una sèrie de paràmetres addicionals (gateway i
DNS habitualment) per tal que pugui formar part de la xarxa i connectar-se a d’altres xarxes si s’escau.
