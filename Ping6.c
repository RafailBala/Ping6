#include <jni.h>
#include "LabNat.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           
#include <string.h>           
#include <netdb.h>            
#include <sys/types.h>        
#include <sys/socket.h>       
#include <netinet/in.h>       
#include <netinet/ip.h>       
#include <netinet/ip6.h>      
#include <netinet/icmp6.h>    
#include <arpa/inet.h>        
#include <sys/ioctl.h>        
#include <bits/ioctls.h>      
#include <net/if.h>           
#include <linux/if_ether.h>   
#include <linux/if_packet.h>  
#include <net/ethernet.h>
#include <sys/time.h>         
#include <errno.h>            

//константы
#define ETH_HDRLEN 14  // Длина заголовка Ethernet
#define IP6_HDRLEN 40  // Длина заголовка IPv6
#define ICMP_HDRLEN 8  // Длина заголовка ICMP 

// прототипы функций
uint16_t checksum (uint16_t *, int);
uint16_t icmp6_checksum (struct ip6_hdr, struct icmp6_hdr, uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);

int i, status, datalen, lendata,frame_length, sendsd, recvsd, bytes, timeout, trycount, trylim, done;
  char *interface, *target, *src_ip, *dst_ip, *rec_ip;
  struct ip6_hdr send_iphdr, *recv_iphdr;
  struct icmp6_hdr send_icmphdr, *recv_icmphdr;
  uint8_t *data,*dataf, *src_mac, *dst_mac, *send_ether_frame, *recv_ether_frame;
  struct addrinfo hints, *res;
  struct sockaddr_in6 *ipv6;
  struct sockaddr_ll device;
  struct ifreq ifr;
  struct sockaddr from;
  socklen_t fromlen;
  struct timeval wait, t1, t2;
  struct timezone tz;
  double dt;
  void *tmp;

JNIEXPORT jboolean JNICALL Java_LabNat_init(JNIEnv *env, jclass jcl, jstring jst)
{
  //выделение памяти
  src_mac = allocate_ustrmem (6);
  dst_mac = allocate_ustrmem (6);
  data = allocate_ustrmem (IP_MAXPACKET);
  dataf = allocate_ustrmem (IP_MAXPACKET);
  send_ether_frame = allocate_ustrmem (IP_MAXPACKET);
  recv_ether_frame = allocate_ustrmem (IP_MAXPACKET);
  interface = allocate_strmem (40);
  target = allocate_strmem (INET6_ADDRSTRLEN);
  src_ip = allocate_strmem (INET6_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET6_ADDRSTRLEN);
  rec_ip = allocate_strmem (INET6_ADDRSTRLEN);

  const char* interfaceName=(*env)->GetStringUTFChars(env,jst,NULL);
  strcpy (interface, interfaceName);
  (*env)->ReleaseStringUTFChars(env,jst,interfaceName);

  if ((sendsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed to get socket descriptor for using ioctl() ");
    exit (EXIT_FAILURE);
  }
  printf("End of initialization");
  return 1;
}

JNIEXPORT void JNICALL Java_LabNat_deinit
  (JNIEnv *env, jclass jcl){
//закрытие дескриптора сокета
  close (sendsd);
  close (recvsd);

  //освобождение памяти
  free (src_mac);
  free (dst_mac);
  free (data);
  free (send_ether_frame);
  free (recv_ether_frame);
  free (interface);
  free (target);
  free (src_ip);
  free (dst_ip);
  free (rec_ip);

  printf("End of deinitialization");
}

JNIEXPORT jint JNICALL Java_LabNat_sendTo(JNIEnv *env, jclass jcl, jbyteArray jba)
{
  jint lengthArr = (*env)->GetArrayLength(env,jba);
  datalen = lengthArr;
  jbyte b[lengthArr];
  (*env)->GetByteArrayRegion(env,jba,0,lengthArr,data);

  //Используем ioctl () для поиска имени интерфейса и его MAC-адреса
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (sendsd, SIOCGIFHWADDR, &ifr) < 0) {
    perror ("ioctl() failed to get source MAC address ");
    return (EXIT_FAILURE);
  }

  //Копируем исходный MAC-адрес
  memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

  // выводим исходный MAC-адрес
  printf ("MAC address for interface %s is ", interface);
  for (i=0; i<5; i++) {
    printf ("%02x:", src_mac[i]);
  }
  printf ("%02x\n", src_mac[5]);

  // Находим индекс интерфейса по имени интерфейса и сохраняем индекс в
  // struct sockaddr_ll устройство, которое будет использоваться в качестве аргумента sendto ()
  memset (&device, 0, sizeof (device));
  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
    perror ("if_nametoindex() failed to obtain interface index ");
    exit (EXIT_FAILURE);
  }
  printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);
//----------------------------------------------------------------------------------------
  // МАК адрес назначения
  dst_mac[0] = 0x08;
  dst_mac[1] = 0x00;
  dst_mac[2] = 0x27;
  dst_mac[3] = 0xd8;
  dst_mac[4] = 0xf1;
  dst_mac[5] = 0xc5;

  // Исходный IPv6-адрес
  strcpy (src_ip, "fe80::4353:9453:684d:af99");
  // Целевой IPv6 адрес
  strcpy (target, "::1");
//------------------------------------------------------------------------------------------
  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  ipv6 = (struct sockaddr_in6 *) res->ai_addr;
  tmp = &(ipv6->sin6_addr);
  if (inet_ntop (AF_INET6, tmp, dst_ip, INET6_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }
  freeaddrinfo (res);

  //Заполняем sockaddr_ll.
  device.sll_family = AF_PACKET;
  memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t));
  device.sll_halen = 6;

  // Версия IPv6 (4 бита), класс трафика (8 бит), метка потока (20 бит)
  send_iphdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);

  // Длина полезной нагрузки (16 бит): заголовок ICMP + данные ICMP
  send_iphdr.ip6_plen = htons (ICMP_HDRLEN + datalen);

  // Следующий заголовок (8 бит): 58 для ICMP
  send_iphdr.ip6_nxt = IPPROTO_ICMPV6;

  // Предел скачка (8 бит)
  send_iphdr.ip6_hops = 255;

  // Исходный IPv6-адрес (128 бит)
  if ((status = inet_pton (AF_INET6, src_ip, &(send_iphdr.ip6_src))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // IPv6-адрес назначения (128 бит)
  if ((status = inet_pton (AF_INET6, dst_ip, &(send_iphdr.ip6_dst))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Заголовок ICMP

  // Тип сообщения (8 бит)
  send_icmphdr.icmp6_type = ICMP6_ECHO_REQUEST;

  // Код сообщения (8 бит)
  send_icmphdr.icmp6_code = 0;

  // Идентификатор (16 бит)
  send_icmphdr.icmp6_id = htons (1000);

  // Порядковый номер (16 бит)
  send_icmphdr.icmp6_seq = htons (0);

  // Контрольная сумма заголовка ICMP (16 бит)
  send_icmphdr.icmp6_cksum = 0;
  send_icmphdr.icmp6_cksum = icmp6_checksum (send_iphdr, send_icmphdr, data, datalen);

  // ЗаполнЯЕМ заголовок кадра Ethernet
  // Длина кадра Ethernet = заголовок Ethernet (MAC + MAC + тип Ethernet) + данные Ethernet (заголовок IP + заголовок ICMP + данные ICMP)
  frame_length = 6 + 6 + 2 + IP6_HDRLEN + ICMP_HDRLEN + datalen;

  // MAC-адреса назначения и источника
  memcpy (send_ether_frame, dst_mac, 6 * sizeof (uint8_t));
  memcpy (send_ether_frame + 6, src_mac, 6 * sizeof (uint8_t));

  // код типа Ethernet (ETH_P_IPV6 для IPv6)
  send_ether_frame[12] = ETH_P_IPV6 / 256;
  send_ether_frame[13] = ETH_P_IPV6 % 256;

  // данные кадра Ethernet (заголовок IPv6 + заголовок ICMP + данные ICMP)
  // IPv6 header
  memcpy (send_ether_frame + ETH_HDRLEN, &send_iphdr, IP6_HDRLEN * sizeof (uint8_t));
  // ICMP header
  memcpy (send_ether_frame + ETH_HDRLEN + IP6_HDRLEN, &send_icmphdr, ICMP_HDRLEN * sizeof (uint8_t));
  // ICMP data
  memcpy (send_ether_frame + ETH_HDRLEN + IP6_HDRLEN + ICMP_HDRLEN, data, datalen * sizeof (uint8_t));
 
  // Отправка кадра Ethernet в сокет
    if ((bytes = sendto (sendsd, send_ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
      perror ("sendto() failed ");
      exit (EXIT_FAILURE);
    }
  printf("Sending is completed");
  return bytes;
}

JNIEXPORT jbyteArray JNICALL Java_LabNat_recvFrom(JNIEnv *env, jclass jcl, jbyteArray jba, jint jin){
  
  // Отправка запроса на необработанный дескриптор сокета для приема пакетов
  if ((recvsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed ");
    exit (EXIT_FAILURE);
  }
  // максимальное количество попыток проверки связи с удаленным хостом
  trylim = 3;
  trycount = 0;

  recv_iphdr = (struct ip6_hdr *) (recv_ether_frame + ETH_HDRLEN);
  recv_icmphdr = (struct icmp6_hdr *) (recv_ether_frame + ETH_HDRLEN + IP6_HDRLEN);

    for (;;) {

      memset (recv_ether_frame, 0, IP_MAXPACKET * sizeof (uint8_t));
      memset (&from, 0, sizeof (from));
      fromlen = sizeof (from);

      bytes = recvfrom (recvsd, recv_ether_frame, IP_MAXPACKET, 0, (struct sockaddr *) &from, &fromlen);
      if (bytes < 0) {

        status = errno;
	
        // проверка на ошибки
        if (status == EAGAIN) {  // EAGAIN = 11
          printf ("No reply within %i seconds.\n", timeout);
          trycount++;
          break;  
        } else if (status == EINTR) {  // EINTR = 4
          continue;  // что-то случилось
        } else {
          perror ("recvfrom() failed ");
          exit (EXIT_FAILURE);
        }
	
      }
	
      // Проверяем фрейм IP Ethernet, несущий эхо-ответ ICMP
      if ((((recv_ether_frame[12] << 8) + recv_ether_frame[13]) == ETH_P_IPV6) &&
         (recv_iphdr->ip6_nxt == IPPROTO_ICMPV6) && (recv_icmphdr->icmp6_type == ICMP6_ECHO_REPLY) && (recv_icmphdr->icmp6_code == 0)) {

        // Остановливаем таймер и считаем, сколько времени потребовалось, чтобы получить ответ
        (void) gettimeofday (&t2, &tz);
        dt = (double) (t2.tv_sec - t1.tv_sec) * 1000.0 + (double) (t2.tv_usec - t1.tv_usec) / 1000.0;

        // Извлекаем IP-адрес источника из полученного кадра Ethernet
        if (inet_ntop (AF_INET6, &(recv_iphdr->ip6_src), rec_ip, INET6_ADDRSTRLEN) == NULL) {
          status = errno;
          fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
          exit (EXIT_FAILURE);
        }

        lendata = 200-(IP6_HDRLEN + ICMP_HDRLEN);
	dataf = (uint8_t *)(recv_ether_frame + ETH_HDRLEN + IP6_HDRLEN + ICMP_HDRLEN);
	break;
      }  
    }
    jbyteArray result = (*env)->NewByteArray(env,lendata);
    (*env)->SetByteArrayRegion(env,result,0,lendata,(jbyte*) dataf);
    return result;
}

// Вычисление контрольной суммы в Интернете (RFC 1071).
uint16_t checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Суммируем 2-байтовые значения, пока не останется ни одного байта или не останется только один байт
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Добавляем оставшийся байт, если есть
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  answer = ~sum;

  return (answer);
}

// Создаем псевдозаголовок IPv6 ICMP и вызываем функцию контрольной суммы 
uint16_t icmp6_checksum (struct ip6_hdr iphdr, struct icmp6_hdr icmp6hdr, uint8_t *payload, int payloadlen)
{
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];

  // Скопируем исходный IP-адрес в buf (128 бит)
  memcpy (ptr, &iphdr.ip6_src.s6_addr, sizeof (iphdr.ip6_src.s6_addr));
  ptr += sizeof (iphdr.ip6_src);
  chksumlen += sizeof (iphdr.ip6_src);

  // CСкопируйте IP-адрес назначения в buf (128 бит)
  memcpy (ptr, &iphdr.ip6_dst.s6_addr, sizeof (iphdr.ip6_dst.s6_addr));
  ptr += sizeof (iphdr.ip6_dst.s6_addr);
  chksumlen += sizeof (iphdr.ip6_dst.s6_addr);

  // Скопируйте длину пакета верхнего уровня в буфер (32 бита)
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = (ICMP_HDRLEN + payloadlen) / 256;
  ptr++;
  *ptr = (ICMP_HDRLEN + payloadlen) % 256;
  ptr++;
  chksumlen += 4;

  // Копировать нулевое поле в buf (24 бита)
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Скопируем следующее поле заголовка в buf (8 бит)
  memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
  ptr += sizeof (iphdr.ip6_nxt);
  chksumlen += sizeof (iphdr.ip6_nxt);

  // Скопируем тип ICMPv6 в buf (8 бит)
  memcpy (ptr, &icmp6hdr.icmp6_type, sizeof (icmp6hdr.icmp6_type));
  ptr += sizeof (icmp6hdr.icmp6_type);
  chksumlen += sizeof (icmp6hdr.icmp6_type);

  // Скопируем код ICMPv6 в buf (8 бит)
  memcpy (ptr, &icmp6hdr.icmp6_code, sizeof (icmp6hdr.icmp6_code));
  ptr += sizeof (icmp6hdr.icmp6_code);
  chksumlen += sizeof (icmp6hdr.icmp6_code);

  // Скопируем идентификатор ICMPv6 в buf (16 бит)
  memcpy (ptr, &icmp6hdr.icmp6_id, sizeof (icmp6hdr.icmp6_id));
  ptr += sizeof (icmp6hdr.icmp6_id);
  chksumlen += sizeof (icmp6hdr.icmp6_id);

  // Скопируем порядковый номер ICMPv6 в буфер (16 бит)
  memcpy (ptr, &icmp6hdr.icmp6_seq, sizeof (icmp6hdr.icmp6_seq));
  ptr += sizeof (icmp6hdr.icmp6_seq);
  chksumlen += sizeof (icmp6hdr.icmp6_seq);

  // Скопируем контрольную сумму ICMPv6 в buf (16 бит)
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Скопируем полезные данные ICMPv6 в buf
  memcpy (ptr, payload, payloadlen * sizeof (uint8_t));
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Переходим к следующей 16-битной границе
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr += 1;
    chksumlen += 1;
  }

  return checksum ((uint16_t *) buf, chksumlen);
}

// Выделяем память для массива символов.
char * allocate_strmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Выделяем память для массива беззнаковых символов.
uint8_t * allocate_ustrmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}
