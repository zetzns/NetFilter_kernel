#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ThatN");


static struct nf_hook_ops *nfhs = NULL; 

static unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph; //Структура для заголовка IP протокола
    struct tcphdr *tcp_header; //Структура для заголовка TCP протокола
    struct udphdr *udph; //Структура для заголовка UDP протокола
    
    if (!skb) return NF_ACCEPT; // Проверка на принадлежность пакетов к сетевому стеку. Если пакет не сетевой, то пропускаем
                                // skb - это soket buffer инициализирован в аргументах функции как struct sk_buff *skb. 
    iph = ip_hdr(skb); // Приравниваем наш указатель на указатель аналогичной структуры в skb.

    u32 src_ipa; //инициализация переменной для получения IP адреса источника пакета. u32 - это unsigned int
    src_ipa = ntohl(iph->saddr); //получаем IP адрес источника пакета

    if (iph->protocol == IPPROTO_TCP) //проверяем принадлежность протокола к TCP
    {
        // printk(KERN_INFO "TCP packet detected!\n"); //тут можно послать в системный лог сообщение ядра об обнаружении пакета, но нам этот мусор не нужен. Так, для информации.

        tcp_header = (struct tcphdr *) skb_transport_header(skb); //Приравниваем наш указатель на указатель аналогичной структуры в skb.

        //проверяем заголовок пакета на принадлежность его к типу SYN (запрос на соединение и порядковый номер пакета рамером 32 бит)
        //Начинает соединение и синхронизирует порядковые номера. Первый пакет, отправленный с каждой стороны, должен в обязательном порядке иметь установленным этот флаг.
        if(tcp_header->syn && !(tcp_header->urg || tcp_header->ack || tcp_header->psh || tcp_header->rst || tcp_header->fin))
        {
            printk(KERN_INFO "SYN Scan detected! Src IP: %pI4h \n" ,&src_ipa); //Выводим информацию в системный лог с указанием IP адреса источника пакета.
            return NF_DROP; // отбрасываем пакет - запрещаем его прохождение внутрь операционной системы и к другим приложениям
        }
                //проверяем заголовок пакета на тип NULL - отсутствие установленных флагов других типов. Такого типа не существует, но его так называют. 
                //Для того, чтобы определить его,надо проверить, что другие флаги не стоят.
                else if (!(tcp_header->syn || tcp_header->urg || tcp_header->ack || tcp_header->psh || tcp_header->rst || tcp_header->fin)) 
                {
                        printk(KERN_INFO "NULL Scan detected! Src IP: %pI4h \n" ,&src_ipa);
                        //Пропускаем, но можем и дропнуть, если надо.
                }
                //проверяем заголовок пакета на принадлежность его к типу ACK (подтверждение соединения и номер подтверждения в 32 бит)
                //Устанавливается, когда пакет содержит значение номера подтверждения в поле подтверждения. Все пакеты после стартового пакета SYN будут иметь установленный флаг ACK.
                else if (tcp_header->ack && !(tcp_header->urg || tcp_header->syn || tcp_header->psh || tcp_header->rst || tcp_header->fin)) 
                {
                        printk(KERN_INFO "ACK/Window Scan detected! Src IP: %pI4h \n" ,&src_ipa);
                        return NF_DROP; //Пропускать не велено.
                }
                //проверяем заголовок пакета на принадлежность его к типу FIN (завершение соединения)
                //Одна из конечных точек отправляет пакет с установленным флагом FIN для другой конечной точки, чтобы сообщить, что все пакеты были отправлены, и соединение пора завершить.
                else if (tcp_header->fin && !(tcp_header->urg || tcp_header->ack || tcp_header->psh || tcp_header->rst || tcp_header->syn)) 
                {
                        printk(KERN_INFO "FIN Scan detected! Src IP: %pI4h \n" ,&src_ipa);
                        return NF_DROP; //Дропаем
                }
                //XMAS — это метод скрытного сканирования портов, который отправляет TCP-пакет с флагами URG, PSH и FIN, установленными в 1.
                //Так называется, так как диаграмма флагов якобы похожа на новогоднюю ёлку. )))
                else if (tcp_header->fin &&  tcp_header->urg && tcp_header->psh && !(tcp_header->syn && tcp_header->rst && tcp_header->ack)) 
                {
                        
                    printk(KERN_INFO "XMAS Scan detected! Src IP: %pI4h \n" ,&src_ipa);
                    return NF_DROP; //Соответственно, дропаем этот пакет.
                }
        
        return NF_ACCEPT; //Если пакет не принадлежит ни к одному виду TCP, то мы разрешаем ему пройти дальше.
    }
    else if (iph->protocol == IPPROTO_UDP) //Если протокол UDP
    {
        printk(KERN_INFO "UDP packet detected!\n");

        udph = udp_hdr(skb);
        
        if (ntohs(udph->dest) == 53) //Если порт 53
        {
            return NF_ACCEPT;
        }
    }
    //Всё остальное от UDP дропаем
    return NF_DROP;
}

static int __init fwkm_init(void)
{
    nfhs = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    
    // Инициализация netfilter hook 
    nfhs->hook  = (nf_hookfn*)hook_func;        //Передача структуре функции hook
    nfhs->hooknum   = NF_INET_PRE_ROUTING;      //Указываем работать с входящими пакетами после стадии INPUT
    nfhs->pf    = PF_INET;                      //Указываем на протокол IPv4
    nfhs->priority  = NF_IP_PRI_FIRST;          //Уровень приоритета нашей hook-функции
    
    nf_register_net_hook(&init_net, nfhs); //вызов функции создания структуры сетевого фильтра с указанием ссылки имеющихся сетевых интерфейсов (&init_net)
    return 0;
}

static void __exit fwkm_exit(void)
{
    nf_unregister_net_hook(&init_net, nfhs); //вызов функции удаления из памяти всех структур
    kfree(nfhs);
}

module_init(fwkm_init);
module_exit(fwkm_exit);
