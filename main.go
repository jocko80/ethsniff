package main

import (
        "encoding/binary"
        "fmt"
        "log"
        "net"
        "os"
        "os/signal"
        "syscall"

        "golang.org/x/sys/unix"
)

// EtherType — тип протокола в Ethernet-кадре.
// В C это была бы константа через #define. В Go — типизированная константа.
type EtherType uint16

const (
        EtherTypeIPv4        EtherType = 0x0800
        EtherTypeARP         EtherType = 0x0806
        EtherTypeVLAN        EtherType = 0x8100
        EtherTypeIPv6        EtherType = 0x86DD
        EtherTypePPPoEDisc   EtherType = 0x8863
        EtherTypePPPoESess   EtherType = 0x8864
)

// String() — это реализация интерфейса fmt.Stringer.
// В C аналог — switch с возвратом строки, но здесь это делается красивее.
// Когда вы напишете fmt.Println(et), Go автоматически вызовет String().
func (e EtherType) String() string {
        switch e {
        case EtherTypeIPv4:
                return "IPv4"
        case EtherTypeARP:
                return "ARP"
        case EtherTypeVLAN:
                return "VLAN"
        case EtherTypeIPv6:
                return "IPv6"
        case EtherTypePPPoEDisc:
                return "PPPoE-Discovery"
        case EtherTypePPPoESess:
                return "PPPoE-Session"
        default:
                return fmt.Sprintf("Unknown(0x%04x)", uint16(e))
        }
}

// formatMAC превращает 6 байт в "aa:bb:cc:dd:ee:ff".
// В C вы бы использовали snprintf с %02x. В Go — fmt.Sprintf.
func formatMAC(mac []byte) string {
        if len(mac) < 6 {
                return "??:??:??:??:??:??"
        }
        return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func main() {
        if len(os.Args) < 2 {
                fmt.Fprintf(os.Stderr, "Usage: %s <interface>\n", os.Args[0])
                fmt.Fprintf(os.Stderr, "Example: sudo %s eth0\n", os.Args[0])
                os.Exit(1)
        }
        ifaceName := os.Args[1]

        // Шаг 1: получаем ifindex интерфейса.
        // В C: if_nametoindex(ifaceName)
        iface, err := net.InterfaceByName(ifaceName)
        if err != nil {
                log.Fatalf("interface %q: %v", ifaceName, err)
        }

        // Шаг 2: создаём raw-сокет AF_PACKET.
        // В C: socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
        //
        // Важно: ETH_P_ALL в Go определён в unix как unix.ETH_P_ALL.
        // htons делает ядро за нас — в Go принято передавать уже в сетевом порядке,
        // но здесь Go-обёртка unix ожидает host order, а внутри сама делает htons.
        fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
        if err != nil {
                log.Fatalf("socket: %v (нужен root?)", err)
        }
        defer unix.Close(fd)

        // Шаг 3: привязываем сокет к интерфейсу.
        // В C: struct sockaddr_ll + bind()
        sa := &unix.SockaddrLinklayer{
                Protocol: htons(unix.ETH_P_ALL),
                Ifindex:  iface.Index,
        }
        if err := unix.Bind(fd, sa); err != nil {
                log.Fatalf("bind: %v", err)
        }

        fmt.Printf("Listening on %s (ifindex=%d), press Ctrl+C to stop\n\n", ifaceName, iface.Index)

        // Шаг 4: обработка Ctrl+C.
        // В C: signal(SIGINT, handler). В Go — каналы и context.
        sigCh := make(chan os.Signal, 1)
        signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
        go func() {
                <-sigCh
                fmt.Println("\nStopping...")
                unix.Close(fd) // закроем сокет, Recvfrom вернёт ошибку, цикл завершится
        }()

        // Шаг 5: главный цикл чтения.
        // В C: while(1) { recv(fd, buf, ...) }
        buf := make([]byte, 65536) // один раз аллоцируем, переиспользуем — важно для производительности
        for {
                n, _, err := unix.Recvfrom(fd, buf, 0)
                if err != nil {
                        // Если сокет закрыт — выходим
                        if err == unix.EBADF || err == unix.EINTR {
                                return
                        }
                        log.Printf("recvfrom: %v", err)
                        continue
                }
                if n < 14 { // минимум для Ethernet-заголовка
                        continue
                }

                // Разбираем Ethernet-заголовок.
                // Формат: [dstMAC 6][srcMAC 6][etherType 2][payload...]
                dstMAC := buf[0:6]
                srcMAC := buf[6:12]
                ethType := EtherType(binary.BigEndian.Uint16(buf[12:14]))

                // Печатаем
                fmt.Printf("%s -> %s  %-18s  len=%d\n",
                        formatMAC(srcMAC),
                        formatMAC(dstMAC),
                        ethType.String(),
                        n,
                )

                // Бонус: если это PPPoE Discovery — покажем код пакета.
                if ethType == EtherTypePPPoEDisc && n >= 16 {
                        code := buf[15]
                        fmt.Printf("    └─ PPPoE Discovery code=0x%02x (%s)\n",
                                code, pppoeCodeName(code))
                }
        }
}

// htons — преобразование из host в network byte order.
// В Go binary.BigEndian уже даёт нужный порядок, но для передачи в syscall
// нужно вручную "перевернуть" на little-endian машинах.
func htons(v uint16) uint16 {
        return (v<<8)&0xff00 | v>>8
}

// Расшифровка кодов PPPoE Discovery — чтобы вывод был читаемым.
func pppoeCodeName(code byte) string {
        switch code {
        case 0x09:
                return "PADI"
        case 0x07:
                return "PADO"
        case 0x19:
                return "PADR"
        case 0x65:
                return "PADS"
        case 0xA7:
                return "PADT"
        default:
                return "?"
        }
}
