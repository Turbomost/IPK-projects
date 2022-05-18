# IPK - Varianta ZETA: Sniffer paketů
## Václav Valenta (xvalen29)
### Překlad programu


```bash
make
```

### Spouštění programu

```bash
./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}
```
Přepínače -i nebo --interface definuje rozhraní. V případě, že rozhraní není zadáno, program vypíše seznam všech rozhraní.

Přepínač -p nebo --port slouží ke specifikaci určitého portu, na kterým se má komunikace zachytávat. Pokud port není specifikován, program bude zachytávat komunikaci na všech portech.

Další přepínače určují typ paketů, které se mají vypisovat (--tcp | -t, --udp | -u, --arp, --icmp). Pokud tyto přepínače nejsou uvedeny, nebo jejich kombinace je neplatná, uvažují se všechny zmíněné typy. Zadaný port se nemění.

Poslední přepínač -n určuje kolik paketů program vypíše.

### Příklad spuštění

```bash
./ipk-sniffer -i eth0
```

### Výstup:

```bash
timestamp: 2022-04-24T23:09:34.199+02:00
src MAC: 00:15:5d:b9:2c:3f
dst MAC: ff:ff:ff:ff:ff:ff
frame length: 305 bytes
src IP: 172.29.144.1
dst IP: 172.29.159.255
src port: 54915
dst port: 54915
0x0000: ff ff ff ff ff ff 00 15  5d b9 2c 3f 08 00 45 00  ........ ].,?..E.
0x0010: 01 23 e3 ec 00 00 80 11  cd a1 ac 1d 90 01 ac 1d  .#...... ........
0x0020: 9f ff d6 83 d6 83 01 0f  ce b2 00 44 45 53 4b 54  ........ ...DESKT
0x0030: 4f 50 2d 56 47 41 33 45  4d 33 00 00 00 00 00 00  OP-VGA3E M3......
0x0040: 00 00 80 29 56 f2 f5 01  00 00 a0 b8 8f 52 b6 00  ...)V... .....R..
0x0050: 00 00 a0 4b d8 ef f5 01  00 00 33 27 00 00 00 00  ...K.... ..3'....
0x0060: 00 00 70 29 56 f2 f5 01  00 00 60 ba 02 ed f5 01  ..p)V... ..`.....
0x0070: 00 00 60 bc 8f 52 b6 00  00 00 60 bc 8f 52 b6 00  ..`..R.. ..`..R..
0x0080: 00 00 c6 74 52 f7 f9 7f  00 00 07 01 00 00 00 00  ...tR... ........
0x0090: 00 00 80 ba 8f 52 b6 00  00 00 30 df 55 f2 f5 01  .....R.. ..0.U...
0x00a0: 00 00 10 f6 4d f2 f5 01  00 00 28 10 20 7b 63 33  ....M... ..(. {c3
0x00b0: 33 36 31 31 31 61 2d 32  63 30 61 2d 34 39 32 37  36111a-2 c0a-4927
0x00c0: 2d 61 32 34 65 2d 34 63  32 36 65 34 33 32 36 30  -a24e-4c 26e43260
0x00d0: 38 62 7d 00 01 ed f5 01  00 00 80 ba 8f 52 1c 00  8b}..... .....R..
0x00e0: 00 00 00 00 00 00 00 00  00 00 01 00 00 00 00 00  ........ ........
0x00f0: 00 00 20 b9 8f 52 b6 00  00 00 00 00 00 00 00 00  .. ..R.. ........
0x0100: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ........ ........
0x0110: 00 00 00 00 00 00 f5 01  00 00 10 03 1b 9d 46 df  ........ ......F.
0x0120: 00 00 8a 51 5d f7 f9 7f  00 00 07 01 00 9e 77 91  ...Q]... ......w.
0x0130: 25                                                %
```