# IPK Projekt 1 - Vytvoření serveru
## Václav Valenta (xvalen29)
### Přeložení

Přeložení projektu se provádí příkazem make, který vytvoří spustitelný soubor hinfosvc.

```bash
make 
```

### Spuštění

Server je spustitelný s argumentem označující lokální port.

```bash
./hinfosvc [port]
```

Server je možné ukončit pomocí CTRL+C.

### Příklady použití

Tento příkaz vytvoří server na portu 12345.
```bash
./hinfosvc 12345 &
```

Získání informací o CPU 
```
curl http://localhost:12345/hostname
```

Zobrazenie názvu procesora serveru.
```
curl http://localhost:12345/cpu-name
```

Aktuální zátěž.
```
curl http://localhost:12345/load
```