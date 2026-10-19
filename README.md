<p align="center"><img src="docs/logo.png" width="160" alt="VulnBuster"></p>

# VulnBuster — zarządzanie podatnościami (on-prem, wielu użytkowników)

*who you gonna patch?*

![License: MIT](https://img.shields.io/badge/license-MIT-green) ![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue) ![Dependencies: cryptography](https://img.shields.io/badge/deps-cryptography%20%7C%20openpyxl-lightgrey)

Webowa aplikacja do codziennej pracy z podatnościami.

Zakres funkcji:
- przegląd wpisów CISA KEV,
- reguły wersji naprawionych per gałąź,
- import inwentarza z Excela, Lansweepera czy CMDB z automatycznym rozpoznawaniem kolumn i porządkowaniem nazw aplikacji,
- **spółki i zespoły realizujące** (Windows, Linux, sieć, helpdesk…) przypisywane regułami,
- **ocena podatności dla organizacji**: wpływ, sposób wykorzystania, wycena ryzyka, termin z SLA,
- **raporty per spółka / zespół / typ sprzętu** z eksportem do Excela,
- **gotowe zgłoszenia do helpdesku per zespół** (tekst do wklejenia albo szkic e-mail .eml z listą hostów),
- porównanie stanu przed i po patchowaniu (także per spółka i zespół),
- mitygacje, ekspozycja, wyjątki, raporty per host i per aplikacja,
- konta użytkowników z rolami i **dziennikiem zmian**.

Dane są w **zaszyfrowanym pliku JSON** (AES-256-GCM), dziennik zmian w osobnym zaszyfrowanym pliku tylko do dopisywania.

## Wdrożenie na serwerze w labie (Windows, RDP) — paczka portable

Na serwerze nic nie instalujesz. Python jest wbudowany w paczkę.

**1. Budowa paczki.** Na dowolnym komputerze z Windows i internetem uruchom:

```powershell
powershell -ExecutionPolicy Bypass -File .\portable\build-portable.ps1
```

Skrypt:
- pobiera oficjalny *embeddable* Python 3.12 z python.org,
- instaluje do niego `cryptography` i `openpyxl`,
- kopiuje aplikację,
- uruchamia testy,
- tworzy `dist\VulnBuster-portable.zip` (ok. 25 MB).

Jest też tryb offline (`-WheelDir`, `-PythonZip`, `-GetPip`). Szczegóły w nagłówku skryptu.

**2. Instalacja na serwerze.** Rozpakuj paczkę, np. do `C:\VulnBuster`. W PowerShell uruchomionym jako administrator wykonaj:

```powershell
powershell -ExecutionPolicy Bypass -File .\install-task.ps1
```

Skrypt:
- rejestruje zadanie *VulnBuster*, które startuje przy rozruchu serwera jako **SYSTEM** (opcjonalnie `-ServiceAccount DOMENA\gmsa$`) i restartuje się po awarii,
- ustawia uprawnienia NTFS do `data\` i `logs\` tylko dla SYSTEM i Administratorów,
- tworzy skrót *VulnBuster* na pulpicie wszystkich użytkowników.

Aplikacja nasłuchuje na `127.0.0.1:8443`. Na Windows Server loopback jest wspólny dla wszystkich sesji RDP, więc każdy zalogowany przez RDP ma do niej dostęp, ale tylko po zalogowaniu własnym kontem w aplikacji.

**3. Pierwsze uruchomienie.** Otwórz skrót i utwórz konto administratora. Potem w zakładce **Użytkownicy** załóż konta pozostałym osobom. Aplikacja wygeneruje hasła tymczasowe, które użytkownik zmienia przy pierwszym logowaniu.

**Ważne:**
- Użytkownicy RDP nie powinni mieć uprawnień administratora na tym serwerze.
- Uruchomienie ręczne bez zadania: `start.bat`.
- Odinstalowanie: `uninstall-task.ps1` (dane zostają).
- Aktualizacja: odinstaluj zadanie, podmień folder `app\`, zainstaluj ponownie.

### Inne uruchomienie (Linux / własny Python 3.10+)

```bash
pip install -r requirements.txt
python run.py --log logs/vulnbuster.log --quiet          # http://127.0.0.1:8443
```

| Opcja | Zmienna | Domyślnie |
|---|---|---|
| `--host` / `--port` | `VULNBUSTER_HOST` / `VULNBUSTER_PORT` | `127.0.0.1` / `8443` |
| `--data` | `VULNBUSTER_DATA` | `data/vulnbuster.json.enc` |
| `--cert` / `--key` | `VULNBUSTER_CERT` / `VULNBUSTER_KEY` | brak (HTTP) |
| `--log` / `--quiet` | `VULNBUSTER_LOG` | konsola / logowanie każdego żądania |

Jeśli aplikacja ma być dostępna z sieci (nie tylko przez RDP), uruchom ją z `--host 0.0.0.0 --cert … --key …` albo za reverse proxy z HTTPS.

## Użytkownicy i role

| Rola | Uprawnienia |
|---|---|
| **Podgląd** | odczyt, wyszukiwarka, raporty, CSV, dziennik zmian (np. administratorzy systemów przed oknem serwisowym) |
| **Analityk** | to co Podgląd + edycja danych, importy, decyzje KEV, reguły CVE, mitygacje, wyjątki |
| **Administrator** | wszystko + konta użytkowników, ustawienia, kopie zapasowe, blokada sejfu |

Zasady kont:
- Hasła mają minimum 12 znaków.
- Po 5 błędnych próbach konto blokuje się na 15 minut.
- Sesja wygasa po 8 h bezczynności.
- Ostatniego administratora nie da się usunąć, zablokować ani zdegradować.
- Zablokowanie konta usuwa klucz użytkownika i kończy jego sesje.
- Odblokowanie konta wymaga ustawienia nowego hasła tymczasowego.

## Bezpieczeństwo

- **Klucze per użytkownik (jak keysloty LUKS):**
  - Dane szyfruje losowy klucz DEK (AES-256-GCM).
  - DEK jest zaszyfrowany osobno dla każdego konta kluczem wyprowadzonym z hasła (scrypt N=2^15, r=8, p=1).
  - Po restarcie serwera sejf jest zablokowany. Odblokowuje go pierwsze poprawne logowanie dowolnego aktywnego użytkownika, więc nie ma wspólnego hasła głównego.
  - Loginy nie są jawne w pliku: identyfikator slotu to SHA-256(file_id | login).
- **Dziennik zmian:**
  - Każdy zapis tworzy wpis: kto, kiedy, akcja oraz zmienione pola (było → jest).
  - Wpisy są szyfrowane i dopisywane do `*.audit.enc`.
  - Wpisy łączy łańcuch SHA-256 (`prev → hash`), więc usunięcie, przestawienie albo podmiana wpisu jest wykrywana. Spójność łańcucha widać w zakładce **Dziennik zmian**.
  - Rejestrowane są też logowania, nieudane próby i blokady kont.
- **Równoczesna edycja:** jeśli ktoś zmienił obiekt (CVE, host, aplikację), od kiedy go otworzyłeś, zapis zostaje odrzucony z informacją, kto i kiedy go zmienił. Nic nie jest nadpisywane po cichu.
- **Wycofanie zmian:** nieudane żądanie (błąd walidacji w połowie operacji) przywraca stan z dysku. W pamięci nie zostają półzapisane dane.
- **Kopie zapasowe:** automatycznie do `data\backups\` (co godzinę i przed każdym importem, ostatnie 30 kopii, razem z dziennikiem). Kopia otwiera się hasłem dowolnego konta, które było aktywne w chwili jej wykonania.
- **Pliki danych:**
  - Szczegóły importów (do porównań) są w `data\imports\`, zaszyfrowane i skompresowane. Liczbę trzymanych importów ustawiasz w Ustawieniach.
  - Główna baza jest kompresowana, więc nawet ~100 tys. instalacji to kilka MB.
  - Kopiując dane na inny serwer, kopiuj cały katalog `data`.
- **Ochrona przeglądarki:**
  - cookie sesji `HttpOnly` i `SameSite=Strict`,
  - wymagany nagłówek anty-CSRF,
  - restrykcyjny CSP: bez zewnętrznych skryptów i CDN, działa offline,
  - nagłówki `X-Frame-Options` i `nosniff`.
- **Ruch wychodzący:** serwer łączy się z internetem tylko po kliknięciu „Pobierz z CISA” lub „Podpowiedz z NVD”. Respektuje `HTTPS_PROXY`. Bez internetu wgrywasz plik KEV ręcznie.

## Jak pracować

### 1. Codzienny przegląd KEV
Wejdź w **Przegląd KEV → Pobierz z CISA**. Jeśli serwer nie ma internetu, wgraj plik `known_exploited_vulnerabilities.json`.

Przy każdym wpisie aplikacja pokazuje dopasowane aplikacje z rejestru, z liczbą hostów i statusem *używamy / nie używamy*. Pokazuje też wcześniejszą decyzję dla tego samego produktu wraz z datą weryfikacji. Jeśli decyzja jest starsza niż próg (domyślnie 90 / 150 dni), dostaniesz ostrzeżenie, że stan mógł się zmienić.

Decyzja **„Nie używamy”** dopisuje produkt do rejestru aplikacji nieużywanych, razem z notatką i datą. Wyszukiwarka (klawisz `/`) od razu pokazuje te informacje.

### 2. Reguły wersji naprawionych (CVE)
W karcie CVE podaj, w jakich wersjach błąd został naprawiony, osobno dla każdej gałęzi:

```
12: 12.18, 14: 14.11, 16: 16.2, 11: brak, 10: niepodatne
```

- `brak` oznacza brak poprawki w gałęzi, więc wynik to *podatne* i potrzebna jest migracja lub mitygacja.
- `niepodatne` oznacza, że gałąź nie jest dotknięta.

Gałąź nieopisana i starsza od opisanych dostaje domyślnie status *do weryfikacji*. Można to zmienić na *podatne* albo *niepodatne*. Wersja nowsza niż wszystkie opisane gałęzie jest *niepodatna*.

Przycisk **„Podpowiedz z NVD”** wypełnia gałęzie na podstawie zakresów CPE z NVD. Zawsze je sprawdź.

**Pakiety dystrybucyjne** (RHEL, Debian, Ubuntu) mają backporty poprawek. W regule wpisuj wtedy wersję dystrybucji, np. `14: 2.4.57-2+deb12u2` albo `*: 2.4.37-62.el8_9`.

Obsługiwane formaty wersji to m.in.:
- semver,
- prerelease (`rc`, `beta`),
- epoka i rewizja Debian/RPM,
- Windows build (`10.0.19045.4651`),
- Cisco (`15.2(4)M7`),
- OpenSSL/OpenSSH (`1.1.1w`, `9.6p1`).

### 3. Import z Excela (Lansweeper, CMDB, skanery)
Zaznacz w Excelu zakres razem z nagłówkami, skopiuj (Ctrl+C) i wklej w **Import z Excela**. Możesz też wybrać plik `.xlsx` lub `.csv`. Kolumny są rozpoznawane po nagłówkach (PL/EN, w tym nazwy z Lansweepera: `AssetName`, `AssetTypename`, `IPAddress`, `OS`, `OSVersion`, `Software`, `softwareVersion`, `SoftwarePublisher`) i po zawartości. Mapowanie da się poprawić w podglądzie, a dla tego samego układu kolumn jest zapamiętywane razem z opcjami importu. Kolejny eksport z Lansweepera to więc: wklej → sprawdź → zapisz.

Rozpoznawane pola:
- Host, IP
- **Spółka**, **Zespół / realizator**
- Typ, System, **Wersja / build systemu**
- **Ekspozycja** (Internet / DMZ / wewnętrzna, także tak/nie)
- Środowisko, Krytyczność, Lokalizacja
- Właściciel, Administrator, Użytkownik
- Aplikacja, Producent, Wersja
- CVE, Wersja naprawiona
- Uwagi

Porządkowanie danych z Lansweepera i podobnych źródeł:
- **Upraszczanie nazw:** „PostgreSQL 14” → „PostgreSQL”, „7-Zip 23.01 (x64)” → „7-Zip”, „Mozilla Firefox (x64 en-US)” → „Mozilla Firefox”. W podglądzie widać, co zostało zmienione.
- **Lista ignorowanych** (Ustawienia → Import): domyślnie aktualizacje KB, pakiety językowe i redystrybuowalne VC++. Wzorce z `*`.
- **Tryb „tylko aplikacje z rejestru”:** pomija wszystko, czego nie ma w rejestrze. Podgląd pokazuje listę pominiętych nazw z liczbą wystąpień, żeby nic ważnego nie umknęło.
- **Aliasy z `*`** w karcie aplikacji (np. `Mozilla Firefox*`) łączą różne warianty nazwy w jedną aplikację.
- **System operacyjny jako aplikacja:** z kolumny systemu powstają instalacje „Windows Server 2019”, „Windows 11”, „Red Hat Enterprise Linux”, „Cisco IOS XE”, z wersją z kolumny *Wersja / build systemu*. Dzięki temu CVE systemów i firmware (częste w KEV) są oceniane tak samo jak aplikacji.
- **Kilka gałęzi na jednym hoście** (np. PostgreSQL 14 i 16) to osobne instalacje. Kilka wersji z tej samej gałęzi: do oceny bierzemy najniższą i wyświetlamy ostrzeżenie.
- Arkusz z samymi hostami (CMDB: host, spółka, zespół, właściciel, ekspozycja) aktualizuje dane hostów bez dotykania aplikacji.

W jednym arkuszu mogą być:
- **inwentarz** (host + aplikacja + wersja),
- **reguły CVE** (CVE + aplikacja + wersja naprawiona); gałąź jest wyprowadzana automatycznie, np. `14.11` → gałąź `14`,
- oba naraz.

Zanim cokolwiek zapiszesz, zobaczysz ocenę każdego wiersza.

> Ustaw kolumny z wersjami w Excelu jako **Tekst**. Excel zamienia `14.10` na liczbę `14.1`. Przy wklejaniu przez schowek ten problem nie występuje.

### 4. Spółki i zespoły (realizatorzy)
Każdy host ma **spółkę** (z importu, ręcznie albo masowo na liście hostów: zaznacz → „Ustaw dla zaznaczonych”) i **zespół, który go łata**. Zespół wynika z reguł w Ustawieniach, sprawdzanych od góry. Domyślne reguły:

| Reguła | Zespół |
|---|---|
| switch / router / firewall / IOS / FortiOS… | Networkers |
| Windows Server | Windows team |
| Windows 10/11, laptopy, stacje | Helpdesk |
| Linux / RHEL / Ubuntu… | Linux team |

Kolejność ustalania zespołu:
1. zespół przypisany do **aplikacji** (np. DBA dla PostgreSQL, gdy bazę łata inny zespół niż ten od serwera),
2. reguły po nazwie aplikacji,
3. zespół ustawiony ręcznie na hoście,
4. reguły hosta.

Przycisk „Sprawdź przypisanie hostów” pokazuje, ile hostów trafi do którego zespołu, jeszcze przed zapisaniem reguł. Każdy zespół ma adres e-mail (kolejka helpdesku) używany w zgłoszeniach.

### 5. Ocena podatności i termin
W karcie CVE, w sekcji **„Ocena dla organizacji”**, wpisujesz:
- wycenę ryzyka: poziom (krytyczne / wysokie / średnie / niskie) i ocenę 0–10,
- wpływ na organizację,
- jak podatność może zostać wykorzystana,
- opcjonalne zalecenie,
- termin załatania.

Przycisk **„z SLA”** ustawia termin jako dziś + liczba dni z Ustawień (domyślnie 7 / 30 / 90 / 180), a przycisk **KEV** przepisuje termin CISA. Termin trafia do raportów i zgłoszeń, a przekroczony jest oznaczany jako „po terminie” (licznik na pulpicie).

### 6. Raporty per spółka / zespół
Zakładka **Raporty**: grupowanie wg spółki, zespołu, typu urządzenia, systemu, środowiska, lokalizacji, właściciela, ekspozycji lub aplikacji. Zakres to wszystkie aplikacje, jedna aplikacja (np. „PostgreSQL per spółka”) albo jedno CVE, opcjonalnie tylko KEV i filtr spółki, zespołu czy typu.

Raport zawiera podsumowanie (hosty, do działań, KEV, po terminie, postęp) i szczegóły per grupa. Formy wyjścia:
- **Excel:** arkusz podsumowania i osobny arkusz dla każdej spółki lub zespołu, z autofiltrem,
- **CSV**,
- **druk / PDF**.

### 7. Zgłoszenia do helpdesku (per zespół)
Z karty CVE, karty aplikacji albo z Raportów: **„Zgłoszenia do realizatorów”**. Aplikacja dzieli hosty wymagające działań wg zespołów. Np. podatność na stacjach i serwerach daje osobne zgłoszenie dla Helpdesku i dla Windows teamu. Można też dzielić wg zespołu i spółki.

Każde zgłoszenie powstaje z szablonu (Ustawienia → Szablon zgłoszenia) i zawiera:
- wycenę ryzyka i termin,
- opis CVE,
- sposób wykorzystania i wpływ na organizację,
- wymagane działanie z wersjami docelowymi per gałąź,
- listę hostów (nazwa, IP, spółka, wersja obecna → docelowa).

Co możesz zrobić ze zgłoszeniem:
- poprawić treść przed wysłaniem,
- **skopiować** temat i treść do formularza helpdesku,
- **pobrać szkic e-mail (.eml)**, który Outlook otwiera do wysłania. Ma adres zespołu i listę hostów w CSV jako załącznik,
- **oznaczyć jako zgłoszone** z numerem ticketu. Widać to potem przy CVE i w historii zgłoszeń, a dziennik zmian zapisuje, kto zgłosił.

### 8. Po oknie serwisowym
Zaimportuj stan ponownie i otwórz **Porównanie importów**. Zobaczysz:
- instalacje załatane, nadal podatne, z nowymi podatnościami i brakujące,
- procent skuteczności patchowania, z filtrem i podsumowaniem wg spółki, zespołu albo aplikacji.

Ocena idzie zawsze według aktualnych reguł CVE.

### 9. Mitygacje, ekspozycja i wyjątki
- **Mitygacja na hoście:** wybierasz grupę podatności (np. „Interfejs zarządzania”) albo konkretne CVE, opcjonalnie tylko dla jednej aplikacji. Takie podatności są liczone jako *mitygowane*.
- **Ekspozycja „sieć wewnętrzna”:** CVE z grupą „Wymaga ekspozycji do Internetu” są mitygowane automatycznie. Można to wyłączyć w karcie CVE. Hosty wystawione do internetu są wyżej na pulpicie.
- **Wyjątek:** informacja od właściciela, że aktualizacja nie jest możliwa. Zawiera powód, osobę przekazującą, środki kompensujące i datę przeglądu. Po terminie przeglądu wyjątek jest oznaczany na pulpicie.

### 10. Raporty per host i aplikacja
- **Host → „Raport na okno serwisowe”:** lista aplikacji do aktualizacji z minimalną wersją docelową, CVE, terminami i polami do odhaczenia. Druk lub zapis do PDF z przeglądarki.
- **Aplikacja → „Raport do druku”:** postęp patchowania, podział na gałęzie wersji, hosty z właścicielami i historia importów.
- **Eksport CSV:** dostępny na większości list (średnik i BOM, otwiera się poprawnie w polskim Excelu).

## Testy

```bash
python -m unittest discover -s tests -v
```

## Struktura

```
run.py                  uruchomienie
portable/               budowa paczki Windows z wbudowanym Pythonem, instalacja zadania
vulnbuster/storage.py   sejf z kluczami per użytkownik, dziennik z łańcuchem SHA-256, kopie
vulnbuster/versions.py  porównywanie wersji
vulnbuster/engine.py    ocena CVE × inwentarz, zespoły, mitygacje, wyjątki, raporty, porównania
vulnbuster/tickets.py   zgłoszenia do realizatorów (szablon, .eml)
vulnbuster/xlsx_export.py  raporty do Excela
vulnbuster/importer.py  parsowanie Excela/CSV, rozpoznawanie kolumn, import
vulnbuster/feeds.py     CISA KEV i NVD (opcjonalnie)
vulnbuster/server.py    serwer HTTP + API, konta, role, sesje, diff zmian
vulnbuster/static/      interfejs (bez zewnętrznych zależności)
```

## Licencja

VulnBuster jest udostępniony na licencji **MIT**, pełny tekst jest w pliku [LICENSE](LICENSE).

Copyright (c) 2026 **Marcin Lewandowski** <marcin.lewandowski.x@gmail.com> · [github.com/mael777it/VulnBuster](https://github.com/mael777it/VulnBuster)

### Komponenty zewnętrzne

Repozytorium zawiera wyłącznie kod VulnBuster. Paczka portable budowana skryptem `portable/build-portable.ps1` dołącza ponadto:

- **Python** (embeddable package) — [PSF License](https://docs.python.org/3/license.html)
- **cryptography** — Apache-2.0 / BSD-3-Clause
- **cffi** — MIT, **pycparser** — BSD-3-Clause (zależności cryptography)
- **openpyxl** — MIT, **et_xmlfile** — MIT

Licencje tych komponentów znajdują się w paczce: w katalogu `python\` oraz w `python\Lib\site-packages\*.dist-info\`.

Dane CISA KEV i NVD są pobierane na żądanie użytkownika z publicznych źródeł rządu USA i nie są dołączone do repozytorium.

VulnBuster nie jest powiązany z CISA, NIST ani żadnym producentem oprogramowania.
