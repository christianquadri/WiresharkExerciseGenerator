# Configurazione dei flussi di pacchetti

Questo documento descrive come utilizzare il file di configurazione YAML per definire e generare flussi di traffico di rete (TCP e HTTP) tramite template predefiniti.

Il file consente di specificare uno o più **flow template**, ciascuno dei quali rappresenta un insieme coerente di parametri per la generazione di flussi di pacchetti tra un client e un server.

---

## Struttura generale del file

Il file di configurazione è composto da:

```yaml
seed: <intero>
flow_list:
  - flow_template:
      ...
```

### `seed`

* **Tipo**: intero
* **Descrizione**: seme per il generatore pseudo-casuale.
* **Scopo**: garantisce la riproducibilità dei flussi generati. A parità di `seed` e configurazione, i flussi risultanti saranno identici.

---

### `flow_list`

* **Tipo**: lista
* **Descrizione**: elenco dei flussi (o gruppi di flussi) da generare.

Ogni elemento della lista contiene una chiave `flow_template`.

---

## `flow_template`

Un `flow_template` definisce **come** e **quanti** flussi generare, oltre ai parametri di rete e applicativi.

### Campi principali

| Campo               | Tipo    | Obbligatorio | Descrizione                                                          |
|---------------------|---------|--------------|----------------------------------------------------------------------|
| `tag`               | stringa | no           | Identificatore logico del flusso, usato per debug, logging o analisi |
| `flow_generator`    | stringa | sì           | Nome del generatore di flussi (case-insensitive)                     |
| `flows_to_generate` | intero  | no           | Numero di flussi da generare (default = 1)                           |
| `flow_parameters`   | mappa   | sì           | Parametri specifici del generatore                                   |

---

## `flow_generator`

Il campo `flow_generator` determina il tipo di traffico simulato e quali parametri sono accettati.

Nel file di esempio sono utilizzati i seguenti generatori:

### `TCP_client_server`

Simula una comunicazione TCP client-server con possibilità di configurare perdita di pacchetti, SACK, fast retransmit e parametri applicativi.

#### Parametri supportati

| Parametro              | Tipo     | Obbligatorio | Default            | Descrizione                                          |
|------------------------|----------|--------------|--------------------|------------------------------------------------------|
| `client_ip`            | stringa  | no           | random             | Indirizzo IP del client                              |
| `client_port`          | intero   | no           | random > 10000     | Porta TCP del client                                 |
| `server_ip`            | stringa  | no           | random             | Indirizzo IP del server                              |
| `server_port`          | intero   | no           | random > 1000      | Porta TCP del server                                 |
| `enable_sack`          | booleano | no           | False              | Abilita/disabilita TCP SACK                          |
| `loss_prob_c2s`        | float    | **sì**       |                    | Probabilità di perdita pacchetti client → server     |
| `fast_retx`            | booleano | no           | False              | Abilita il fast retransmit                           |
| `mss`                  | intero   | **sì**       |                    | Maximum Segment Size (byte)                          |
| `app_bytes_to_send`    | intero   | no           | Uniforme(1kB-10kB) | Byte applicativi inviati dal client                  |
| `init_server_window`   | intero   | no           | 65535              | Dimensione iniziale della finestra TCP del server    |
| `app_read_rate_server` | intero   | **sì**       |                    | Velocità di lettura applicativa lato server (byte/s) |
| `rto_timer`            | float    | no           | 1 secondo          | RTO timer                                            |


---

### `HTTP_request_reply`

Simula uno scambio HTTP request/response sopra TCP, con possibilità di frammentazione IP.

#### Parametri supportati

| Parametro             | Tipo    | Obbligatorio | Default               | Descrizione                                 |
|-----------------------|---------|--------------|-----------------------|---------------------------------------------|
| `client_ip`           | stringa | no           | random                | Indirizzo IP del client                     |
| `client_port`         | intero  | no           | random > 10000        | Porta TCP del client                        |
| `server_ip`           | stringa | no           | random                | Indirizzo IP del server                     |
| `server_port`         | intero  | no           | {80, 443, 8080, 8443} | Porta TCP del server (es. 80, 8080)         |
| `mss`                 | intero  | **sì**       |                       | MSS TCP                                     |
| `ip_fragsize`         | intero  | **sì**       |                       | Dimensione massima dei frammenti IP         |
| `http_body_resp_size` | intero  | no           | Uniforme(1kB-10kB)    | Dimensione del body HTTP di risposta (byte) |

---
### Nota su `flows_to_generate`

Se `flows_to_generate > 1`:
* le **porte client** vengono estratte da un intervallo
* le **porte server** vengono estratte da un intervallo o lista, a seconda del generatore


## Esempi inclusi

Il file `exercise_specification.yaml` fornisce alcuni esempi pratici di utilizzo:

1. **TCP con fast retransmit senza SACK**
2. **TCP con fast retransmit e SACK, più flussi paralleli**
3. **HTTP request/response generico**
4. **HTTP request/response generico con frammentazione IP**

Questi esempi possono essere usati come base per creare nuovi scenari, modificando:
* IP e porte
* numero di flussi
* parametri TCP (perdita, MSS, finestra)
* dimensione dei contenuti applicativi

---

## Linee guida operative

* Utilizzare un `tag` univoco e descrittivo per ogni template
* Impostare `seed` per garantire risultati riproducibili
* Verificare la coerenza tra `mss` e `ip_fragsize`
* Usare `flows_to_generate` per generare più flussi paralleli tra client e server

---

## Estensione e personalizzazione

Il file può essere esteso aggiungendo nuovi `flow_template` alla lista `flow_list`, purché il `flow_generator` sia supportato dal sistema di generazione dei flussi.

