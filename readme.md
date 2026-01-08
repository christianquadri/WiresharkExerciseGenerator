# WiresharkExerciseGenerator

Questo repository fornisce un generatore di traffico/esercizi (TCP e HTTP) pensato per essere analizzato con **Wireshark**. 
Il generatore utilizza file di configurazione YAML per descrivere in modo riproducibile i flussi di pacchetti da creare.

---

## Prerequisiti

* **Python 3.10+** (supporto f-string)
* **pip**
* (Consigliato) **virtualenv / venv**
* **Wireshark** installato per analizzare i file di cattura generati

---

## Installazione

### 1. Clonare la repository

```bash
git clone https://github.com/christianquadri/WiresharkExerciseGenerator.git
cd WiresharkExerciseGenerator
```

### 2. Creare e attivare un ambiente virtuale (consigliato per evitare conflitti con le dipendenze globali)

Le seguenti istruzioni craano un ambiente virtuale Python nella directory `.venv` all'interno del progetto e lo attivano.

Linux / macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows (PowerShell):

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Installare le dipendenze

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

---

## Esecuzione di `main_generator`

Il generatore va eseguito **come modulo Python** dal root della repository, così da garantire la corretta risoluzione degli import.

```bash
python -m wireshark_exercise_generator.main_generator --help
```

### Esecuzione tipica

```bash
python -m wireshark_exercise_generator.main_generator \
  -f ./examples/exercise_specification.yaml \
  -o exercise1
```

Dove:

* `-f | --flow-spec-file` è il file YAML che descrive i flussi di traffico da generare
* `-o | --out-filename` indica il prefisso dei file generati (es. `exercise1.pcap` e `exercise1_solution.txt`)

---

## File di configurazione YAML

Il file di configurazione definisce:

* un **`seed`** per garantire la riproducibilità dei flussi generati
* una **`flow_list`** composta da uno o più `flow_template`

Ogni `flow_template` specifica:

* il tipo di generatore (`flow_generator`, es. `TCP_client_server`, `HTTP_request_reply`)
* il numero di flussi (`flows_to_generate`)
* i parametri di rete e applicativi (`flow_parameters`)

Per la descrizione dettagliata dei file di configurazione, vedere [README degli esempi](examples/README.md)

---

## Output e analisi

Il generatore crea due file:
- un file `out/pcap_output/<filename_prefix>.pcap` con i flussi generati
- un file `out/solutions/<filename_prefix>_solutions.txt` con la soluzione dei flussi generati

I file generati `.pcap` possono essere aperti direttamente con **Wireshark** per:

* analisi TCP (ritrasmissioni, SACK, finestre, perdita)
* analisi HTTP request/response
* studio della frammentazione IP

I file di soluzione `.txt` contengono le soluzioni delle analisi dei flussi.

---

## Struttura della repository

```text
WiresharkExerciseGenerator/
├── wireshark_exercise_generator/   # Package Python principale
│   └── main_generator.py           # Entry point del generatore
├── examples/                       
    └── exercise_specification.yaml # Esempio di configurazione
    └── README.md                   # Documentazione per generare altri flussi
├── requirements.txt                # Dipendenze Python
└── README.md
```

---

## Troubleshooting

* **ModuleNotFoundError**: assicurarsi di eseguire i comandi dal root della repo e usando `python -m`.
* **Dipendenze mancanti**: verificare che l’ambiente virtuale sia attivo e che `requirements.txt` sia stato installato.
* **Permessi Wireshark**: per catture live su Linux potrebbero essere necessari permessi aggiuntivi (capabilities).

