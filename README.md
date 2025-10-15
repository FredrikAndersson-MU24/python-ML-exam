# Python och maskininlärning individuell examination

## Uppgiftsbeskrivning
### Maskininlärningsprojekt från Data till Web-API

Uppgiften består av fyra huvudsakliga faser:
1.  Datainsamling och Urval: Välj ett relevant, intressant och publikt tillgängligt dataset.
2.  Explorativ Dataanalys (EDA) och Förbehandling: Utför en djupgående EDA och förbered datan för modellering.
3.  Modellträning och Utvärdering: Träna en maskininlärningsmodell på din data, utvärdera den och spara den tränade modellen.
4.  API-utveckling: Skapa ett enkelt RESTful webb-API i Python som använder den sparade modellen för att göra prediktioner.
---

## Projektbeskrivning
Projektet började med en Jupyter Lab Notebook där ett dataset valdes för att bygga en klassificeringsmodell med 
syfte att kunna klassificera om personer bedöms ha risk för att utveckla diabetes. Tre olika klassificeringsmodeller har
tränats, optimerats och utvärderats för att finna den enligt mig mest lämpliga, där fokus har varit att så långt som 
möjligt hitta personer i riskzon utan att behöva kompromissa för mycket med precisionen. Modellen har sedan exporterats 
för att kunna användas i ett REST API utvecklat i Python med Flask.
Nedan följer en beskrivning av REST API:et. Läs mer om valt dataset och modeller i [Jupyter Lab Notebook](/notebook/diabetes.ipynb).


---

## Komma igång

### Sätta upp en Python-miljö och installera nödvändiga Python-paket

Klona projektet.  
Sätt upp en Python-miljö.  
De paket som krävs för projektet finns i `requirements.txt`.  
Installera nödvändiga paket med kommandot  
```
pip install -r requirements.txt
```

---

## REST API

Begäran om nya förutsägelser kräver JWT Token, vilket innebär att användaren måste vara registrerad och
inloggad för att kunna nå respektive endpoint.
Interaktion med REST API:et sker med nedanstående endpoints.


### Autentisering ("/api/auth")
Registrera och logga in användare.
````json
{
   "username": "{8-32 characters}",
   "password": "{8-32 characters}"
}
````

| Kommando | Operation            | Endpoint    | Begränsningar           | Returnerar  |
|----------|----------------------|-------------|-------------------------|-------------|
| POST     | Registrera användare | `/register` | 8-32 tecken, unikt      |             |
| POST     | Logga in användare   | `/login`    | 8-32 tecken, teckenkrav | `JWT Token` |


### Förutsägelse ("/api/predict")
Syntax för att begära en ny klassificering. 
````json
{   "gen_hlth": {1-5}, 
    "high_bp": {0/1},
    "bmi": {20-100},
    "high_chol": {0/1},
    "age": {1-13},
    "diff_walk": {0/1},
    "phys_hlth": {0-30},
    "heart_disease_or_attack": {0/1},
    "phys_activity": {0/1},
    "education": {1-6},
    "income": {1-8}
    }
````
| Kommando | Operation                | Endpoint | Begränsningar   | Returnerar                         |
|----------|--------------------------|----------|-----------------|------------------------------------|
| POST     | Begär ny förutsägelse    |          | JWT Token krävs | Klassificering som JSON            |
| GET      | Hämta alla förutsägelser |          | JWT Token krävs | Lista av klassificeringar som JSON |

---

## Reflektion

Projektet gav mig möjlighet att kombinera teknisk problemlösning med analytiskt tänkande för att optimera
maskininlärningsmodeller och förbättra deras prestanda samt implementera modeller i ett REST API. Det gav mig insikter i
min förmåga att analysera problem och statistiska samband samt vikten av att kunna ta ett steg tillbaka för att sedan
ta sig an problemet från ett annat perspektiv och med ny energi.

### Tekniska färdigheter
- Python 
   - Flask
- Jupyter Lab
  - Numpy
  - Matplotlib
  - Pandas
  - Seaborn
  - Scikit-learn
    - Modellträning
    - Modellutvärdering
- Git
- GitHub
- Jetbrains PyCharm
- Postman

### Mjuka färdigheter
- Problemlösning
- Analytiskt tänkande
- Struktur
- Presentation