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


---

## Komma igång

### Sätta upp en Python-miljö och installera nödvändiga Python-paket

Skapa en Python-miljö.  
De paket som används i projektet är specificerade i `requirements.txt`.  
Installera nödvändiga paket med kommandot:  
```
pip install -r requirements.txt
```

---

## REST API

Interaktion med REST API:et kan ske med nedanstående endpoints.


### Users ("/api/auth")
Registrera och logga in användare
````json
{
   "username": "{4-16 characters}",
   "password": "{4-16 characters}"
}
````

| Kommando | Operation            | Endpoint    | Restrictions    | Returnerar  |
|----------|----------------------|-------------|-----------------|-------------|
| POST     | Registrera användare | `/register` | 4-16 characters |             |
| POST     | Logga in användare   | `/login`    |                 | `JWT Token` |


### Förutsägelse ("/api/prediction")
Syntax för att begära en ny förutsägelse. 
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
| Kommando | Operation                                       | Endpoint | Begränsningar   | Returnerar          |
|----------|-------------------------------------------------|----------|-----------------|---------------------|
| POST     | Begär ny förutsägelse                           |          | JWT Token krävs | Prediction som JSON |
| GET      | Hämta alla förutsägelser för inloggad användare |          | JWT Token krävs | ``                  |

---

## Abilities used for this assignment
### Technical
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
- Dokumentation
- Jetbrains PyCharm
- Postman

### Soft
- Problemlösning
- Analytisk förmåga
- Struktur