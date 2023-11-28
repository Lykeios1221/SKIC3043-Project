# SKIC3043 Project

## Installation

To install the packages required run the following command:

```
pip install -r requirement.txt
```

## Setup Project

To setup the database, follows the below structure:

<img style="background-color: white" src="C:\Users\derri\OneDrive - UNIVERSITY UTARA MALAYSIA\Documents\UUM\Semester 5\SKIC3043 SECURE SOFTWARE DEVELOPMENT\Project\SKIC3043 Project\database.svg"/>

Or simply import the [secure_software.sql](secure_software.sql)

**_NOTE:_** The app config for database url should be changed according to your own database as follows:

```python
app.config['SQLALCHEMY_DATABASE_URI'] = 'dialect+driver://username:password@host:port/database'
```

## Run
To run it locally, please install [xampp](https://www.apachefriends.org/) and start Apache and MySQL server   

**_NOTE:_** Only the [main.py](main.py) file should be run