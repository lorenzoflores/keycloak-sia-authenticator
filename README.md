# Keycloak SIA Authenticator

*Keycloak SIA Authenticator* es una extensión para el IAM Keycloak que añade un nuevo authenticator a la plataforma para validarse contra la plataforma en la nube de SIA. 

- [1. Preparación del entorno ⚙️](#1.-preparación-del-entorno-⚙️)
- [2. Comenzando 🚀](#2.-comenzando-🚀)
- [3. Deployment 📦](#3.-deployment-📦)

## 1. Preparación del entorno ⚙️

Prerequisitos:
* java JDK20
* maven 3.6+,
* git  

## 2. Comenzando 🚀

Estas instrucciones te permitirán obtener una copia del proyecto en funcionamiento en tu máquina local para propósitos de desarrollo y pruebas.
 * Importar como proyecto Maven el proyecto clonado (recomendamos en el workspace del IDE con el que trabajemos).
 

## 3. Deployment 📦

Para generar el jar ejecutar el siguiente comando Maven:

 ```bash
   $ mvn clean package shade:shade
   ```

Posteriormente situar el jar obtenido en el directorio *providers* del directorio donde se encuentre instalado el servidor Keycloak.

Este proyecto ha sido realizado por Lorenzo Flores Sánchez como parte del Trabajo Fin de Grado (TFG) del CURSO DE ADAPTACIÓN AL GRADO EN INGENIERÍA INFORMÁTICA de la Universidad Internacional de La Rioja (UNIR).
