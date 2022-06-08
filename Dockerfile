FROM gradle:7.3.3

WORKDIR /sd-jwt
COPY . .

RUN gradle build

CMD java -jar build/libs/sd-jwt-kotlin-1.0-SNAPSHOT.jar
