FROM gradle:7.3.3

WORKDIR /sd-jwt
COPY . .

CMD ./gradlew test -i
