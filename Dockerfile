FROM debian:11-slim

RUN apt update && apt install -y openjdk-17-jdk

WORKDIR /sd-jwt
COPY . .

CMD ./gradlew test --tests SdJwtKtTest -i -PossrhUsername= -PossrhPassword=
