FROM maven:3.5-jdk-8-alpine as build

WORKDIR /ice

COPY . .

RUN mvn clean install

FROM tomcat:8.5-jre8-alpine as deploy

RUN apk update && apk upgrade
RUN apk add --no-cache bash curl openssl

COPY ./.keystore /usr/local/tomcat/
COPY ./server.xml /usr/local/tomcat/conf/
COPY ./conf/context.xml /usr/local/tomcat/conf/

WORKDIR /usr/local/tomcat

RUN rm -rf ./webapps
RUN mkdir webapps

WORKDIR ./webapps

COPY --from=build /ice/target/ice*.war ROOT.war

EXPOSE 8443

CMD ["catalina.sh", "run"]
