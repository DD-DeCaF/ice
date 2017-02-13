FROM tomcat:8.5-jre8-alpine

RUN apk update && apk upgrade
RUN apk add --no-cache bash curl openssl

COPY ./.keystore /usr/local/tomcat/
COPY ./server.xml /usr/local/tomcat/conf/

WORKDIR /usr/local/tomcat

RUN rm -rf ./webapps
RUN mkdir webapps

WORKDIR ./webapps

RUN curl -s https://api.github.com/repos/dd-decaf/ice/releases/latest | grep browser_download_url | head -n 1 | cut -d '"' -f 4 > download_url
RUN cat download_url | xargs -n 1 curl -O -L

RUN mv ice*.war ROOT.war
RUN rm download_url

EXPOSE 8443

CMD ["catalina.sh", "run"]