mvn package
if [ $1 != "" ];
then
    java -cp target/crypto-mailer-server-1.0-SNAPSHOT.jar $1;
else
    java -jar target/crypto-mailer-server-1.0-SNAPSHOT.jar;
fi