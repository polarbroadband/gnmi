#FROM golang:1.15
FROM golang:1.13

#EXPOSE 35580

WORKDIR /appsrc/main
#CMD go run -mod=vendor .
CMD go run .
