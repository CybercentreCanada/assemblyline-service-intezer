FROM cccs/assemblyline-v4-service-base:stable

ENV SERVICE_PATH intezer.Intezer

USER root

RUN apt-get update

USER assemblyline

RUN pip install intezer-sdk && rm -rf ~/.cache/pip

WORKDIR /opt/al_service
COPY . .

ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

USER assemblyline
