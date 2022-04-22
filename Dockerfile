FROM cccs/assemblyline-v4-service-base:stable

ENV SERVICE_PATH intezer_static.IntezerStatic

USER root

RUN apt-get update

USER assemblyline

# RUN pip install intezer-sdk
# Using fork temporarily while https://github.com/intezer/analyze-python-sdk/issues/35 and https://github.com/intezer/analyze-python-sdk/issues/39 are open
RUN pip install --no-cache-dir --user git+https://github.com/cccs-kevin/analyze-python-sdk && rm -rf ~/.cache/pip

WORKDIR /opt/al_service
COPY . .

ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

USER assemblyline
