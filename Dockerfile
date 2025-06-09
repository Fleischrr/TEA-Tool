FROM python:3.12-slim

ARG USER_ID=1000
ARG GROUP_ID=1000

RUN groupadd --gid $GROUP_ID tea && \
    useradd --uid $USER_ID --gid $GROUP_ID  --shell /bin/bash tea && \
    echo "tea:tea" | chpasswd

USER tea
WORKDIR /home/tea/app

COPY --chown=tea:tea . .

RUN echo "python ~/app/tea_tool.py" >> ~/.bashrc

RUN python3 && \
    pip install --upgrade pip && \
    pip install -r requirements.txt
