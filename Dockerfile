FROM python:3.12-slim

ENV VIRTUAL_ENV=/home/tea/.teaenv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

ARG USER_ID=1000
ARG GROUP_ID=1000

#RUN useradd -ms /bin/bash tea
RUN groupadd --gid $GROUP_ID tea && \
    useradd --uid $USER_ID --gid $GROUP_ID --no-create-home  --shell /bin/bash tea && \
    echo "tea:tea" | chpasswd

USER tea
WORKDIR /home/tea/app

COPY --chown=tea:tea . .

RUN python3 -m venv $VIRTUAL_ENV && \
    pip install --upgrade pip && \
    pip install -r requirements.txt