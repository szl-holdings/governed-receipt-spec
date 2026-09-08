# SPDX-License-Identifier: Apache-2.0
# linux/amd64; digest read back and checked against the official registry bytes.
FROM python:3.12.14-slim@sha256:2fe5997d249a808b8eeea52c58a1dbffbba28754dc11699ef5c029f2d818ce79
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY examples/public-single-cell/requirements-linux-cp312.lock /opt/example/requirements.lock
RUN python -m pip --isolated install --no-cache-dir --only-binary=:all: --require-hashes --index-url https://pypi.org/simple -r /opt/example/requirements.lock && python -m pip check
COPY verify.py /app/verify.py
COPY schema/governed-receipt.schema.json /app/schema/governed-receipt.schema.json
COPY examples/public-single-cell/run_example.py examples/public-single-cell/check_reproduction.py examples/public-single-cell/reproduction-profile.json examples/public-single-cell/requirements-linux-cp312.lock /app/examples/public-single-cell/
RUN python examples/public-single-cell/check_reproduction.py --environment --installed
ARG SOURCE_REVISION
RUN python -c "import os,re; assert re.fullmatch('[0-9a-f]{40}', os.environ.get('SOURCE_REVISION','')), 'exact source revision required'"
LABEL org.opencontainers.image.source="https://github.com/szl-holdings/governed-receipt-spec" org.opencontainers.image.revision="${SOURCE_REVISION}"
USER 65532:65532
ENTRYPOINT ["python", "examples/public-single-cell/run_example.py"]
