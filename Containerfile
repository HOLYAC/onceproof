FROM python:3.13-slim AS build

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip install --no-cache-dir build && python -m build --wheel

FROM python:3.13-slim

RUN useradd --create-home --uid 10001 onceproof
COPY --from=build /build/dist/*.whl /tmp/onceproof.whl
RUN python -m pip install --no-cache-dir /tmp/onceproof.whl && rm /tmp/onceproof.whl
COPY scripts/container-entrypoint.sh /usr/local/bin/onceproof-container
RUN chmod 0555 /usr/local/bin/onceproof-container
RUN mkdir -p /var/lib/onceproof && chown onceproof:onceproof /var/lib/onceproof

USER onceproof
WORKDIR /var/lib/onceproof
EXPOSE 8787
STOPSIGNAL SIGTERM
VOLUME ["/var/lib/onceproof"]
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('ONCEPROOF_PORT','8787')+'/readyz', timeout=2).read()"

ENTRYPOINT ["/usr/local/bin/onceproof-container"]
CMD ["serve"]
