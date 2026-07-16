FROM python:3.13-slim-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends equivs \
    && equivs-control libgl1-mesa-dri \
    && printf 'Section: misc\nPriority: optional\nStandards-Version: 3.9.2\nPackage: libgl1-mesa-dri\nVersion: 99.0.0\nDescription: Dummy package for libgl1-mesa-dri\n' >> libgl1-mesa-dri \
    && equivs-build libgl1-mesa-dri \
    && mv libgl1-mesa-dri_*.deb /libgl1-mesa-dri.deb \
    && equivs-control adwaita-icon-theme \
    && printf 'Section: misc\nPriority: optional\nStandards-Version: 3.9.2\nPackage: adwaita-icon-theme\nVersion: 99.0.0\nDescription: Dummy package for adwaita-icon-theme\n' >> adwaita-icon-theme \
    && equivs-build adwaita-icon-theme \
    && mv adwaita-icon-theme_*.deb /adwaita-icon-theme.deb

FROM python:3.13-slim-bookworm

COPY --from=builder /*.deb /

WORKDIR /app

# Pin Chromium to 149 (matches working instances). Debian's live apt now ships
# Chromium 150, which crashes at launch ("chrome not reachable") with this
# FlareSolverr/undetected-chromedriver build. We freeze apt to Debian snapshots
# where 149.0.7827.196 is the newest Chromium available, so 150 can't be pulled.
ARG CHROMIUM_VERSION=149.0.7827.196-1~deb12u1

RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* \
    && printf 'Types: deb\nURIs: http://snapshot.debian.org/archive/debian/20260628T143645Z/\nSuites: bookworm bookworm-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n\nTypes: deb\nURIs: http://snapshot.debian.org/archive/debian-security/20260626T014759Z/\nSuites: bookworm-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n' > /etc/apt/sources.list.d/debian.sources \
    && printf 'Acquire::Check-Valid-Until "false";\nAcquire::Retries "6";\n' > /etc/apt/apt.conf.d/99snapshot \
    && dpkg -i /libgl1-mesa-dri.deb \
    && dpkg -i /adwaita-icon-theme.deb \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        chromium=${CHROMIUM_VERSION} chromium-common=${CHROMIUM_VERSION} chromium-driver=${CHROMIUM_VERSION} \
        xvfb dumb-init procps curl xauth \
    && apt-mark hold chromium chromium-common chromium-driver \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /usr/lib/x86_64-linux-gnu/libmfxhw* \
    && rm -f /usr/lib/x86_64-linux-gnu/mfx/* \
    && mv /usr/bin/chromedriver /app/chromedriver || true

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir -p "/root/.config/chromium/Crash Reports/pending"

COPY src/ .
COPY package.json ../

EXPOSE 8191

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["python", "-u", "/app/flaresolverr.py"]
