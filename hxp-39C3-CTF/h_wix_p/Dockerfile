FROM debian:trixie-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3-minimal \
    qemu-system-x86 && \
    rm -rf /var/lib/apt/lists

RUN useradd --create-home --shell /bin/bash ctf

ADD [f]lag.txt FiwixOS-3.5-i386.raw /root/
WORKDIR /root


RUN if [ -f flag.txt ]; then \
    python3 -c 'dummy = b"hxp{dummy-flag.................................................}"; \
    flag = open("flag.txt", "rb").read().strip().ljust(len(dummy), b" "); \
    assert len(dummy) == len(flag), "invalid flag length"; \
    f = open("FiwixOS-3.5-i386.raw", "r+b"); \
    d = f.read(); \
    assert d.count(dummy) == 1, "More or less than 1 flag found"; \
    d = d.replace(dummy, flag); \
    f.seek(0); f.write(d); f.close(); \
    '; \
    fi
RUN mv FiwixOS-3.5-i386.raw /home/ctf && rm -rf /root/*

COPY ynetd /sbin/
COPY run.sh fiwix /home/ctf/

RUN chmod 555 /home/ctf && \
    chown -R root:root /home/ctf && \
    chmod -R 000 /home/ctf/* && \
    chmod 500 /sbin/ynetd && \
    chmod 004 /home/ctf/fiwix /home/ctf/FiwixOS-3.5-i386.raw && \
    chmod 005 /home/ctf/run.sh

RUN ynetd -v

RUN find / -ignore_readdir_race -path /sys -prune -o -type f \( -perm -4000 -o -perm -2000 \) -not -wholename /readflag -exec rm {} \;
USER ctf
RUN ! find / -writable -or -user $(id -un) -or -group $(id -Gn|sed -e 's/ / -or -group /g') 2> /dev/null | grep -Ev -m 1 '^(/dev/|/run/|/proc/|/sys/|/tmp|/var/tmp|/var/lock)'
USER root


WORKDIR /home/ctf
EXPOSE 1024
CMD /sbin/ynetd -pow 30 -lm 2147483648 -lt 30 -t 300 -sh n /home/ctf/run.sh
