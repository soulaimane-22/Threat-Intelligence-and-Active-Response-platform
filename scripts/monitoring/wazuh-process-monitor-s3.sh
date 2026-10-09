#!/usr/bin/env bash

for pid in $(pgrep -f '(^|/)(ncat|nc)( |$)' 2>/dev/null); do

    [ -r "/proc/$pid/cmdline" ] || continue

    cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
    cmd=$(echo "$cmd" | sed 's/[[:space:]]*$//')

    # Seulement les processus en mode écoute
    if ! echo " $cmd " | grep -Eq ' (-l|--listen)( |$)'; then
        continue
    fi

    exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
    [ -n "$exe" ] || continue

    user=$(ps -o user= -p "$pid" 2>/dev/null | xargs)

    sha256=$(sha256sum "$exe" 2>/dev/null | awk '{print $1}')

    printf 'SUSPICIOUS_PROCESS pid=%s user=%s exe=%s sha256=%s cmd="%s"\n' \
        "$pid" "$user" "$exe" "$sha256" "$cmd"
done

exit 0
