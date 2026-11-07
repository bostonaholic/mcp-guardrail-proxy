# Turns TLC's `-dump dot,actionlabels` output into the graph format of specs/graphs:
#   init <state>
#   edge <state> | <action> | <state>
# A state lists its variables as name=value. TLC's fingerprints differ from run to run, so
# they stay out, and the caller sorts the lines to get a file that diffs cleanly.
function state_text(label,    parts, count, i, pair, text) {
  count = split(label, parts, /\\n/)
  text = ""
  for (i = 1; i <= count; i++) {
    pair = parts[i]
    sub(/^\/\\\\ /, "", pair)
    sub(/ = /, "=", pair)
    gsub(/\\"/, "", pair)
    text = text (i > 1 ? " " : "") pair
  }
  return text
}

/^-?[0-9]+ -> -?[0-9]+ \[label="/ {
  edges++
  from[edges] = $1
  to[edges] = $3
  action = $0
  sub(/^[^"]*"/, "", action)
  sub(/".*$/, "", action)
  name[edges] = action
  next
}

/^-?[0-9]+ \[label="/ {
  id = $1
  label = $0
  sub(/^[^"]*"/, "", label)
  sub(/"(,style = filled)?\]?;?$/, "", label)
  sub(/",style = filled\]$/, "", label)
  sub(/"\];?$/, "", label)
  states[id] = state_text(label)
  if ($0 ~ /style = filled/) {
    initial[id] = 1
  }
}

END {
  for (id in initial) {
    print "init " states[id]
  }
  for (i = 1; i <= edges; i++) {
    print "edge " states[from[i]] " | " name[i] " | " states[to[i]]
  }
}
