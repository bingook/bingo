#!/bin/sh
set -eu

repo_root=$(git rev-parse --show-toplevel)
source_hook="$repo_root/scripts/git-hooks/post-commit"
hook_dir=$(git rev-parse --git-path hooks)
dest_hook="$hook_dir/post-commit"
backup_hook="$hook_dir/post-commit.bingo-existing"

mkdir -p "$hook_dir"

if [ -f "$dest_hook" ] && grep -q "bingo-change-memory-hook" "$dest_hook"; then
    echo "bingo change-memory hook is already installed"
    exit 0
fi

if [ -f "$dest_hook" ]; then
    mv "$dest_hook" "$backup_hook"
fi

cat > "$dest_hook" <<EOF
#!/bin/sh
# bingo-change-memory-hook

if [ -x "$backup_hook" ]; then
    "$backup_hook" "\$@" || exit \$?
fi

exec "$source_hook" "\$@"
EOF

chmod +x "$dest_hook" "$source_hook"
echo "installed: $dest_hook"
