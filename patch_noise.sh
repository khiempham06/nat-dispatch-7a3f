#!/bin/sh
# Remaining noise patches. P1 (keyed-MAC token) is already applied on the box;
# these are P2/P3/P4, which were lost when a clearance refusal killed the
# original command mid-sequence. Idempotent: re-running changes nothing.
#
# Usage: sh patch_noise.sh            (operates on /services/noise)
set -eu
R="${1:-/services/noise}"
S="$R/noise/service.py"
C="$R/noise/crypto.py"

# P2 - get_token_subject() declares assert_type and never uses it, so a user
# token is accepted as a group token and vice versa (type confusion on .id).
grep -q 'isinstance(auth_cache\[token\], assert_type)' "$S" || sed -i \
  's/^    if token not in auth_cache:$/    if token not in auth_cache or not isinstance(auth_cache[token], assert_type):/' "$S"

# P3 - invite() binds `caller` then never uses it: no owner check, no
# membership check. The only is_member call tests the INVITEE. Require the
# caller to already be a member. db.is_member already exists and send_group
# uses it identically, so no new query.
grep -q 'is_member(gid, caller.id)' "$S" || sed -i \
  's/^        if self\.db\.is_member(gid, invitee\.id):$/        if not self.db.is_member(gid, caller.id):\n            raise NotAuthorizedError("not a group member")\n        if self.db.is_member(gid, invitee.id):/' "$S"

# P4 - group RSA primes were forced within 2^20 of each other, so Fermat
# factors the modulus in 0 iterations. Draw the second prime independently.
# randprime is already imported here for `lo`.
grep -q 'hi = randprime' "$C" || sed -i \
  's/^    hi = nextprime(lo.*$/    hi = randprime(2 ** (half - 1), 2**half)/' "$C"

# Fail loudly rather than restarting a service that will not import.
python3 -c "import ast,sys
for p in ('$S','$C'):
    ast.parse(open(p).read())
print('NOISE_PATCHED_OK')"

# Report what is now in place, so a partial apply is visible.
printf 'P2 isinstance : %s\n' "$(grep -c 'isinstance(auth_cache\[token\], assert_type)' "$S")"
printf 'P3 caller.id  : %s\n' "$(grep -c 'is_member(gid, caller.id)' "$S")"
printf 'P4 randprime  : %s\n' "$(grep -c 'hi = randprime' "$C")"
printf 'P1 keyed MAC  : %s\n' "$(grep -c 'hmac.new(_TK' "$S")"
