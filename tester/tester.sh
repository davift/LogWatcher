#!/bin/bash
TARGET="192.168.1.101"
TIMEOUT=2

log() { echo -e "\n\033[1;36m[TEST]\033[0m $*"; }

log "1. Normal connect / immediate disconnect"
ssh -o ConnectTimeout=$TIMEOUT -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa "$TARGET" exit 2>/dev/null

log "2. Failed auth - root user"
ssh -o ConnectTimeout=$TIMEOUT -o StrictHostKeyChecking=no -o BatchMode=yes root@"$TARGET" exit 2>/dev/null

log "3. Failed auth - non-existent user 'ghost'"
ssh -o ConnectTimeout=$TIMEOUT -o StrictHostKeyChecking=no -o BatchMode=yes ghost@"$TARGET" exit 2>/dev/null

log "4. Failed auth - non-existent user 'admin'"
ssh -o ConnectTimeout=$TIMEOUT -o StrictHostKeyChecking=no -o BatchMode=yes admin@"$TARGET" exit 2>/dev/null

log "5. Wrong password - user 'ubuntu' (requires sshpass)"
sshpass -p "wrongpassword" ssh -o ConnectTimeout=$TIMEOUT -o StrictHostKeyChecking=no ubuntu@"$TARGET" exit 2>/dev/null

log "6. Brute-force burst - 5 rapid failed attempts"
for i in {1..5}; do
  ssh -o ConnectTimeout=$TIMEOUT -o StrictHostKeyChecking=no -o BatchMode=yes bruteuser@"$TARGET" exit 2>/dev/null &
done
wait

log "19. Credential stuffing - rotating usernames"
for user in oracle mysql postgres www-data nobody daemon bin sys; do
  ssh -o ConnectTimeout=$TIMEOUT -o StrictHostKeyChecking=no -o BatchMode=yes "${user}@${TARGET}" exit 2>/dev/null &
done
wait

log "8. Malformed username (very long string)"
LONGUSER=$(python3 -c "print('a'*100)")
ssh -o ConnectTimeout=$TIMEOUT -o StrictHostKeyChecking=no -o BatchMode=yes "${LONGUSER}@${TARGET}" exit 2>/dev/null

log "9. Malformed username (special characters)"
ssh -o ConnectTimeout=$TIMEOUT -o StrictHostKeyChecking=no -o BatchMode=yes "'; DROP TABLE users;--@${TARGET}" exit 2>/dev/null

log "10. Wrong private key attempt"
TMPKEY='tester.key'
ssh -o ConnectTimeout=$TIMEOUT -o StrictHostKeyChecking=no -o BatchMode=yes -i "$TMPKEY" testuser@"$TARGET" exit 2>/dev/null

log "11. X11 forwarding request"
ssh -o ConnectTimeout=$TIMEOUT -o StrictHostKeyChecking=no -o BatchMode=yes -X testuser@"$TARGET" exit 2>/dev/null

log "12. Agent forwarding request"
ssh -o ConnectTimeout=$TIMEOUT -o StrictHostKeyChecking=no -o BatchMode=yes -A testuser@"$TARGET" exit 2>/dev/null

log "13. Local port-forward tunnel attempt (lateral movement)"
ssh -o ConnectTimeout=$TIMEOUT -o StrictHostKeyChecking=no -o BatchMode=yes -L 8080:localhost:80 testuser@"$TARGET" exit 2>/dev/null

log "14. Remote port-forward / reverse tunnel attempt"
ssh -o ConnectTimeout=$TIMEOUT -o StrictHostKeyChecking=no -o BatchMode=yes -R 9090:localhost:9090 testuser@"$TARGET" exit 2>/dev/null

log "15. Remote command execution attempt"
ssh -o ConnectTimeout=$TIMEOUT -o StrictHostKeyChecking=no -o BatchMode=yes testuser@"$TARGET" "id; whoami; cat /etc/passwd" 2>/dev/null

log "16. SFTP access attempt"
sftp -o ConnectTimeout=$TIMEOUT -o StrictHostKeyChecking=no -o BatchMode=yes testuser@"$TARGET" <<< "ls" 2>/dev/null

log "17. SCP download attempt (data exfiltration pattern)"
TMPFILE=$(mktemp)
scp -o ConnectTimeout=$TIMEOUT -o StrictHostKeyChecking=no -o BatchMode=yes testuser@"${TARGET}:/etc/passwd" "$TMPFILE" 2>/dev/null
rm -f "$TMPFILE"

log "18. Login from low-numbered source port (unusual client)"
sudo ssh -o ConnectTimeout=$TIMEOUT -o StrictHostKeyChecking=no -o BatchMode=yes -b 0.0.0.0 testuser@"$TARGET" exit 2>/dev/null

