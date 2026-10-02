# keyvault

本地密钥保管库（Go + SQLite）。每把密钥一个 UUID + 32 字节随机材料，
材料用主密钥做 AES-256-GCM 加密后存库；主密钥由口令经
PBKDF2-SHA256（600000 次迭代）派生，口令不落盘。

## API

- `Open(path, passphrase)` — 打开（或创建）库；口令错误返回 `ErrBadPassphrase`。
- `CreateKey() (string, error)` — 生成新密钥，返回 UUID。
- `GetMaterial(id) ([]byte, error)` — 返回明文材料。
- `DestroyKey(id) error` — 永久销毁。
- `RotateMaster(newPassphrase) error` — 主密钥轮换。

## 轮换设计

1. **Meta 切换（单个小事务）**：写入新 salt、新口令校验值、epoch+1、
   `state=rotating`，以及 escrow——旧主密钥用**新**主密钥加密后的瞬态
   副本。从事务提交起旧口令即失效。
2. **分批重加密**：每批 500 行一个事务，把旧 epoch 的材料密文用旧主密钥
   解密、用新主密钥重新加密。批间不持锁，`CreateKey`/`GetMaterial`/
   `DestroyKey` 照常并发，单次最多被阻塞一个批次；新建密钥直接写新
   epoch。不按固定游标，而是反复 `SELECT ... WHERE epoch=old LIMIT 500`，
   天然处理轮换期间的新增与删除。
3. **Finalize（单个小事务）**：`state=normal`，删除 escrow，内存中擦除
   旧主密钥。此后库里不存在旧主密钥的任何形式。

## 崩溃恢复

轮换期间被 kill -9 后：

- 若 meta 切换未提交：库完全处于旧口令状态，旧口令可开。
- 若已提交：新口令可开。`Open` 发现 `state=rotating` 时，用新口令派生
  新主密钥、解开 escrow 得到旧主密钥，**续跑**剩余批次并 finalize 后才
  返回。旧口令从 meta 提交起即失效。

因此调用方先新后旧尝试，恰好一个口令有效，且 `Open` 返回后所有存活
密钥可读、字节正确。

## 安全论证

攻击者在轮换开始前拿到进程内存中的全部密钥字节（旧主密钥；本设计无
中间层密钥）。轮换后：所有材料密文均已换成新主密钥加密；escrow 是新
主密钥加密旧主密钥，攻击者没有新口令派生不出新主密钥，解不开；
escrow 与旧校验值在 finalize 时被删除/覆盖。轮换期间新建的密钥直接
用新主密钥加密。

## 测试

```sh
go test ./...
```

- `TestConcurrentRotate`：预置 10 万把密钥，轮换期间多 goroutine 并发
  增删读；任何一次对存活密钥的读取失败或字节不符即失败。轮换后用轮换
  前截获的主密钥逐条试解库里全部密文（含 meta），并校验当前密钥解出的
  明文不等于任何已销毁密钥的材料。
- `TestCrashRecovery`：子进程跑 `RotateMaster`，在提交前 / 批次中 /
  完成后等随机时刻被 kill -9，多轮链式重复（恢复后紧接着再轮换再杀）。
  每轮按先新后旧顺序 Open，逐字节校验全部存活密钥，并验证另一口令失效。
