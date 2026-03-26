# StablePay X Verify Mock (CloudWeGo / Hertz)

一个可直接联调的最小版 X 验证服务，目标：

- `POST /verify-twitter`
- 支持 `x.com` / `twitter.com`
- 校验 DID 格式
- 校验 DID 是否存在
- 校验同一 X 账号只能绑定一个 DID
- 校验同一 DID 只能绑定一个 X 账号
- mock 注册奖励发放
- 提供 mock tweet 写入接口，方便前端/插件联调

## API

### 1) 创建 mock DID

```bash
curl -X POST http://127.0.0.1:8080/api/v1/mock/dids \
  -H 'Content-Type: application/json' \
  -d '{
    "did": "did:solana:4fK9x2HyJkMock1111111111111111111111111",
    "wallet_address": "4fK9x2HyJkMock1111111111111111111111111"
  }'
```

### 2) 写入 mock tweet

```bash
curl -X POST http://127.0.0.1:8080/api/v1/mock/twitter/tweets \
  -H 'Content-Type: application/json' \
  -d '{
    "tweet_url": "https://x.com/alice/status/123456789",
    "author_handle": "alice",
    "text": "I am verifying my StablePay DID: did:solana:4fK9x2HyJkMock1111111111111111111111111",
    "is_public": true
  }'
```

### 3) 调用验证接口

```bash
curl -X POST http://127.0.0.1:8080/verify-twitter \
  -H 'Content-Type: application/json' \
  -d '{
    "did": "did:solana:4fK9x2HyJkMock1111111111111111111111111",
    "tweet_url": "https://x.com/alice/status/123456789"
  }'
```

### 4) 查询验证状态

```bash
curl "http://127.0.0.1:8080/verify?did=did:solana:4fK9x2HyJkMock1111111111111111111111111"
```

## 说明

这版是 mock，不会真的请求 X API，也不会真的打 Solana。
验证逻辑是从内存中的 mock tweet 表读取 tweet，然后检查：

1. tweet 是否存在
2. tweet 是否公开
3. tweet 文本是否包含对应 DID
4. X 账号是否已绑定其他 DID
5. DID 是否已绑定其他 X 账号

奖励发放也是 mock：只生成一个 `reward_tx`，并把余额加 1 USDC。
