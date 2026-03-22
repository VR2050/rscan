# 登录逻辑逆向报告（静态取证）

## 1. 样本信息
- APK: `/home/vr2050/RUST/rscan_codex/违法apk/20260310-1138010.apk`
- SHA256: `648ffc31a4b13a74d49e6bc1456c215f43d52097526da2d6b6a7fa6102787229`
- 反编译目录: `/home/vr2050/RUST/rscan_codex/analysis/newapp_jadx`
- 分析日期: `2026-03-11`

## 2. 结论摘要
- 该样本存在多条登录入口，核心在 `SignViewModel` 与 `MineViewModel`/`PhoneViewModel`。
- 登录成功后会把 `TokenBean` 写入 `SharedPreferences(default_storage)` 的 `USER_TOKEN`。
- 后续业务请求统一封装为 `BaseRequestBody{deviceId, token, data}`，并进行 AES/ECB 加密后发送。
- 当响应出现 `errorCode=2002` 时，拦截器会静默发起 `user/login` 刷新 token 并重试原请求。

## 3. 登录入口与触发关系

### 3.1 账号密码登录（LoginActivity -> SignViewModel）
1. `act_login_input` 页面双向绑定账号/密码输入到 `SignViewModel.phoneData/pwdData`。
2. 点击登录按钮触发 `SignViewModel.refreshAccount(context)`。
3. `refreshAccount` 调用接口 `user/findByAccount(account_name, account_password, type, code)`。
4. 返回 `TokenBean` 后先落库，再请求 `user/info` 拉取用户资料。
5. `MyApp.userInfo` 更新后提示“登录成功”并结束页面。

关键定位:
- 登录按钮回调到 `refreshAccount`:  
  `ActLoginInputBindingImpl._internalCallbackOnClick(1)`  
  `/sources/com/jbzd/media/movecartoons/databinding/ActLoginInputBindingImpl.java:112-117`
- 账号密码接口调用:  
  `/sources/com/jbzd/media/movecartoons/p396ui/settings/SignViewModel.java:91`
- token 先落库再拉 `user/info`:  
  `/sources/com/jbzd/media/movecartoons/p396ui/settings/SignViewModel$refreshAccount$1.java:56-60`

### 3.2 注册复用同一认证接口（RegisterActivity -> SignViewModel）
1. 注册页同样绑定手机号/密码/邀请码到 `SignViewModel`。
2. 点击注册按钮依旧触发 `refreshAccount(context)`。
3. `type` 由页面类型判定：`LoginActivity` 为 `login`，否则 `register`。
4. 同一接口 `user/findByAccount(...)` 通过 `type` 区分登录/注册语义。

关键定位:
- 注册按钮触发 `refreshAccount`:  
  `/sources/com/jbzd/media/movecartoons/databinding/ActRegisterInputBindingImpl.java:133-138`
- `type = login/register` 判定:  
  `/sources/com/jbzd/media/movecartoons/p396ui/settings/SignViewModel.java:85`

### 3.3 手机验证码登录/绑定（PhoneViewModel 与 MineViewModel）
1. 获取图形验证码: `system/captcha`，取 `base64` 图片内容展示。
2. 提交手机号+短信码:
   - `isBinding=false` -> `user/findByPhone(phone, code)`（手机号登录）
   - `isBinding=true` -> `user/bindPhone(phone, code)`（绑定手机）
3. 登录路径返回 `TokenBean` 后直接 `MyApp.m4188i(...)` 落库。

关键定位:
- 图形验证码获取:  
  `/sources/com/jbzd/media/movecartoons/p396ui/settings/PhoneViewModel.java:166-183`
- 手机登录/绑定分支:  
  `/sources/com/jbzd/media/movecartoons/p396ui/settings/PhoneViewModel.java:217-265`
- MineViewModel 的手机号登录实现:  
  `/sources/com/jbzd/media/movecartoons/p396ui/mine/MineViewModel.java:538-580`

### 3.4 卡密/二维码登录（MineViewModel）
1. 入口方法: `loginByCard(code)`。
2. 调用 `user/findQrcode(code)`，返回 `TokenBean`。
3. token 落库并设置 `loginCardSuccess=true`。

关键定位:
- `/sources/com/jbzd/media/movecartoons/p396ui/mine/MineViewModel.java:789-831`

## 4. 登录接口与参数矩阵

### 4.1 Retrofit 声明接口（InterfaceC0921e）
- `user/findByAccount`  
  参数: `account_name`, `account_password`, `type`, `code`  
  `/sources/p005b/p006a/p007a/p008a/p017r/InterfaceC0921e.java:96-99`
- `user/findByPhone`  
  参数: `phone`, `code`  
  `/sources/p005b/p006a/p007a/p008a/p017r/InterfaceC0921e.java:102-105`
- `user/findQrcode`  
  参数: `code`  
  `/sources/p005b/p006a/p007a/p008a/p017r/InterfaceC0921e.java:159-162`
- `user/bindPhone`  
  参数: `phone`, `code`  
  `/sources/p005b/p006a/p007a/p008a/p017r/InterfaceC0921e.java:177-180`
- `system/captcha`  
  参数: 无  
  `/sources/p005b/p006a/p007a/p008a/p017r/InterfaceC0921e.java:67-70`
- `user/info`  
  参数: 无  
  `/sources/p005b/p006a/p007a/p008a/p017r/InterfaceC0921e.java:51-54`

### 4.2 动态字符串路由调用（MineViewModel）
- `system/sendSms(phone, captcha, token)`  
  `/sources/com/jbzd/media/movecartoons/p396ui/mine/MineViewModel.java:942-950`

## 5. Token 生命周期与存储

### 5.1 Token 结构
- 字段: `token`, `user_id`, `username`, `expired_at`, `set_pwd` 等。  
  `/sources/com/jbzd/media/movecartoons/bean/TokenBean.java:7-14`

### 5.2 Token 落库与读取
- 写入: `MyApp.m4188i(tokenBean)` -> `default_storage.USER_TOKEN`  
  `/sources/com/jbzd/media/movecartoons/MyApp.java:139-155`
- 读取: `MyApp.m4186g()` <- `default_storage.USER_TOKEN`  
  `/sources/com/jbzd/media/movecartoons/MyApp.java:98-115`

### 5.3 Token 参与后续请求
- 统一请求体: `BaseRequestBody{deviceId, token, data}`  
  `/sources/com/jbzd/media/movecartoons/bean/request/BaseRequestBody.java:4-7`
- token 组装格式: `token + "_" + user_id`  
  `/sources/p005b/p006a/p007a/p008a/p017r/C0917a.java:763-767`

## 6. 网络封装与鉴权行为

### 6.1 请求封装
- 所有核心请求通过 `C0917a` 封装，body 为 `application/octet-stream`。  
  `/sources/p005b/p006a/p007a/p008a/p017r/C0917a.java:756-790`

### 6.2 加密方式
- AES/ECB/PKCS5Padding，密钥硬编码 `67f69826eac1a4f1`。  
  请求加密: `/sources/p005b/p006a/p007a/p008a/p017r/C0917a.java:775-778`  
  响应解密: `/sources/p005b/p006a/p007a/p008a/p017r/C0917a.java:602-605`

### 6.3 Token 过期自动刷新
- 拦截器检测 `errorCode == 2002` 后，静默调用 `user/login` 刷新 token，再重放原 POST。  
  `/sources/p005b/p006a/p007a/p008a/p017r/p020m/C0943d.java:82-115`

## 7. 关键流程图（文字）

### 7.1 账号密码链
`LoginActivity` -> `ActLoginInputBindingImpl` -> `SignViewModel.refreshAccount` -> `user/findByAccount` -> `MyApp.m4188i(token)` -> `user/info` -> `MyApp.m4189j(userInfo)`

### 7.2 手机验证码链
`PhoneViewModel.getPicCaptcha` -> `system/captcha` -> `sendSmsCode(system/sendSms)` -> `submit` -> `user/findByPhone` -> `MyApp.m4188i(token)`

### 7.3 卡密链
`MineViewModel.loginByCard` -> `user/findQrcode` -> `MyApp.m4188i(token)`

## 8. 取证建议（动态）
1. 抓包同时记录 `USER_TOKEN` 变化（登录前后、过期刷新后）。
2. 针对 4 条登录路径各取一条完整请求链：
   - 请求时间、URL、密文长度、解密后 JSON 字段、响应 `errorCode/status`。
3. 专门验证 `errorCode=2002` 场景，留存：
   - 原始失败请求
   - 自动 `user/login` 请求
   - 重放后成功请求
4. 固定留存字段:
   - `account_name/phone/code/type`
   - `TokenBean.token/user_id/expired_at`
   - `BaseRequestBody.token` 组装值
   - `user/info` 返回用户标识

## 9. 风险备注（仅取证结论）
- 登录与注册共用 `user/findByAccount`，仅靠 `type` 区分，后端若校验薄弱容易引发逻辑混淆。
- token 存储为可读 JSON（SharedPreferences），且传输层使用固定密钥 AES-ECB，存在安全设计弱点。
- 存在自动 token 刷新与重放机制，需重点审计是否可被异常触发滥用。

---
本报告基于静态逆向，不包含未授权的在线攻击行为。
