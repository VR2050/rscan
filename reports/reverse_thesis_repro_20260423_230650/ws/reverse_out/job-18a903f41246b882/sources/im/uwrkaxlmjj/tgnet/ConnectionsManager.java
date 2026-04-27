package im.uwrkaxlmjj.tgnet;

import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.os.AsyncTask;
import android.os.Build;
import android.os.SystemClock;
import android.text.TextUtils;
import com.google.android.exoplayer2.util.Log;
import com.google.firebase.remoteconfig.FirebaseRemoteConfig;
import com.king.zxing.util.LogUtils;
import com.litesuits.orm.db.assit.SQLBuilder;
import im.uwrkaxlmjj.messenger.AccountInstance;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BaseController;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.KeepAliveJob;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.StatsController;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.network.NetWorkManager;
import im.uwrkaxlmjj.tgnet.TLRPC;
import java.io.File;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/* JADX INFO: loaded from: classes2.dex */
public class ConnectionsManager extends BaseController {
    private static final int CORE_POOL_SIZE;
    public static final int CPU_COUNT;
    public static final int ConnectionStateConnected = 3;
    public static final int ConnectionStateConnecting = 1;
    public static final int ConnectionStateConnectingToProxy = 4;
    public static final int ConnectionStateUpdating = 5;
    public static final int ConnectionStateWaitingForNetwork = 2;
    public static final int ConnectionTypeDownload = 2;
    public static final int ConnectionTypeDownload2 = 65538;
    public static final int ConnectionTypeGeneric = 1;
    public static final int ConnectionTypePush = 8;
    public static final int ConnectionTypeUpload = 4;
    public static final int DEFAULT_DATACENTER_ID = Integer.MAX_VALUE;
    public static final Executor DNS_THREAD_POOL_EXECUTOR;
    public static final int FileTypeAudio = 50331648;
    public static final int FileTypeFile = 67108864;
    public static final int FileTypePhoto = 16777216;
    public static final int FileTypeVideo = 33554432;
    private static volatile ConnectionsManager[] Instance = null;
    private static final int KEEP_ALIVE_SECONDS = 30;
    private static final int MAXIMUM_POOL_SIZE;
    public static final int RequestFlagCanCompress = 4;
    public static final int RequestFlagEnableUnauthorized = 1;
    public static final int RequestFlagFailOnServerErrors = 2;
    public static final int RequestFlagForceDownload = 32;
    public static final int RequestFlagInvokeAfter = 64;
    public static final int RequestFlagNeedQuickAck = 128;
    public static final int RequestFlagTryDifferentDc = 16;
    public static final int RequestFlagWithoutLogin = 8;
    private static AsyncTask currentTask;
    private static HashMap<String, ResolvedDomain> dnsCache;
    private static int lastClassGuid;
    private static long lastDnsRequestTime;
    private static HashMap<String, ResolveHostByNameTask> resolvingHostnameTasks = new HashMap<>();
    private static final BlockingQueue<Runnable> sPoolWorkQueue;
    private static final ThreadFactory sThreadFactory;
    private boolean appPaused;
    private int appResumeCount;
    private int connectionState;
    private String currentAddress;
    private boolean isUpdating;
    private long lastPauseTime;
    private AtomicInteger lastRequestToken;

    public static native void native_applyBackupConfig(int i, long j);

    public static native void native_applyBackupIp(int i, String str, int i2, int i3);

    public static native void native_applyDatacenterAddress(int i, int i2, String str, int i3);

    public static native void native_applyDnsConfig(int i, long j, String str, int i2);

    public static native void native_bindRequestToGuid(int i, int i2, int i3);

    public static native void native_cancelRequest(int i, int i2, boolean z);

    public static native void native_cancelRequestsForGuid(int i, int i2);

    public static native long native_checkProxy(int i, String str, int i2, String str2, String str3, String str4, RequestTimeDelegate requestTimeDelegate);

    public static native void native_cleanUp(int i, boolean z);

    public static native long native_getAuthKeyId(int i);

    public static native int native_getConnectionState(int i);

    public static native int native_getCurrentTime(int i);

    public static native long native_getCurrentTimeMillis(int i);

    public static native int native_getTimeDifference(int i);

    public static native void native_init(int i, int i2, int i3, int i4, String str, String str2, String str3, String str4, String str5, String str6, String str7, String str8, int i5, boolean z, boolean z2, int i6, String str9);

    public static native int native_isTestBackend(int i);

    public static native void native_onHostNameResolved(String str, long j, String str2);

    public static native void native_pauseNetwork(int i);

    public static native void native_resumeNetwork(int i, boolean z);

    public static native void native_seSystemLangCode(int i, String str);

    public static native void native_sendRequest(int i, long j, RequestDelegateInternal requestDelegateInternal, QuickAckDelegate quickAckDelegate, WriteToSocketDelegate writeToSocketDelegate, int i2, int i3, int i4, boolean z, int i5);

    public static native void native_setAddress(int i, int i2, String str, int i3);

    public static native void native_setIpPortDefaultAddress(int i, String str, int i2);

    public static native void native_setJava(boolean z);

    public static native void native_setLangCode(int i, String str);

    public static native void native_setNetworkAvailable(int i, boolean z, int i2, boolean z2);

    public static native void native_setProxySettings(int i, String str, int i2, String str2, String str3, String str4);

    public static native void native_setPushConnectionEnabled(int i, boolean z);

    public static native void native_setRegId(int i, String str);

    public static native void native_setSystemLangCode(int i, String str);

    public static native void native_setUseIpv6(int i, boolean z);

    public static native void native_setUserId(int i, int i2);

    public static native void native_switchBackend(int i);

    public static native void native_updateDcSettings(int i);

    static {
        int iAvailableProcessors = Runtime.getRuntime().availableProcessors();
        CPU_COUNT = iAvailableProcessors;
        CORE_POOL_SIZE = Math.max(2, Math.min(iAvailableProcessors - 1, 4));
        MAXIMUM_POOL_SIZE = (CPU_COUNT * 2) + 1;
        sPoolWorkQueue = new LinkedBlockingQueue(128);
        sThreadFactory = new ThreadFactory() { // from class: im.uwrkaxlmjj.tgnet.ConnectionsManager.1
            private final AtomicInteger mCount = new AtomicInteger(1);

            @Override // java.util.concurrent.ThreadFactory
            public Thread newThread(Runnable r) {
                return new Thread(r, "DnsAsyncTask #" + this.mCount.getAndIncrement());
            }
        };
        ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(CORE_POOL_SIZE, MAXIMUM_POOL_SIZE, 30L, TimeUnit.SECONDS, sPoolWorkQueue, sThreadFactory);
        threadPoolExecutor.allowCoreThreadTimeOut(true);
        DNS_THREAD_POOL_EXECUTOR = threadPoolExecutor;
        dnsCache = new HashMap<>();
        lastClassGuid = 1;
        Instance = new ConnectionsManager[3];
    }

    /* JADX INFO: Access modifiers changed from: private */
    static class ResolvedDomain {
        public ArrayList<String> addresses;
        long ttl;

        public ResolvedDomain(ArrayList<String> a, long t) {
            this.addresses = a;
            this.ttl = t;
        }

        public String getAddress() {
            return this.addresses.get(Utilities.random.nextInt(this.addresses.size()));
        }
    }

    public static ConnectionsManager getInstance(int num) {
        ConnectionsManager localInstance = Instance[num];
        if (localInstance == null) {
            synchronized (ConnectionsManager.class) {
                localInstance = Instance[num];
                if (localInstance == null) {
                    ConnectionsManager[] connectionsManagerArr = Instance;
                    ConnectionsManager connectionsManager = new ConnectionsManager(num);
                    localInstance = connectionsManager;
                    connectionsManagerArr[num] = connectionsManager;
                }
            }
        }
        return localInstance;
    }

    public ConnectionsManager(int instance) {
        File config;
        String appVersion;
        String systemVersion;
        String systemLangCode;
        String langCode;
        String langCode2;
        String deviceModel;
        String appVersion2;
        String systemVersion2;
        String pushString;
        super(instance);
        this.lastPauseTime = System.currentTimeMillis();
        this.appPaused = true;
        this.lastRequestToken = new AtomicInteger(1);
        if (BuildVars.DEBUG_VERSION) {
            FileLog.d("ConnectionsManager.java ===> constructor , currentAccount=" + this.currentAccount + " ,newAccount=" + instance);
        }
        this.connectionState = native_getConnectionState(this.currentAccount);
        File config2 = ApplicationLoader.getFilesDirFixed();
        if (instance == 0) {
            config = config2;
        } else {
            File config3 = new File(config2, "account" + instance);
            config3.mkdirs();
            config = config3;
        }
        String configPath = config.toString();
        SharedPreferences preferences = MessagesController.getGlobalNotificationsSettings();
        boolean enablePushConnection = preferences.getBoolean("pushConnection", true);
        try {
            systemLangCode = LocaleController.getSystemLocaleStringIso639().toLowerCase();
            String langCode3 = LocaleController.getLocaleStringIso639().toLowerCase();
            langCode2 = Build.MANUFACTURER + Build.MODEL;
            PackageInfo pInfo = ApplicationLoader.applicationContext.getPackageManager().getPackageInfo(ApplicationLoader.applicationContext.getPackageName(), 0);
            appVersion = pInfo.versionName + " (" + pInfo.versionCode + SQLBuilder.PARENTHESES_RIGHT;
            systemVersion = "SDK " + Build.VERSION.SDK_INT;
            langCode = langCode3;
        } catch (Exception e) {
            appVersion = "App version unknown";
            systemVersion = "SDK " + Build.VERSION.SDK_INT;
            systemLangCode = "en";
            langCode = "";
            langCode2 = "Android unknown";
        }
        systemLangCode = systemLangCode.trim().length() == 0 ? "en" : systemLangCode;
        if (langCode2.trim().length() != 0) {
            deviceModel = langCode2;
        } else {
            deviceModel = "Android unknown";
        }
        if (appVersion.trim().length() != 0) {
            appVersion2 = appVersion;
        } else {
            appVersion2 = "App version unknown";
        }
        if (systemVersion.trim().length() != 0) {
            systemVersion2 = systemVersion;
        } else {
            systemVersion2 = "SDK Unknown";
        }
        getUserConfig().loadConfig();
        String pushString2 = SharedConfig.pushString;
        if (TextUtils.isEmpty(pushString2) && !TextUtils.isEmpty(SharedConfig.pushStringStatus)) {
            pushString = SharedConfig.pushStringStatus;
        } else {
            pushString = pushString2;
        }
        init(BuildVars.BUILD_VERSION, 105, BuildVars.APP_ID, deviceModel, systemVersion2, appVersion2, langCode, systemLangCode, configPath, FileLog.getNetworkLogPath(), pushString, getUserConfig().getClientUserId(), enablePushConnection);
    }

    public long getCurrentTimeMillis() {
        return native_getCurrentTimeMillis(this.currentAccount);
    }

    public int getCurrentTime() {
        return native_getCurrentTime(this.currentAccount);
    }

    public int getTimeDifference() {
        return native_getTimeDifference(this.currentAccount);
    }

    public int sendRequest(TLObject object, RequestDelegate completionBlock) {
        return sendRequest(object, completionBlock, (QuickAckDelegate) null, 0);
    }

    public int sendRequest(TLObject object, RequestDelegate completionBlock, int flags) {
        return sendRequest(object, completionBlock, null, null, flags, Integer.MAX_VALUE, 1, true);
    }

    public int sendRequest(TLObject object, RequestDelegate completionBlock, int flags, int connetionType) {
        return sendRequest(object, completionBlock, null, null, flags, Integer.MAX_VALUE, connetionType, true);
    }

    public int sendRequest(TLObject object, RequestDelegate completionBlock, QuickAckDelegate quickAckBlock, int flags) {
        return sendRequest(object, completionBlock, quickAckBlock, null, flags, Integer.MAX_VALUE, 1, true);
    }

    public int sendRequest(final TLObject object, final RequestDelegate onComplete, final QuickAckDelegate onQuickAck, final WriteToSocketDelegate onWriteToSocket, final int flags, final int datacenterId, final int connetionType, final boolean immediate) {
        final int requestToken = this.lastRequestToken.getAndIncrement();
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.tgnet.-$$Lambda$ConnectionsManager$beYIByTHYt2LhgI4bF_TsFNB6uo
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$sendRequest$2$ConnectionsManager(object, requestToken, onComplete, onQuickAck, onWriteToSocket, flags, datacenterId, connetionType, immediate);
            }
        });
        return requestToken;
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x0065  */
    /* JADX WARN: Removed duplicated region for block: B:29:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$sendRequest$2$ConnectionsManager(final im.uwrkaxlmjj.tgnet.TLObject r17, int r18, final im.uwrkaxlmjj.tgnet.RequestDelegate r19, im.uwrkaxlmjj.tgnet.QuickAckDelegate r20, im.uwrkaxlmjj.tgnet.WriteToSocketDelegate r21, int r22, int r23, int r24, boolean r25) {
        /*
            r16 = this;
            r1 = r17
            boolean r0 = im.uwrkaxlmjj.messenger.BuildVars.LOGS_ENABLED
            if (r0 == 0) goto L25
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            java.lang.String r2 = "send request "
            r0.append(r2)
            r0.append(r1)
            java.lang.String r2 = " with token = "
            r0.append(r2)
            r2 = r18
            r0.append(r2)
            java.lang.String r0 = r0.toString()
            im.uwrkaxlmjj.messenger.FileLog.d(r0)
            goto L27
        L25:
            r2 = r18
        L27:
            im.uwrkaxlmjj.tgnet.NativeByteBuffer r0 = new im.uwrkaxlmjj.tgnet.NativeByteBuffer     // Catch: java.lang.Exception -> L59
            int r3 = r17.getObjectSize()     // Catch: java.lang.Exception -> L59
            r0.<init>(r3)     // Catch: java.lang.Exception -> L59
            r1.serializeToStream(r0)     // Catch: java.lang.Exception -> L59
            r17.freeResources()     // Catch: java.lang.Exception -> L59
            r14 = r16
            int r3 = r14.currentAccount     // Catch: java.lang.Exception -> L57
            long r4 = r0.address     // Catch: java.lang.Exception -> L57
            im.uwrkaxlmjj.tgnet.-$$Lambda$ConnectionsManager$w9x9PJ-Nl1t6C699v9dMe_JKfDw r6 = new im.uwrkaxlmjj.tgnet.-$$Lambda$ConnectionsManager$w9x9PJ-Nl1t6C699v9dMe_JKfDw     // Catch: java.lang.Exception -> L57
            r15 = r19
            r6.<init>()     // Catch: java.lang.Exception -> L55
            r7 = r20
            r8 = r21
            r9 = r22
            r10 = r23
            r11 = r24
            r12 = r25
            r13 = r18
            native_sendRequest(r3, r4, r6, r7, r8, r9, r10, r11, r12, r13)     // Catch: java.lang.Exception -> L55
            goto L7d
        L55:
            r0 = move-exception
            goto L5e
        L57:
            r0 = move-exception
            goto L5c
        L59:
            r0 = move-exception
            r14 = r16
        L5c:
            r15 = r19
        L5e:
            im.uwrkaxlmjj.messenger.FileLog.e(r0)
            boolean r3 = im.uwrkaxlmjj.messenger.BuildVars.LOGS_ENABLED
            if (r3 == 0) goto L7d
            java.lang.StringBuilder r3 = new java.lang.StringBuilder
            r3.<init>()
            java.lang.String r4 = "java request outer layer exception "
            r3.append(r4)
            java.lang.String r4 = r0.toString()
            r3.append(r4)
            java.lang.String r3 = r3.toString()
            im.uwrkaxlmjj.messenger.FileLog.e(r3)
        L7d:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.tgnet.ConnectionsManager.lambda$sendRequest$2$ConnectionsManager(im.uwrkaxlmjj.tgnet.TLObject, int, im.uwrkaxlmjj.tgnet.RequestDelegate, im.uwrkaxlmjj.tgnet.QuickAckDelegate, im.uwrkaxlmjj.tgnet.WriteToSocketDelegate, int, int, int, boolean):void");
    }

    static /* synthetic */ void lambda$null$1(TLObject object, final RequestDelegate onComplete, long response, int errorCode, String errorText, int networkType) {
        TLObject resp = null;
        TLRPC.TL_error error = null;
        try {
            if (response != 0) {
                NativeByteBuffer buff = NativeByteBuffer.wrap(response);
                buff.reused = true;
                resp = object.deserializeResponse(buff, buff.readInt32(true), true);
            } else if (errorText != null) {
                error = new TLRPC.TL_error();
                error.code = errorCode;
                error.text = errorText;
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.e(object + " got error " + error.code + " " + error.text);
                }
            }
            if (resp != null) {
                resp.networkType = networkType;
            }
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("java received " + resp + " error = " + error);
            }
            final TLObject finalResponse = resp;
            final TLRPC.TL_error finalError = error;
            Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.tgnet.-$$Lambda$ConnectionsManager$eC_83xpm6jtdB-0J-bkm-kndEY4
                @Override // java.lang.Runnable
                public final void run() {
                    ConnectionsManager.lambda$null$0(onComplete, finalResponse, finalError);
                }
            });
        } catch (Exception e) {
            FileLog.e(e);
            if (BuildVars.LOGS_ENABLED) {
                FileLog.e("java parse inner layer exception " + e.toString());
            }
        }
    }

    static /* synthetic */ void lambda$null$0(RequestDelegate onComplete, TLObject finalResponse, TLRPC.TL_error finalError) {
        onComplete.run(finalResponse, finalError);
        if (finalResponse != null) {
            finalResponse.freeResources();
        }
    }

    public void cancelRequest(int token, boolean notifyServer) {
        native_cancelRequest(this.currentAccount, token, notifyServer);
    }

    public void cleanup(boolean resetKeys) {
        native_cleanUp(this.currentAccount, resetKeys);
    }

    public void cancelRequestsForGuid(int guid) {
        native_cancelRequestsForGuid(this.currentAccount, guid);
    }

    public void bindRequestToGuid(int requestToken, int guid) {
        native_bindRequestToGuid(this.currentAccount, requestToken, guid);
    }

    public void applyDatacenterAddress(int datacenterId, String ipAddress, int port) {
        this.currentAddress = ipAddress + LogUtils.COLON + port;
        native_applyDatacenterAddress(this.currentAccount, datacenterId, ipAddress, port);
    }

    public void setAddress(int datacenterId, String ipAddress, int port) {
        this.currentAddress = ipAddress + LogUtils.COLON + port;
        native_setAddress(this.currentAccount, datacenterId, ipAddress, port);
    }

    public int getConnectionState() {
        if (this.connectionState == 3 && this.isUpdating) {
            return 5;
        }
        return this.connectionState;
    }

    public void setUserId(int id) {
        native_setUserId(this.currentAccount, id);
    }

    public void checkConnection() {
        native_setUseIpv6(this.currentAccount, useIpv6Address());
        native_setNetworkAvailable(this.currentAccount, ApplicationLoader.isNetworkOnline(), ApplicationLoader.getCurrentNetworkType(), ApplicationLoader.isConnectionSlow());
    }

    public void setPushConnectionEnabled(boolean value) {
        native_setPushConnectionEnabled(this.currentAccount, value);
    }

    public void init(int version, int layer, int apiId, String deviceModel, String systemVersion, String appVersion, String langCode, String systemLangCode, String configPath, String logPath, String regId, int userId, boolean enablePushConnection) {
        SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences("mainconfig", 0);
        String proxyAddress = preferences.getString("proxy_ip", "");
        String proxyUsername = preferences.getString("proxy_user", "");
        String proxyPassword = preferences.getString("proxy_pass", "");
        String proxySecret = preferences.getString("proxy_secret", "");
        int proxyPort = preferences.getInt("proxy_port", 1080);
        if (preferences.getBoolean("proxy_enabled", false) && !TextUtils.isEmpty(proxyAddress)) {
            native_setProxySettings(this.currentAccount, proxyAddress, proxyPort, proxyUsername, proxyPassword, proxySecret);
        }
        native_init(this.currentAccount, version, layer, apiId, deviceModel, systemVersion, appVersion, langCode, systemLangCode, configPath, logPath, regId, userId, enablePushConnection, ApplicationLoader.isNetworkOnline(), ApplicationLoader.getCurrentNetworkType(), "Sbcc");
        checkConnection();
    }

    public static void setLangCode(String langCode) {
        String langCode2 = langCode.replace('_', '-').toLowerCase();
        for (int a = 0; a < 3; a++) {
            native_setLangCode(a, langCode2);
        }
    }

    public static void setRegId(String regId, String status) {
        String pushString = regId;
        if (TextUtils.isEmpty(pushString) && !TextUtils.isEmpty(status)) {
            pushString = status;
        }
        for (int a = 0; a < 3; a++) {
            native_setRegId(a, pushString);
        }
    }

    public static void setSystemLangCode(String langCode) {
        String langCode2 = langCode.replace('_', '-').toLowerCase();
        for (int a = 0; a < 3; a++) {
            native_setSystemLangCode(a, langCode2);
        }
    }

    public void switchBackend() {
        SharedPreferences preferences = MessagesController.getGlobalMainSettings();
        preferences.edit().remove("language_showed2").commit();
        native_switchBackend(this.currentAccount);
    }

    public void resumeNetworkMaybe() {
        native_resumeNetwork(this.currentAccount, true);
    }

    public void updateDcSettings() {
        native_updateDcSettings(this.currentAccount);
    }

    public long getPauseTime() {
        return this.lastPauseTime;
    }

    public long checkProxy(String address, int port, String username, String password, String secret, RequestTimeDelegate requestTimeDelegate) {
        if (TextUtils.isEmpty(address)) {
            return 0L;
        }
        if (address == null) {
            address = "";
        }
        if (username == null) {
            username = "";
        }
        if (password == null) {
            password = "";
        }
        if (secret == null) {
            secret = "";
        }
        return native_checkProxy(this.currentAccount, address, port, username, password, secret, requestTimeDelegate);
    }

    public void setAppPaused(boolean value, boolean byScreenState) {
        if (!byScreenState) {
            this.appPaused = value;
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("app paused = " + value);
            }
            if (value) {
                this.appResumeCount--;
            } else {
                this.appResumeCount++;
            }
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("app resume count " + this.appResumeCount);
            }
            if (this.appResumeCount < 0) {
                this.appResumeCount = 0;
            }
        }
        if (this.appResumeCount == 0) {
            if (this.lastPauseTime == 0) {
                this.lastPauseTime = System.currentTimeMillis();
            }
            native_pauseNetwork(this.currentAccount);
        } else {
            if (this.appPaused) {
                return;
            }
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("reset app pause time");
            }
            this.lastPauseTime = 0L;
            native_resumeNetwork(this.currentAccount, false);
        }
    }

    public static void onUnparsedMessageReceived(long address, final int currentAccount) {
        try {
            NativeByteBuffer buff = NativeByteBuffer.wrap(address);
            buff.reused = true;
            int constructor = buff.readInt32(true);
            final TLObject message = TLClassStore.Instance().TLdeserialize(buff, constructor, true);
            if (message instanceof TLRPC.Updates) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("java received " + message);
                }
                KeepAliveJob.finishJob();
                Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.tgnet.-$$Lambda$ConnectionsManager$LvSYfbYqOQtvBoL2T8jUVsZHXTU
                    @Override // java.lang.Runnable
                    public final void run() throws Exception {
                        AccountInstance.getInstance(currentAccount).getMessagesController().processUpdates((TLRPC.Updates) message, false);
                    }
                });
                return;
            }
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d(String.format("java received unknown constructor 0x%x", Integer.valueOf(constructor)));
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public static void onUpdate(final int currentAccount) {
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.tgnet.-$$Lambda$ConnectionsManager$896wns587NsSjBvnjMEBK6O5QhU
            @Override // java.lang.Runnable
            public final void run() throws Exception {
                AccountInstance.getInstance(currentAccount).getMessagesController().updateTimerProc();
            }
        });
    }

    public static void onSessionCreated(final int currentAccount) {
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.tgnet.-$$Lambda$ConnectionsManager$JLNEW-ROS4yHVzOaQ3o4HreZzAA
            @Override // java.lang.Runnable
            public final void run() {
                AccountInstance.getInstance(currentAccount).getMessagesController().getDifference();
            }
        });
    }

    public static void onConnectionStateChanged(final int state, final int currentAccount) {
        Log.e("bond", "connectionState = " + state);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.tgnet.-$$Lambda$ConnectionsManager$R1vAa1Qv7EWQC2QvVgYDGSefQSQ
            @Override // java.lang.Runnable
            public final void run() {
                ConnectionsManager.lambda$onConnectionStateChanged$6(currentAccount, state);
            }
        });
    }

    static /* synthetic */ void lambda$onConnectionStateChanged$6(int currentAccount, int state) {
        getInstance(currentAccount).connectionState = state;
        AccountInstance.getInstance(currentAccount).getNotificationCenter().postNotificationName(NotificationCenter.didUpdateConnectionState, new Object[0]);
    }

    public static void onLogout(final int currentAccount) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.tgnet.-$$Lambda$ConnectionsManager$-Vz0Dl302ybywvOKJygxEb3Nuh0
            @Override // java.lang.Runnable
            public final void run() {
                ConnectionsManager.lambda$onLogout$7(currentAccount);
            }
        });
    }

    static /* synthetic */ void lambda$onLogout$7(int currentAccount) {
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("ConnectionManager.java received signal of logout.");
        }
        AccountInstance accountInstance = AccountInstance.getInstance(currentAccount);
        if (accountInstance.getUserConfig().getClientUserId() != 0) {
            accountInstance.getUserConfig().clearConfig();
            accountInstance.getMessagesController().performLogout(0);
        }
    }

    public static int getInitFlags() {
        return 0;
    }

    public static void onBytesSent(int amount, int networkType, int currentAccount) {
        try {
            AccountInstance.getInstance(currentAccount).getStatsController().incrementSentBytesCount(networkType, 6, amount);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public static void onRequestNewServerIpAndPort(final int second, final int currentAccount) {
        Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.tgnet.-$$Lambda$ConnectionsManager$JMMeL0lSlDvMUggb7E84ZP9ozTg
            @Override // java.lang.Runnable
            public final void run() {
                ConnectionsManager.lambda$onRequestNewServerIpAndPort$8(second, currentAccount);
            }
        });
    }

    static /* synthetic */ void lambda$onRequestNewServerIpAndPort$8(int second, int currentAccount) {
        if (currentTask != null || ((second == 0 && Math.abs(lastDnsRequestTime - System.currentTimeMillis()) < 6000) || !ApplicationLoader.isNetworkOnline())) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("don't start task, current task = " + currentTask + " next task = " + second + " time diff = " + Math.abs(lastDnsRequestTime - System.currentTimeMillis()) + " network = " + ApplicationLoader.isNetworkOnline());
                return;
            }
            return;
        }
        lastDnsRequestTime = System.currentTimeMillis();
        if (second == 1) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("start dns txt task");
            }
            DnsTxtLoadTask task = new DnsTxtLoadTask(currentAccount);
            task.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, null, null, null);
            currentTask = task;
            return;
        }
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("start firebase task");
        }
        FirebaseTask task2 = new FirebaseTask(currentAccount);
        task2.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, null, null, null);
        currentTask = task2;
    }

    public static void onProxyError() {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.tgnet.-$$Lambda$ConnectionsManager$TpSCeWOKmFQx1mOG1VDPWu1OrhY
            @Override // java.lang.Runnable
            public final void run() {
                NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.needShowAlert, 3);
            }
        });
    }

    public static void getHostByName(final String hostName, final long address) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.tgnet.-$$Lambda$ConnectionsManager$dI1GPACEsHEEc2xcJoy79YGVPWI
            @Override // java.lang.Runnable
            public final void run() {
                ConnectionsManager.lambda$getHostByName$10(hostName, address);
            }
        });
    }

    static /* synthetic */ void lambda$getHostByName$10(String hostName, long address) {
        ResolvedDomain resolvedDomain = dnsCache.get(hostName);
        if (resolvedDomain != null && SystemClock.elapsedRealtime() - resolvedDomain.ttl < 300000) {
            native_onHostNameResolved(hostName, address, resolvedDomain.getAddress());
            return;
        }
        ResolveHostByNameTask task = resolvingHostnameTasks.get(hostName);
        if (task == null) {
            task = new ResolveHostByNameTask(hostName);
            try {
                task.executeOnExecutor(DNS_THREAD_POOL_EXECUTOR, null, null, null);
                resolvingHostnameTasks.put(hostName, task);
            } catch (Throwable e) {
                FileLog.e(e);
                native_onHostNameResolved(hostName, address, "");
                return;
            }
        }
        task.addAddress(address);
    }

    public static void onBytesReceived(int amount, int networkType, int currentAccount) {
        try {
            StatsController.getInstance(currentAccount).incrementReceivedBytesCount(networkType, 6, amount);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public static void onUpdateConfig(long address, final int currentAccount) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.tgnet.-$$Lambda$ConnectionsManager$LmJgB3E_LSiaRgAOt1a0oTa1gwU
            @Override // java.lang.Runnable
            public final void run() {
                ConnectionsManager.lambda$onUpdateConfig$11(currentAccount);
            }
        });
        try {
            NativeByteBuffer buff = NativeByteBuffer.wrap(address);
            buff.reused = true;
            final TLRPC.TL_config message = TLRPC.TL_config.TLdeserialize(buff, buff.readInt32(true), true);
            if (message != null) {
                Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.tgnet.-$$Lambda$ConnectionsManager$ADY2KnxsAGRLTV74MUz_-PlGRpA
                    @Override // java.lang.Runnable
                    public final void run() {
                        AccountInstance.getInstance(currentAccount).getMessagesController().updateConfig(message);
                    }
                });
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    static /* synthetic */ void lambda$onUpdateConfig$11(int currentAccount) {
        NotificationCenter.getInstance(currentAccount).postNotificationName(NotificationCenter.getBackupIpStatus, "server 3");
        NetWorkManager.getInstance().setServer2("server 3");
    }

    public static void onInternalPushReceived(int currentAccount) {
        KeepAliveJob.startJob();
    }

    public static void setProxySettings(boolean enabled, String address, int port, String username, String password, String secret) {
        if (address == null) {
            address = "";
        }
        if (username == null) {
            username = "";
        }
        if (password == null) {
            password = "";
        }
        if (secret == null) {
            secret = "";
        }
        for (int a = 0; a < 3; a++) {
            if (enabled && !TextUtils.isEmpty(address)) {
                native_setProxySettings(a, address, port, username, password, secret);
            } else {
                native_setProxySettings(a, "", 1080, "", "", "");
            }
            AccountInstance accountInstance = AccountInstance.getInstance(a);
            if (accountInstance.getUserConfig().isClientActivated()) {
                accountInstance.getMessagesController().checkProxyInfo(true);
            }
        }
    }

    public long getAuthKeyId(int currentAccount) {
        return native_getAuthKeyId(currentAccount);
    }

    public static int generateClassGuid() {
        int i = lastClassGuid;
        lastClassGuid = i + 1;
        return i;
    }

    public void setIsUpdating(final boolean value) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.tgnet.-$$Lambda$ConnectionsManager$pbIuXmMo7w8gsDPK90X-R5uasx0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$setIsUpdating$13$ConnectionsManager(value);
            }
        });
    }

    public /* synthetic */ void lambda$setIsUpdating$13$ConnectionsManager(boolean value) {
        if (this.isUpdating == value) {
            return;
        }
        this.isUpdating = value;
        if (this.connectionState == 3) {
            AccountInstance.getInstance(this.currentAccount).getNotificationCenter().postNotificationName(NotificationCenter.didUpdateConnectionState, new Object[0]);
        }
    }

    protected static boolean useIpv6Address() {
        boolean hasIpv4;
        boolean hasIpv6;
        if (Build.VERSION.SDK_INT < 19) {
            return false;
        }
        if (BuildVars.LOGS_ENABLED) {
            try {
                Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
                while (networkInterfaces.hasMoreElements()) {
                    NetworkInterface networkInterface = networkInterfaces.nextElement();
                    if (networkInterface.isUp() && !networkInterface.isLoopback() && !networkInterface.getInterfaceAddresses().isEmpty()) {
                        if (BuildVars.LOGS_ENABLED) {
                            FileLog.d("valid interface: " + networkInterface);
                        }
                        List<InterfaceAddress> interfaceAddresses = networkInterface.getInterfaceAddresses();
                        for (int a = 0; a < interfaceAddresses.size(); a++) {
                            InterfaceAddress address = interfaceAddresses.get(a);
                            InetAddress inetAddress = address.getAddress();
                            if (BuildVars.LOGS_ENABLED) {
                                FileLog.d("address: " + inetAddress.getHostAddress());
                            }
                            if (!inetAddress.isLinkLocalAddress() && !inetAddress.isLoopbackAddress() && !inetAddress.isMulticastAddress() && BuildVars.LOGS_ENABLED) {
                                FileLog.d("address is good");
                            }
                        }
                    }
                }
            } catch (Throwable e) {
                FileLog.e(e);
            }
        }
        try {
            Enumeration<NetworkInterface> networkInterfaces2 = NetworkInterface.getNetworkInterfaces();
            hasIpv4 = false;
            hasIpv6 = false;
            while (networkInterfaces2.hasMoreElements()) {
                NetworkInterface networkInterface2 = networkInterfaces2.nextElement();
                if (networkInterface2.isUp() && !networkInterface2.isLoopback()) {
                    List<InterfaceAddress> interfaceAddresses2 = networkInterface2.getInterfaceAddresses();
                    for (int a2 = 0; a2 < interfaceAddresses2.size(); a2++) {
                        InterfaceAddress address2 = interfaceAddresses2.get(a2);
                        InetAddress inetAddress2 = address2.getAddress();
                        if (!inetAddress2.isLinkLocalAddress() && !inetAddress2.isLoopbackAddress() && !inetAddress2.isMulticastAddress()) {
                            if (inetAddress2 instanceof Inet6Address) {
                                hasIpv6 = true;
                            } else if (inetAddress2 instanceof Inet4Address) {
                                String addrr = inetAddress2.getHostAddress();
                                if (!addrr.startsWith("192.0.0.")) {
                                    hasIpv4 = true;
                                }
                            }
                        }
                    }
                }
            }
        } catch (Throwable e2) {
            FileLog.e(e2);
        }
        return !hasIpv4 && hasIpv6;
    }

    /* JADX INFO: Access modifiers changed from: private */
    static class ResolveHostByNameTask extends AsyncTask<Void, Void, ResolvedDomain> {
        private ArrayList<Long> addresses = new ArrayList<>();
        private String currentHostName;

        public ResolveHostByNameTask(String hostName) {
            this.currentHostName = hostName;
        }

        public void addAddress(long address) {
            if (this.addresses.contains(Long.valueOf(address))) {
                return;
            }
            this.addresses.add(Long.valueOf(address));
        }

        /* JADX INFO: Access modifiers changed from: protected */
        /* JADX WARN: Removed duplicated region for block: B:80:0x00dd A[EXC_TOP_SPLITTER, SYNTHETIC] */
        /* JADX WARN: Removed duplicated region for block: B:94:? A[RETURN, SYNTHETIC] */
        @Override // android.os.AsyncTask
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public im.uwrkaxlmjj.tgnet.ConnectionsManager.ResolvedDomain doInBackground(java.lang.Void... r14) {
            /*
                Method dump skipped, instruction units count: 279
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.tgnet.ConnectionsManager.ResolveHostByNameTask.doInBackground(java.lang.Void[]):im.uwrkaxlmjj.tgnet.ConnectionsManager$ResolvedDomain");
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        public void onPostExecute(ResolvedDomain result) {
            if (result != null) {
                ConnectionsManager.dnsCache.put(this.currentHostName, result);
                int N = this.addresses.size();
                for (int a = 0; a < N; a++) {
                    ConnectionsManager.native_onHostNameResolved(this.currentHostName, this.addresses.get(a).longValue(), result.getAddress());
                }
            } else {
                int N2 = this.addresses.size();
                for (int a2 = 0; a2 < N2; a2++) {
                    ConnectionsManager.native_onHostNameResolved(this.currentHostName, this.addresses.get(a2).longValue(), "");
                }
            }
            ConnectionsManager.resolvingHostnameTasks.remove(this.currentHostName);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    static class DnsTxtLoadTask extends AsyncTask<Void, Void, NativeByteBuffer> {
        private int currentAccount;
        private int responseDate;

        public DnsTxtLoadTask(int instance) {
            this.currentAccount = instance;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        public NativeByteBuffer doInBackground(Void... voids) {
            if (BuildVars.DEBUG_VERSION) {
                Log.i("connection", "java DnsTxtLoadTask doInBackground ===> ");
            }
            NetWorkManager.getInstance().applyDatacenterAddress(this.currentAccount, true);
            return null;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        public void onPostExecute(final NativeByteBuffer result) {
            Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.tgnet.-$$Lambda$ConnectionsManager$DnsTxtLoadTask$ijwSoORkcbBanXn_6FUaxLNt-bk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onPostExecute$0$ConnectionsManager$DnsTxtLoadTask(result);
                }
            });
        }

        public /* synthetic */ void lambda$onPostExecute$0$ConnectionsManager$DnsTxtLoadTask(NativeByteBuffer result) {
            if (result != null) {
                ConnectionsManager.native_applyBackupConfig(this.currentAccount, result.address);
            } else if (BuildVars.LOGS_ENABLED) {
                FileLog.d("failed to get dns txt result");
            }
            AsyncTask unused = ConnectionsManager.currentTask = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    static class FirebaseTask extends AsyncTask<Void, Void, NativeByteBuffer> {
        private int currentAccount;
        private FirebaseRemoteConfig firebaseRemoteConfig;

        public FirebaseTask(int instance) {
            this.currentAccount = instance;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        public NativeByteBuffer doInBackground(Void... voids) {
            if (BuildVars.DEBUG_VERSION) {
                Log.i("connection", "java FirebaseTask doInBackground ===> ");
            }
            NetWorkManager.getInstance().applyDatacenterAddress(this.currentAccount, true);
            return null;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        public void onPostExecute(final NativeByteBuffer result) {
            Utilities.stageQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.tgnet.-$$Lambda$ConnectionsManager$FirebaseTask$hJ68P6beSdaTrZ1t1WxiZG-teqc
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onPostExecute$0$ConnectionsManager$FirebaseTask(result);
                }
            });
        }

        public /* synthetic */ void lambda$onPostExecute$0$ConnectionsManager$FirebaseTask(NativeByteBuffer result) {
            if (result != null) {
                ConnectionsManager.native_applyBackupConfig(this.currentAccount, result.address);
            } else if (BuildVars.LOGS_ENABLED) {
                FileLog.d("failed to get dns txt result");
            }
            AsyncTask unused = ConnectionsManager.currentTask = null;
        }
    }
}
