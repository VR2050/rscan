package com.RNFetchBlob;

import B2.w;
import B2.z;
import android.app.Activity;
import android.app.DownloadManager;
import android.content.Intent;
import android.util.SparseArray;
import com.RNFetchBlob.f;
import com.facebook.react.bridge.ActivityEventListener;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.LifecycleEventListener;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import java.io.File;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes.dex */
public class RNFetchBlob extends ReactContextBaseJavaModule {
    private static boolean ActionViewVisible;
    static ReactApplicationContext RCTContext;
    static LinkedBlockingQueue<Runnable> fsTaskQueue;
    private static ThreadPoolExecutor fsThreadPool;
    private static SparseArray<Promise> promiseTable;
    private static LinkedBlockingQueue<Runnable> taskQueue = new LinkedBlockingQueue<>();
    private static ThreadPoolExecutor threadPool;
    private final z mClient;

    class a implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ String f5694b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ String f5695c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ Promise f5696d;

        a(String str, String str2, Promise promise) {
            this.f5694b = str;
            this.f5695c = str2;
            this.f5696d = promise;
        }

        @Override // java.lang.Runnable
        public void run() {
            com.RNFetchBlob.d.o(this.f5694b, this.f5695c, this.f5696d);
        }
    }

    class b implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ ReactApplicationContext f5698b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ String f5699c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ String f5700d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ int f5701e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        final /* synthetic */ int f5702f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        final /* synthetic */ String f5703g;

        b(ReactApplicationContext reactApplicationContext, String str, String str2, int i3, int i4, String str3) {
            this.f5698b = reactApplicationContext;
            this.f5699c = str;
            this.f5700d = str2;
            this.f5701e = i3;
            this.f5702f = i4;
            this.f5703g = str3;
        }

        @Override // java.lang.Runnable
        public void run() {
            new com.RNFetchBlob.d(this.f5698b).y(this.f5699c, this.f5700d, this.f5701e, this.f5702f, this.f5703g);
        }
    }

    class c implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ Callback f5705b;

        c(Callback callback) {
            this.f5705b = callback;
        }

        @Override // java.lang.Runnable
        public void run() {
            com.RNFetchBlob.d.f(this.f5705b);
        }
    }

    class d implements ActivityEventListener {
        d() {
        }

        @Override // com.facebook.react.bridge.ActivityEventListener
        public void onActivityResult(Activity activity, int i3, int i4, Intent intent) {
            Integer num = com.RNFetchBlob.c.f5772a;
            if (i3 == num.intValue() && i4 == -1) {
                ((Promise) RNFetchBlob.promiseTable.get(num.intValue())).resolve(intent.getData().toString());
                RNFetchBlob.promiseTable.remove(num.intValue());
            }
        }

        @Override // com.facebook.react.bridge.ActivityEventListener
        public void onNewIntent(Intent intent) {
        }
    }

    class e implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ String f5708b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ String f5709c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ String f5710d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ Promise f5711e;

        e(String str, String str2, String str3, Promise promise) {
            this.f5708b = str;
            this.f5709c = str2;
            this.f5710d = str3;
            this.f5711e = promise;
        }

        @Override // java.lang.Runnable
        public void run() {
            com.RNFetchBlob.d.c(this.f5708b, this.f5709c, this.f5710d, this.f5711e);
        }
    }

    class f implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ String f5713b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ ReadableArray f5714c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ Promise f5715d;

        f(String str, ReadableArray readableArray, Promise promise) {
            this.f5713b = str;
            this.f5714c = readableArray;
            this.f5715d = promise;
        }

        @Override // java.lang.Runnable
        public void run() {
            com.RNFetchBlob.d.d(this.f5713b, this.f5714c, this.f5715d);
        }
    }

    class g implements LifecycleEventListener {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ Promise f5717b;

        g(Promise promise) {
            this.f5717b = promise;
        }

        @Override // com.facebook.react.bridge.LifecycleEventListener
        public void onHostDestroy() {
        }

        @Override // com.facebook.react.bridge.LifecycleEventListener
        public void onHostPause() {
        }

        @Override // com.facebook.react.bridge.LifecycleEventListener
        public void onHostResume() {
            if (RNFetchBlob.ActionViewVisible) {
                this.f5717b.resolve(null);
            }
            RNFetchBlob.RCTContext.removeLifecycleEventListener(this);
        }
    }

    class h implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ String f5719b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ String f5720c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ Callback f5721d;

        h(String str, String str2, Callback callback) {
            this.f5719b = str;
            this.f5720c = str2;
            this.f5721d = callback;
        }

        @Override // java.lang.Runnable
        public void run() {
            com.RNFetchBlob.d.b(this.f5719b, this.f5720c, this.f5721d);
        }
    }

    class i implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ String f5723b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ String f5724c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ Promise f5725d;

        i(String str, String str2, Promise promise) {
            this.f5723b = str;
            this.f5724c = str2;
            this.f5725d = promise;
        }

        @Override // java.lang.Runnable
        public void run() {
            com.RNFetchBlob.d.x(this.f5723b, this.f5724c, this.f5725d);
        }
    }

    class j implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ String f5727b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ ReadableArray f5728c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ boolean f5729d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ Promise f5730e;

        j(String str, ReadableArray readableArray, boolean z3, Promise promise) {
            this.f5727b = str;
            this.f5728c = readableArray;
            this.f5729d = z3;
            this.f5730e = promise;
        }

        @Override // java.lang.Runnable
        public void run() {
            com.RNFetchBlob.d.I(this.f5727b, this.f5728c, this.f5729d, this.f5730e);
        }
    }

    class k implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ String f5732b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ String f5733c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ String f5734d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ boolean f5735e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        final /* synthetic */ Promise f5736f;

        k(String str, String str2, String str3, boolean z3, Promise promise) {
            this.f5732b = str;
            this.f5733c = str2;
            this.f5734d = str3;
            this.f5735e = z3;
            this.f5736f = promise;
        }

        @Override // java.lang.Runnable
        public void run() {
            com.RNFetchBlob.d.J(this.f5732b, this.f5733c, this.f5734d, this.f5735e, this.f5736f);
        }
    }

    class l implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ ReadableArray f5738b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ ReactApplicationContext f5739c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ Callback f5740d;

        l(ReadableArray readableArray, ReactApplicationContext reactApplicationContext, Callback callback) {
            this.f5738b = readableArray;
            this.f5739c = reactApplicationContext;
            this.f5740d = callback;
        }

        @Override // java.lang.Runnable
        public void run() {
            int size = this.f5738b.size();
            String[] strArr = new String[size];
            String[] strArr2 = new String[size];
            for (int i3 = 0; i3 < size; i3++) {
                ReadableMap map = this.f5738b.getMap(i3);
                if (map.hasKey("path")) {
                    strArr[i3] = map.getString("path");
                    if (map.hasKey("mime")) {
                        strArr2[i3] = map.getString("mime");
                    } else {
                        strArr2[i3] = null;
                    }
                }
            }
            new com.RNFetchBlob.d(this.f5739c).A(strArr, strArr2, this.f5740d);
        }
    }

    static {
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        threadPool = new ThreadPoolExecutor(5, 10, 5000L, timeUnit, taskQueue);
        fsTaskQueue = new LinkedBlockingQueue<>();
        fsThreadPool = new ThreadPoolExecutor(2, 10, 5000L, timeUnit, taskQueue);
        ActionViewVisible = false;
        promiseTable = new SparseArray<>();
    }

    public RNFetchBlob(ReactApplicationContext reactApplicationContext) {
        super(reactApplicationContext);
        z zVarF = com.facebook.react.modules.network.g.f();
        this.mClient = zVarF;
        ((com.facebook.react.modules.network.a) zVarF.q()).d(new w(new com.facebook.react.modules.network.d(reactApplicationContext)));
        RCTContext = reactApplicationContext;
        reactApplicationContext.addActivityEventListener(new d());
    }

    @ReactMethod
    public void actionViewIntent(String str, String str2, Promise promise) {
        try {
            Intent dataAndType = new Intent("android.intent.action.VIEW").setDataAndType(androidx.core.content.b.h(getCurrentActivity(), getReactApplicationContext().getPackageName() + ".provider", new File(str)), str2);
            dataAndType.setFlags(1);
            dataAndType.addFlags(268435456);
            if (dataAndType.resolveActivity(getCurrentActivity().getPackageManager()) != null) {
                getReactApplicationContext().startActivity(dataAndType);
            }
            ActionViewVisible = true;
            RCTContext.addLifecycleEventListener(new g(promise));
        } catch (Exception e3) {
            promise.reject("EUNSPECIFIED", e3.getLocalizedMessage());
        }
    }

    @ReactMethod
    public void addCompleteDownload(ReadableMap readableMap, Promise promise) {
        DownloadManager downloadManager = (DownloadManager) RCTContext.getSystemService("download");
        if (readableMap == null || !readableMap.hasKey("path")) {
            promise.reject("EINVAL", "RNFetchblob.addCompleteDownload config or path missing.");
            return;
        }
        String strW = com.RNFetchBlob.d.w(readableMap.getString("path"));
        if (strW == null) {
            promise.reject("EINVAL", "RNFetchblob.addCompleteDownload can not resolve URI:" + readableMap.getString("path"));
            return;
        }
        try {
            downloadManager.addCompletedDownload(readableMap.hasKey("title") ? readableMap.getString("title") : "", readableMap.hasKey("description") ? readableMap.getString("description") : "", true, readableMap.hasKey("mime") ? readableMap.getString("mime") : null, strW, Long.valueOf(com.RNFetchBlob.d.D(strW).getString("size")).longValue(), readableMap.hasKey("showNotification") && readableMap.getBoolean("showNotification"));
            promise.resolve(null);
        } catch (Exception e3) {
            promise.reject("EUNSPECIFIED", e3.getLocalizedMessage());
        }
    }

    @ReactMethod
    public void cancelRequest(String str, Callback callback) {
        try {
            com.RNFetchBlob.g.c(str);
            callback.invoke(null, str);
        } catch (Exception e3) {
            callback.invoke(e3.getLocalizedMessage(), null);
        }
    }

    @ReactMethod
    public void closeStream(String str, Callback callback) {
        com.RNFetchBlob.d.a(str, callback);
    }

    @ReactMethod
    public void cp(String str, String str2, Callback callback) {
        threadPool.execute(new h(str, str2, callback));
    }

    @ReactMethod
    public void createFile(String str, String str2, String str3, Promise promise) {
        threadPool.execute(new e(str, str2, str3, promise));
    }

    @ReactMethod
    public void createFileASCII(String str, ReadableArray readableArray, Promise promise) {
        threadPool.execute(new f(str, readableArray, promise));
    }

    @ReactMethod
    public void df(Callback callback) {
        fsThreadPool.execute(new c(callback));
    }

    @ReactMethod
    public void enableProgressReport(String str, int i3, int i4) {
        com.RNFetchBlob.g.f5793w.put(str, new com.RNFetchBlob.f(true, i3, i4, f.a.Download));
    }

    @ReactMethod
    public void enableUploadProgressReport(String str, int i3, int i4) {
        com.RNFetchBlob.g.f5794x.put(str, new com.RNFetchBlob.f(true, i3, i4, f.a.Upload));
    }

    @ReactMethod
    public void exists(String str, Callback callback) {
        com.RNFetchBlob.d.j(str, callback);
    }

    @ReactMethod
    public void fetchBlob(ReadableMap readableMap, String str, String str2, String str3, ReadableMap readableMap2, String str4, Callback callback) {
        new com.RNFetchBlob.g(readableMap, str, str2, str3, readableMap2, str4, null, this.mClient, callback).run();
    }

    @ReactMethod
    public void fetchBlobForm(ReadableMap readableMap, String str, String str2, String str3, ReadableMap readableMap2, ReadableArray readableArray, Callback callback) {
        new com.RNFetchBlob.g(readableMap, str, str2, str3, readableMap2, null, readableArray, this.mClient, callback).run();
    }

    @Override // com.facebook.react.bridge.BaseJavaModule
    public Map<String, Object> getConstants() {
        return com.RNFetchBlob.d.m(getReactApplicationContext());
    }

    @ReactMethod
    public void getContentIntent(String str, Promise promise) {
        Intent intent = new Intent("android.intent.action.GET_CONTENT");
        if (str != null) {
            intent.setType(str);
        } else {
            intent.setType("*/*");
        }
        SparseArray<Promise> sparseArray = promiseTable;
        Integer num = com.RNFetchBlob.c.f5772a;
        sparseArray.put(num.intValue(), promise);
        getReactApplicationContext().startActivityForResult(intent, num.intValue(), null);
    }

    @Override // com.facebook.react.bridge.NativeModule
    public String getName() {
        return "RNFetchBlob";
    }

    @ReactMethod
    public void getSDCardApplicationDir(Promise promise) {
        com.RNFetchBlob.d.k(getReactApplicationContext(), promise);
    }

    @ReactMethod
    public void getSDCardDir(Promise promise) {
        com.RNFetchBlob.d.l(promise);
    }

    @ReactMethod
    public void hash(String str, String str2, Promise promise) {
        threadPool.execute(new a(str, str2, promise));
    }

    @ReactMethod
    public void ls(String str, Promise promise) {
        com.RNFetchBlob.d.s(str, promise);
    }

    @ReactMethod
    public void lstat(String str, Callback callback) {
        com.RNFetchBlob.d.t(str, callback);
    }

    @ReactMethod
    public void mkdir(String str, Promise promise) {
        com.RNFetchBlob.d.u(str, promise);
    }

    @ReactMethod
    public void mv(String str, String str2, Callback callback) {
        com.RNFetchBlob.d.v(str, str2, callback);
    }

    @ReactMethod
    public void readFile(String str, String str2, Promise promise) {
        threadPool.execute(new i(str, str2, promise));
    }

    @ReactMethod
    public void readStream(String str, String str2, int i3, int i4, String str3) {
        fsThreadPool.execute(new b(getReactApplicationContext(), str, str2, i3, i4, str3));
    }

    @ReactMethod
    public void removeSession(ReadableArray readableArray, Callback callback) {
        com.RNFetchBlob.d.z(readableArray, callback);
    }

    @ReactMethod
    public void scanFile(ReadableArray readableArray, Callback callback) {
        threadPool.execute(new l(readableArray, getReactApplicationContext(), callback));
    }

    @ReactMethod
    public void slice(String str, String str2, int i3, int i4, Promise promise) {
        com.RNFetchBlob.d.B(str, str2, i3, i4, "", promise);
    }

    @ReactMethod
    public void stat(String str, Callback callback) {
        com.RNFetchBlob.d.C(str, callback);
    }

    @ReactMethod
    public void unlink(String str, Callback callback) {
        com.RNFetchBlob.d.F(str, callback);
    }

    @ReactMethod
    public void writeArrayChunk(String str, ReadableArray readableArray, Callback callback) {
        com.RNFetchBlob.d.G(str, readableArray, callback);
    }

    @ReactMethod
    public void writeChunk(String str, String str2, Callback callback) {
        com.RNFetchBlob.d.H(str, str2, callback);
    }

    @ReactMethod
    public void writeFile(String str, String str2, String str3, boolean z3, Promise promise) {
        threadPool.execute(new k(str, str2, str3, z3, promise));
    }

    @ReactMethod
    public void writeFileArray(String str, ReadableArray readableArray, boolean z3, Promise promise) {
        threadPool.execute(new j(str, readableArray, z3, promise));
    }

    @ReactMethod
    public void writeStream(String str, String str2, boolean z3, Callback callback) {
        new com.RNFetchBlob.d(getReactApplicationContext()).K(str, str2, z3, callback);
    }
}
