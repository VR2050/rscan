package com.RNFetchBlob;

import B2.B;
import B2.C;
import B2.D;
import B2.E;
import B2.InterfaceC0167e;
import B2.InterfaceC0168f;
import B2.k;
import B2.t;
import B2.v;
import B2.x;
import B2.z;
import android.app.DownloadManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.Uri;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.ReadableMapKeySetIterator;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.modules.core.DeviceEventManagerModule;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes.dex */
public class g extends BroadcastReceiver implements Runnable {

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    public static HashMap f5791u = new HashMap();

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    public static HashMap f5792v = new HashMap();

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    static HashMap f5793w = new HashMap();

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    static HashMap f5794x = new HashMap();

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    static k f5795y = new k();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    com.RNFetchBlob.b f5796b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    String f5797c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    String f5798d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    String f5799e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    String f5800f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    String f5801g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    ReadableArray f5802h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    ReadableMap f5803i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    Callback f5804j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    long f5805k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    long f5806l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    com.RNFetchBlob.a f5807m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    e f5808n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    EnumC0091g f5809o;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    WritableMap f5811q;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    z f5814t;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    f f5810p = f.Auto;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    boolean f5812r = false;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    ArrayList f5813s = new ArrayList();

    class a implements v {
        a() {
        }

        @Override // B2.v
        public D a(v.a aVar) {
            g.this.f5813s.add(aVar.i().l().toString());
            return aVar.a(aVar.i());
        }
    }

    class b implements v {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ B f5816a;

        b(B b3) {
            this.f5816a = b3;
        }

        @Override // B2.v
        public D a(v.a aVar) {
            E aVar2;
            try {
                D dA = aVar.a(this.f5816a);
                int i3 = d.f5820b[g.this.f5809o.ordinal()];
                if (i3 == 1 || i3 != 2) {
                    aVar2 = new O.a(RNFetchBlob.RCTContext, g.this.f5797c, dA.r(), g.this.f5796b.f5769l.booleanValue());
                } else {
                    ReactApplicationContext reactApplicationContext = RNFetchBlob.RCTContext;
                    String str = g.this.f5797c;
                    E eR = dA.r();
                    g gVar = g.this;
                    aVar2 = new O.b(reactApplicationContext, str, eR, gVar.f5801g, gVar.f5796b.f5767j.booleanValue());
                }
                return dA.u0().b(aVar2).c();
            } catch (SocketException unused) {
                g.this.f5812r = true;
                return aVar.a(aVar.i());
            } catch (SocketTimeoutException unused2) {
                g.this.f5812r = true;
                return aVar.a(aVar.i());
            } catch (Exception unused3) {
                return aVar.a(aVar.i());
            }
        }
    }

    class c implements InterfaceC0168f {
        c() {
        }

        @Override // B2.InterfaceC0168f
        public void a(InterfaceC0167e interfaceC0167e, D d3) {
            ReadableMap readableMap = g.this.f5796b.f5761d;
            if (readableMap != null) {
                String string = readableMap.hasKey("title") ? g.this.f5796b.f5761d.getString("title") : "";
                String string2 = readableMap.hasKey("description") ? readableMap.getString("description") : "";
                String string3 = readableMap.hasKey("mime") ? readableMap.getString("mime") : "text/plain";
                boolean z3 = readableMap.hasKey("mediaScannable") ? readableMap.getBoolean("mediaScannable") : false;
                boolean z4 = readableMap.hasKey("notification") ? readableMap.getBoolean("notification") : false;
                DownloadManager downloadManager = (DownloadManager) RNFetchBlob.RCTContext.getSystemService("download");
                g gVar = g.this;
                downloadManager.addCompletedDownload(string, string2, z3, string3, gVar.f5801g, gVar.f5805k, z4);
            }
            g.this.d(d3);
        }

        @Override // B2.InterfaceC0168f
        public void b(InterfaceC0167e interfaceC0167e, IOException iOException) {
            g.c(g.this.f5797c);
            g gVar = g.this;
            if (gVar.f5811q == null) {
                gVar.f5811q = Arguments.createMap();
            }
            if (iOException.getClass().equals(SocketTimeoutException.class)) {
                g.this.f5811q.putBoolean("timeout", true);
                g.this.f5804j.invoke("The request timed out.", null, null);
            } else {
                g.this.f5804j.invoke(iOException.getLocalizedMessage(), null, null);
            }
            g.this.m();
        }
    }

    static /* synthetic */ class d {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        static final /* synthetic */ int[] f5819a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        static final /* synthetic */ int[] f5820b;

        static {
            int[] iArr = new int[EnumC0091g.values().length];
            f5820b = iArr;
            try {
                iArr[EnumC0091g.KeepInMemory.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f5820b[EnumC0091g.FileStorage.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            int[] iArr2 = new int[e.values().length];
            f5819a = iArr2;
            try {
                iArr2[e.SingleFile.ordinal()] = 1;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                f5819a[e.AsIs.ordinal()] = 2;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                f5819a[e.Form.ordinal()] = 3;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                f5819a[e.WithoutBody.ordinal()] = 4;
            } catch (NoSuchFieldError unused6) {
            }
        }
    }

    enum e {
        Form,
        SingleFile,
        AsIs,
        WithoutBody,
        Others
    }

    enum f {
        Auto,
        UTF8,
        BASE64
    }

    /* JADX INFO: renamed from: com.RNFetchBlob.g$g, reason: collision with other inner class name */
    enum EnumC0091g {
        KeepInMemory,
        FileStorage
    }

    public g(ReadableMap readableMap, String str, String str2, String str3, ReadableMap readableMap2, String str4, ReadableArray readableArray, z zVar, Callback callback) {
        this.f5798d = str2.toUpperCase();
        com.RNFetchBlob.b bVar = new com.RNFetchBlob.b(readableMap);
        this.f5796b = bVar;
        this.f5797c = str;
        this.f5799e = str3;
        this.f5803i = readableMap2;
        this.f5804j = callback;
        this.f5800f = str4;
        this.f5802h = readableArray;
        this.f5814t = zVar;
        if (bVar.f5758a.booleanValue() || this.f5796b.f5759b != null) {
            this.f5809o = EnumC0091g.FileStorage;
        } else {
            this.f5809o = EnumC0091g.KeepInMemory;
        }
        if (str4 != null) {
            this.f5808n = e.SingleFile;
        } else if (readableArray != null) {
            this.f5808n = e.Form;
        } else {
            this.f5808n = e.WithoutBody;
        }
    }

    public static void c(String str) {
        if (f5791u.containsKey(str)) {
            ((InterfaceC0167e) f5791u.get(str)).cancel();
            f5791u.remove(str);
        }
        if (f5792v.containsKey(str)) {
            ((DownloadManager) RNFetchBlob.RCTContext.getApplicationContext().getSystemService("download")).remove(((Long) f5792v.get(str)).longValue());
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:24:0x00c3 A[Catch: IOException -> 0x0126, TRY_LEAVE, TryCatch #3 {IOException -> 0x0126, blocks: (B:17:0x007e, B:19:0x0088, B:20:0x00a4, B:22:0x00ab, B:23:0x00b0, B:24:0x00c3, B:27:0x00db, B:29:0x00e9, B:31:0x0103, B:33:0x0109, B:34:0x0118), top: B:46:0x007e, inners: #0 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void d(B2.D r9) {
        /*
            Method dump skipped, instruction units count: 316
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.RNFetchBlob.g.d(B2.D):void");
    }

    private void e(WritableMap writableMap) {
        ((DeviceEventManagerModule.RCTDeviceEventEmitter) RNFetchBlob.RCTContext.getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)).emit("RNFetchBlobState", writableMap);
    }

    private String g(t tVar, String str) {
        String strA = tVar.a(str);
        return strA != null ? strA : tVar.a(str.toLowerCase()) == null ? "" : tVar.a(str.toLowerCase());
    }

    private String h(HashMap map, String str) {
        String str2 = (String) map.get(str);
        if (str2 != null) {
            return str2;
        }
        String str3 = (String) map.get(str.toLowerCase());
        return str3 == null ? "" : str3;
    }

    public static com.RNFetchBlob.f i(String str) {
        if (f5793w.containsKey(str)) {
            return (com.RNFetchBlob.f) f5793w.get(str);
        }
        return null;
    }

    public static com.RNFetchBlob.f j(String str) {
        if (f5794x.containsKey(str)) {
            return (com.RNFetchBlob.f) f5794x.get(str);
        }
        return null;
    }

    private WritableMap k(D d3, boolean z3) {
        WritableMap writableMapCreateMap = Arguments.createMap();
        writableMapCreateMap.putInt("status", d3.A());
        writableMapCreateMap.putString("state", "2");
        writableMapCreateMap.putString("taskId", this.f5797c);
        writableMapCreateMap.putBoolean("timeout", this.f5812r);
        WritableMap writableMapCreateMap2 = Arguments.createMap();
        for (int i3 = 0; i3 < d3.e0().size(); i3++) {
            writableMapCreateMap2.putString(d3.e0().b(i3), d3.e0().h(i3));
        }
        WritableArray writableArrayCreateArray = Arguments.createArray();
        Iterator it = this.f5813s.iterator();
        while (it.hasNext()) {
            writableArrayCreateArray.pushString((String) it.next());
        }
        writableMapCreateMap.putArray("redirects", writableArrayCreateArray);
        writableMapCreateMap.putMap("headers", writableMapCreateMap2);
        t tVarE0 = d3.e0();
        if (z3) {
            writableMapCreateMap.putString("respType", "blob");
        } else if (g(tVarE0, "content-type").equalsIgnoreCase("text/")) {
            writableMapCreateMap.putString("respType", "text");
        } else if (g(tVarE0, "content-type").contains("application/json")) {
            writableMapCreateMap.putString("respType", "json");
        } else {
            writableMapCreateMap.putString("respType", "");
        }
        return writableMapCreateMap;
    }

    private boolean l(D d3) {
        boolean z3;
        String strG = g(d3.e0(), "Content-Type");
        boolean zEqualsIgnoreCase = strG.equalsIgnoreCase("text/");
        boolean zEqualsIgnoreCase2 = strG.equalsIgnoreCase("application/json");
        if (this.f5796b.f5771n != null) {
            for (int i3 = 0; i3 < this.f5796b.f5771n.size(); i3++) {
                if (strG.toLowerCase().contains(this.f5796b.f5771n.getString(i3).toLowerCase())) {
                    z3 = true;
                    break;
                }
            }
            z3 = false;
        } else {
            z3 = false;
        }
        return (zEqualsIgnoreCase2 && zEqualsIgnoreCase) || z3;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void m() {
        if (f5791u.containsKey(this.f5797c)) {
            f5791u.remove(this.f5797c);
        }
        if (f5792v.containsKey(this.f5797c)) {
            f5792v.remove(this.f5797c);
        }
        if (f5794x.containsKey(this.f5797c)) {
            f5794x.remove(this.f5797c);
        }
        if (f5793w.containsKey(this.f5797c)) {
            f5793w.remove(this.f5797c);
        }
        com.RNFetchBlob.a aVar = this.f5807m;
        if (aVar != null) {
            aVar.j();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x00f0  */
    @Override // android.content.BroadcastReceiver
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onReceive(android.content.Context r11, android.content.Intent r12) {
        /*
            Method dump skipped, instruction units count: 341
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.RNFetchBlob.g.onReceive(android.content.Context, android.content.Intent):void");
    }

    @Override // java.lang.Runnable
    public void run() {
        ReadableMap readableMap = this.f5796b.f5761d;
        if (readableMap != null && readableMap.hasKey("useDownloadManager") && this.f5796b.f5761d.getBoolean("useDownloadManager")) {
            DownloadManager.Request request = new DownloadManager.Request(Uri.parse(this.f5799e));
            if (this.f5796b.f5761d.hasKey("notification") && this.f5796b.f5761d.getBoolean("notification")) {
                request.setNotificationVisibility(1);
            } else {
                request.setNotificationVisibility(2);
            }
            if (this.f5796b.f5761d.hasKey("title")) {
                request.setTitle(this.f5796b.f5761d.getString("title"));
            }
            if (this.f5796b.f5761d.hasKey("description")) {
                request.setDescription(this.f5796b.f5761d.getString("description"));
            }
            if (this.f5796b.f5761d.hasKey("path")) {
                request.setDestinationUri(Uri.parse("file://" + this.f5796b.f5761d.getString("path")));
            }
            if (this.f5796b.f5761d.hasKey("mime")) {
                request.setMimeType(this.f5796b.f5761d.getString("mime"));
            }
            ReadableMapKeySetIterator readableMapKeySetIteratorKeySetIterator = this.f5803i.keySetIterator();
            if (this.f5796b.f5761d.hasKey("mediaScannable") && this.f5796b.f5761d.hasKey("mediaScannable")) {
                request.allowScanningByMediaScanner();
            }
            while (readableMapKeySetIteratorKeySetIterator.hasNextKey()) {
                String strNextKey = readableMapKeySetIteratorKeySetIterator.nextKey();
                request.addRequestHeader(strNextKey, this.f5803i.getString(strNextKey));
            }
            Context applicationContext = RNFetchBlob.RCTContext.getApplicationContext();
            long jEnqueue = ((DownloadManager) applicationContext.getSystemService("download")).enqueue(request);
            this.f5806l = jEnqueue;
            f5792v.put(this.f5797c, Long.valueOf(jEnqueue));
            applicationContext.registerReceiver(this, new IntentFilter("android.intent.action.DOWNLOAD_COMPLETE"));
            return;
        }
        String strB = this.f5797c;
        String str = this.f5796b.f5760c.isEmpty() ? "" : "." + this.f5796b.f5760c;
        String str2 = this.f5796b.f5764g;
        if (str2 != null) {
            strB = h.b(str2);
            if (strB == null) {
                strB = this.f5797c;
            }
            File file = new File(com.RNFetchBlob.d.n(strB) + str);
            if (file.exists()) {
                this.f5804j.invoke(null, "path", file.getAbsolutePath());
                return;
            }
        }
        com.RNFetchBlob.b bVar = this.f5796b;
        String str3 = bVar.f5759b;
        if (str3 != null) {
            this.f5801g = str3;
        } else if (bVar.f5758a.booleanValue()) {
            this.f5801g = com.RNFetchBlob.d.n(strB) + str;
        }
        try {
            z.a aVarC = this.f5796b.f5762e.booleanValue() ? h.c(this.f5814t) : this.f5814t.C();
            if (this.f5796b.f5763f.booleanValue()) {
                ConnectivityManager connectivityManager = (ConnectivityManager) RNFetchBlob.RCTContext.getSystemService("connectivity");
                for (Network network : connectivityManager.getAllNetworks()) {
                    NetworkInfo networkInfo = connectivityManager.getNetworkInfo(network);
                    NetworkCapabilities networkCapabilities = connectivityManager.getNetworkCapabilities(network);
                    if (networkCapabilities != null && networkInfo != null && networkInfo.isConnected() && networkCapabilities.hasTransport(1)) {
                        aVarC.R(Proxy.NO_PROXY);
                        aVarC.U(network.getSocketFactory());
                    }
                }
                this.f5804j.invoke("No available WiFi connections.", null, null);
                m();
                return;
            }
            B.a aVar = new B.a();
            try {
                aVar.n(new URL(this.f5799e));
            } catch (MalformedURLException e3) {
                e3.printStackTrace();
            }
            HashMap map = new HashMap();
            ReadableMap readableMap2 = this.f5803i;
            if (readableMap2 != null) {
                ReadableMapKeySetIterator readableMapKeySetIteratorKeySetIterator2 = readableMap2.keySetIterator();
                while (readableMapKeySetIteratorKeySetIterator2.hasNextKey()) {
                    String strNextKey2 = readableMapKeySetIteratorKeySetIterator2.nextKey();
                    String string = this.f5803i.getString(strNextKey2);
                    if (!strNextKey2.equalsIgnoreCase("RNFB-Response")) {
                        aVar.e(strNextKey2.toLowerCase(), string);
                        map.put(strNextKey2.toLowerCase(), string);
                    } else if (string.equalsIgnoreCase("base64")) {
                        this.f5810p = f.BASE64;
                    } else if (string.equalsIgnoreCase("utf8")) {
                        this.f5810p = f.UTF8;
                    }
                }
            }
            if (this.f5798d.equalsIgnoreCase("post") || this.f5798d.equalsIgnoreCase("put") || this.f5798d.equalsIgnoreCase("patch")) {
                String lowerCase = h(map, "Content-Type").toLowerCase();
                if (this.f5802h != null) {
                    this.f5808n = e.Form;
                } else if (lowerCase.isEmpty()) {
                    if (!lowerCase.equalsIgnoreCase("")) {
                        aVar.e("Content-Type", "application/octet-stream");
                    }
                    this.f5808n = e.SingleFile;
                }
                String str4 = this.f5800f;
                if (str4 != null) {
                    if (str4.startsWith("RNFetchBlob-file://") || this.f5800f.startsWith("RNFetchBlob-content://")) {
                        this.f5808n = e.SingleFile;
                    } else if (lowerCase.toLowerCase().contains(";base64") || lowerCase.toLowerCase().startsWith("application/octet")) {
                        String strReplace = lowerCase.replace(";base64", "").replace(";BASE64", "");
                        if (map.containsKey("content-type")) {
                            map.put("content-type", strReplace);
                        }
                        if (map.containsKey("Content-Type")) {
                            map.put("Content-Type", strReplace);
                        }
                        this.f5808n = e.SingleFile;
                    } else {
                        this.f5808n = e.AsIs;
                    }
                }
            } else {
                this.f5808n = e.WithoutBody;
            }
            boolean zEqualsIgnoreCase = h(map, "Transfer-Encoding").equalsIgnoreCase("chunked");
            int i3 = d.f5819a[this.f5808n.ordinal()];
            if (i3 == 1) {
                com.RNFetchBlob.a aVarS = new com.RNFetchBlob.a(this.f5797c).i(zEqualsIgnoreCase).t(this.f5808n).r(this.f5800f).s(x.f(h(map, "content-type")));
                this.f5807m = aVarS;
                aVar.g(this.f5798d, aVarS);
            } else if (i3 == 2) {
                com.RNFetchBlob.a aVarS2 = new com.RNFetchBlob.a(this.f5797c).i(zEqualsIgnoreCase).t(this.f5808n).r(this.f5800f).s(x.f(h(map, "content-type")));
                this.f5807m = aVarS2;
                aVar.g(this.f5798d, aVarS2);
            } else if (i3 == 3) {
                com.RNFetchBlob.a aVarS3 = new com.RNFetchBlob.a(this.f5797c).i(zEqualsIgnoreCase).t(this.f5808n).q(this.f5802h).s(x.f("multipart/form-data; boundary=" + ("RNFetchBlob-" + this.f5797c)));
                this.f5807m = aVarS3;
                aVar.g(this.f5798d, aVarS3);
            } else if (i3 == 4) {
                if (this.f5798d.equalsIgnoreCase("post") || this.f5798d.equalsIgnoreCase("put") || this.f5798d.equalsIgnoreCase("patch")) {
                    aVar.g(this.f5798d, C.e(null, new byte[0]));
                } else {
                    aVar.g(this.f5798d, null);
                }
            }
            B b3 = aVar.b();
            aVarC.b(new a());
            aVarC.a(new b(b3));
            long j3 = this.f5796b.f5768k;
            if (j3 >= 0) {
                TimeUnit timeUnit = TimeUnit.MILLISECONDS;
                aVarC.f(j3, timeUnit);
                aVarC.S(this.f5796b.f5768k, timeUnit);
            }
            aVarC.g(f5795y);
            aVarC.T(false);
            aVarC.j(this.f5796b.f5770m.booleanValue());
            aVarC.k(this.f5796b.f5770m.booleanValue());
            aVarC.T(true);
            InterfaceC0167e interfaceC0167eA = f(aVarC).c().a(b3);
            f5791u.put(this.f5797c, interfaceC0167eA);
            interfaceC0167eA.p(new c());
        } catch (Exception e4) {
            e4.printStackTrace();
            m();
            this.f5804j.invoke("RNFetchBlob request error: " + e4.getMessage() + e4.getCause());
        }
    }

    public static z.a f(z.a aVar) {
        return aVar;
    }
}
