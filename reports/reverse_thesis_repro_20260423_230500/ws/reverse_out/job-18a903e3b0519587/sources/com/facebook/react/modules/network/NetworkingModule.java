package com.facebook.react.modules.network;

import B2.C;
import B2.D;
import B2.E;
import B2.InterfaceC0167e;
import B2.InterfaceC0168f;
import B2.t;
import B2.v;
import B2.w;
import B2.x;
import B2.y;
import B2.z;
import Q2.q;
import Q2.t;
import android.net.Uri;
import android.os.Bundle;
import android.util.Base64;
import com.facebook.fbreact.specs.NativeNetworkingAndroidSpec;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import h1.C0554a;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import u1.InterfaceC0703a;

/* JADX INFO: loaded from: classes.dex */
@InterfaceC0703a(name = "Networking")
public final class NetworkingModule extends NativeNetworkingAndroidSpec {
    private static final int CHUNK_TIMEOUT_NS = 100000000;
    private static final String CONTENT_ENCODING_HEADER_NAME = "content-encoding";
    private static final String CONTENT_TYPE_HEADER_NAME = "content-type";
    private static final int MAX_CHUNK_SIZE_BETWEEN_FLUSHES = 8192;
    private static final String REQUEST_BODY_KEY_BASE64 = "base64";
    private static final String REQUEST_BODY_KEY_FORMDATA = "formData";
    private static final String REQUEST_BODY_KEY_STRING = "string";
    private static final String REQUEST_BODY_KEY_URI = "uri";
    private static final String TAG = "Networking";
    private static final String USER_AGENT_HEADER_NAME = "user-agent";
    private static com.facebook.react.modules.network.b customClientBuilder;
    private final z mClient;
    private final com.facebook.react.modules.network.d mCookieHandler;
    private final com.facebook.react.modules.network.a mCookieJarContainer;
    private final String mDefaultUserAgent;
    private final List<d> mRequestBodyHandlers;
    private final Set<Integer> mRequestIds;
    private final List<e> mResponseHandlers;
    private boolean mShuttingDown;
    private final List<f> mUriHandlers;

    class a implements i {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        long f7115a = System.nanoTime();

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ String f7116b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ ReactApplicationContext f7117c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ int f7118d;

        a(String str, ReactApplicationContext reactApplicationContext, int i3) {
            this.f7116b = str;
            this.f7117c = reactApplicationContext;
            this.f7118d = i3;
        }

        @Override // com.facebook.react.modules.network.i
        public void a(long j3, long j4, boolean z3) {
            long jNanoTime = System.nanoTime();
            if ((z3 || NetworkingModule.shouldDispatch(jNanoTime, this.f7115a)) && !this.f7116b.equals("text")) {
                o.c(this.f7117c, this.f7118d, j3, j4);
                this.f7115a = jNanoTime;
            }
        }
    }

    class b implements InterfaceC0168f {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ int f7120a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ ReactApplicationContext f7121b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ String f7122c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ boolean f7123d;

        b(int i3, ReactApplicationContext reactApplicationContext, String str, boolean z3) {
            this.f7120a = i3;
            this.f7121b = reactApplicationContext;
            this.f7122c = str;
            this.f7123d = z3;
        }

        @Override // B2.InterfaceC0168f
        public void a(InterfaceC0167e interfaceC0167e, D d3) {
            if (NetworkingModule.this.mShuttingDown) {
                return;
            }
            NetworkingModule.this.removeRequest(this.f7120a);
            o.h(this.f7121b, this.f7120a, d3.A(), NetworkingModule.translateHeaders(d3.e0()), d3.y0().l().toString());
            try {
                E eR = d3.r();
                if ("gzip".equalsIgnoreCase(d3.W("Content-Encoding")) && eR != null) {
                    q qVar = new q(eR.y());
                    String strW = d3.W("Content-Type");
                    eR = E.x(strW != null ? x.f(strW) : null, -1L, t.d(qVar));
                }
                for (e eVar : NetworkingModule.this.mResponseHandlers) {
                    if (eVar.b(this.f7122c)) {
                        o.a(this.f7121b, this.f7120a, eVar.a(eR));
                        o.g(this.f7121b, this.f7120a);
                        return;
                    }
                }
                if (this.f7123d && this.f7122c.equals("text")) {
                    NetworkingModule.this.readWithProgress(this.f7120a, eR);
                    o.g(this.f7121b, this.f7120a);
                    return;
                }
                String strA = "";
                if (this.f7122c.equals("text")) {
                    try {
                        strA = eR.A();
                    } catch (IOException e3) {
                        if (!d3.y0().h().equalsIgnoreCase("HEAD")) {
                            o.f(this.f7121b, this.f7120a, e3.getMessage(), e3);
                        }
                    }
                } else if (this.f7122c.equals(NetworkingModule.REQUEST_BODY_KEY_BASE64)) {
                    strA = Base64.encodeToString(eR.i(), 2);
                }
                o.b(this.f7121b, this.f7120a, strA);
                o.g(this.f7121b, this.f7120a);
            } catch (IOException e4) {
                o.f(this.f7121b, this.f7120a, e4.getMessage(), e4);
            }
        }

        @Override // B2.InterfaceC0168f
        public void b(InterfaceC0167e interfaceC0167e, IOException iOException) {
            String message;
            if (NetworkingModule.this.mShuttingDown) {
                return;
            }
            NetworkingModule.this.removeRequest(this.f7120a);
            if (iOException.getMessage() != null) {
                message = iOException.getMessage();
            } else {
                message = "Error while executing request: " + iOException.getClass().getSimpleName();
            }
            o.f(this.f7121b, this.f7120a, message, iOException);
        }
    }

    class c implements i {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        long f7125a = System.nanoTime();

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ ReactApplicationContext f7126b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ int f7127c;

        c(ReactApplicationContext reactApplicationContext, int i3) {
            this.f7126b = reactApplicationContext;
            this.f7127c = i3;
        }

        @Override // com.facebook.react.modules.network.i
        public void a(long j3, long j4, boolean z3) {
            long jNanoTime = System.nanoTime();
            if (z3 || NetworkingModule.shouldDispatch(jNanoTime, this.f7125a)) {
                o.d(this.f7126b, this.f7127c, j3, j4);
                this.f7125a = jNanoTime;
            }
        }
    }

    public interface d {
        boolean a(ReadableMap readableMap);

        C b(ReadableMap readableMap, String str);
    }

    public interface e {
        WritableMap a(E e3);

        boolean b(String str);
    }

    public interface f {
        WritableMap a(Uri uri);

        boolean b(Uri uri, String str);
    }

    public NetworkingModule(ReactApplicationContext reactApplicationContext, String str, z zVar, List<Object> list) {
        super(reactApplicationContext);
        this.mCookieHandler = new com.facebook.react.modules.network.d();
        this.mRequestIds = new HashSet();
        this.mRequestBodyHandlers = new ArrayList();
        this.mUriHandlers = new ArrayList();
        this.mResponseHandlers = new ArrayList();
        this.mShuttingDown = false;
        if (list != null) {
            z.a aVarC = zVar.C();
            Iterator<Object> it = list.iterator();
            if (it.hasNext()) {
                androidx.activity.result.d.a(it.next());
                throw null;
            }
            zVar = aVarC.c();
        }
        this.mClient = zVar;
        if (zVar.q() instanceof com.facebook.react.modules.network.a) {
            this.mCookieJarContainer = (com.facebook.react.modules.network.a) zVar.q();
        } else {
            this.mCookieJarContainer = null;
        }
        this.mDefaultUserAgent = str;
    }

    private synchronized void addRequest(int i3) {
        this.mRequestIds.add(Integer.valueOf(i3));
    }

    private synchronized void cancelAllRequests() {
        try {
            Iterator<Integer> it = this.mRequestIds.iterator();
            while (it.hasNext()) {
                cancelRequest(it.next().intValue());
            }
            this.mRequestIds.clear();
        } catch (Throwable th) {
            throw th;
        }
    }

    private void cancelRequest(int i3) {
        C0554a.a(this.mClient, Integer.valueOf(i3));
    }

    private y.a constructMultipartBody(ReadableArray readableArray, String str, int i3) {
        x xVarF;
        y.a aVar = new y.a();
        aVar.d(x.f(str));
        ReactApplicationContext reactApplicationContextIfActiveOrWarn = getReactApplicationContextIfActiveOrWarn();
        int size = readableArray.size();
        for (int i4 = 0; i4 < size; i4++) {
            ReadableMap map = readableArray.getMap(i4);
            B2.t tVarExtractHeaders = extractHeaders(map.getArray("headers"), null);
            if (tVarExtractHeaders == null) {
                o.f(reactApplicationContextIfActiveOrWarn, i3, "Missing or invalid header format for FormData part.", null);
                return null;
            }
            String strA = tVarExtractHeaders.a(CONTENT_TYPE_HEADER_NAME);
            if (strA != null) {
                xVarF = x.f(strA);
                tVarExtractHeaders = tVarExtractHeaders.e().h(CONTENT_TYPE_HEADER_NAME).e();
            } else {
                xVarF = null;
            }
            if (map.hasKey(REQUEST_BODY_KEY_STRING)) {
                aVar.a(tVarExtractHeaders, C.d(xVarF, map.getString(REQUEST_BODY_KEY_STRING)));
            } else if (!map.hasKey(REQUEST_BODY_KEY_URI)) {
                o.f(reactApplicationContextIfActiveOrWarn, i3, "Unrecognized FormData part.", null);
            } else {
                if (xVarF == null) {
                    o.f(reactApplicationContextIfActiveOrWarn, i3, "Binary FormData part needs a content-type header.", null);
                    return null;
                }
                String string = map.getString(REQUEST_BODY_KEY_URI);
                InputStream inputStreamH = n.h(getReactApplicationContext(), string);
                if (inputStreamH == null) {
                    o.f(reactApplicationContextIfActiveOrWarn, i3, "Could not retrieve file for uri " + string, null);
                    return null;
                }
                aVar.a(tVarExtractHeaders, n.c(xVarF, inputStreamH));
            }
        }
        return aVar;
    }

    private B2.t extractHeaders(ReadableArray readableArray, ReadableMap readableMap) {
        String str;
        if (readableArray == null) {
            return null;
        }
        t.a aVar = new t.a();
        int size = readableArray.size();
        for (int i3 = 0; i3 < size; i3++) {
            ReadableArray array = readableArray.getArray(i3);
            if (array != null && array.size() == 2) {
                String strA = com.facebook.react.modules.network.e.a(array.getString(0));
                String string = array.getString(1);
                if (strA != null && string != null) {
                    aVar.d(strA, string);
                }
            }
            return null;
        }
        if (aVar.f(USER_AGENT_HEADER_NAME) == null && (str = this.mDefaultUserAgent) != null) {
            aVar.a(USER_AGENT_HEADER_NAME, str);
        }
        if (readableMap == null || !readableMap.hasKey(REQUEST_BODY_KEY_STRING)) {
            aVar.h(CONTENT_ENCODING_HEADER_NAME);
        }
        return aVar.e();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ D lambda$sendRequestInternal$0(String str, ReactApplicationContext reactApplicationContext, int i3, v.a aVar) {
        D dA = aVar.a(aVar.i());
        return dA.u0().b(new k(dA.r(), new a(str, reactApplicationContext, i3))).c();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void readWithProgress(int i3, E e3) throws IOException {
        long jE0;
        long jR = -1;
        try {
            k kVar = (k) e3;
            jE0 = kVar.e0();
            try {
                jR = kVar.r();
            } catch (ClassCastException unused) {
            }
        } catch (ClassCastException unused2) {
            jE0 = -1;
        }
        l lVar = new l(e3.v() == null ? StandardCharsets.UTF_8 : e3.v().c(StandardCharsets.UTF_8));
        InputStream inputStreamB = e3.b();
        try {
            byte[] bArr = new byte[MAX_CHUNK_SIZE_BETWEEN_FLUSHES];
            ReactApplicationContext reactApplicationContextIfActiveOrWarn = getReactApplicationContextIfActiveOrWarn();
            while (true) {
                int i4 = inputStreamB.read(bArr);
                if (i4 == -1) {
                    return;
                } else {
                    o.e(reactApplicationContextIfActiveOrWarn, i3, lVar.a(bArr, i4), jE0, jR);
                }
            }
        } finally {
            inputStreamB.close();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public synchronized void removeRequest(int i3) {
        this.mRequestIds.remove(Integer.valueOf(i3));
    }

    public static void setCustomClientBuilder(com.facebook.react.modules.network.b bVar) {
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static boolean shouldDispatch(long j3, long j4) {
        return j4 + 100000000 < j3;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static WritableMap translateHeaders(B2.t tVar) {
        Bundle bundle = new Bundle();
        for (int i3 = 0; i3 < tVar.size(); i3++) {
            String strB = tVar.b(i3);
            if (bundle.containsKey(strB)) {
                bundle.putString(strB, bundle.getString(strB) + ", " + tVar.h(i3));
            } else {
                bundle.putString(strB, tVar.h(i3));
            }
        }
        return Arguments.fromBundle(bundle);
    }

    private C wrapRequestBodyWithProgressEmitter(C c3, int i3) {
        if (c3 == null) {
            return null;
        }
        return n.e(c3, new c(getReactApplicationContextIfActiveOrWarn(), i3));
    }

    @Override // com.facebook.fbreact.specs.NativeNetworkingAndroidSpec
    public void abortRequest(double d3) {
        int i3 = (int) d3;
        cancelRequest(i3);
        removeRequest(i3);
    }

    @Override // com.facebook.fbreact.specs.NativeNetworkingAndroidSpec
    public void addListener(String str) {
    }

    public void addRequestBodyHandler(d dVar) {
        this.mRequestBodyHandlers.add(dVar);
    }

    public void addResponseHandler(e eVar) {
        this.mResponseHandlers.add(eVar);
    }

    public void addUriHandler(f fVar) {
        this.mUriHandlers.add(fVar);
    }

    @Override // com.facebook.fbreact.specs.NativeNetworkingAndroidSpec
    @ReactMethod
    public void clearCookies(Callback callback) {
        this.mCookieHandler.d(callback);
    }

    @Override // com.facebook.react.bridge.BaseJavaModule, com.facebook.react.bridge.NativeModule, com.facebook.react.turbomodule.core.interfaces.TurboModule
    public void initialize() {
        com.facebook.react.modules.network.a aVar = this.mCookieJarContainer;
        if (aVar != null) {
            aVar.d(new w(this.mCookieHandler));
        }
    }

    @Override // com.facebook.react.bridge.BaseJavaModule, com.facebook.react.bridge.NativeModule, com.facebook.react.turbomodule.core.interfaces.TurboModule
    public void invalidate() {
        this.mShuttingDown = true;
        cancelAllRequests();
        this.mCookieHandler.f();
        com.facebook.react.modules.network.a aVar = this.mCookieJarContainer;
        if (aVar != null) {
            aVar.a();
        }
        this.mRequestBodyHandlers.clear();
        this.mResponseHandlers.clear();
        this.mUriHandlers.clear();
    }

    @Override // com.facebook.fbreact.specs.NativeNetworkingAndroidSpec
    public void removeListeners(double d3) {
    }

    public void removeRequestBodyHandler(d dVar) {
        this.mRequestBodyHandlers.remove(dVar);
    }

    public void removeResponseHandler(e eVar) {
        this.mResponseHandlers.remove(eVar);
    }

    public void removeUriHandler(f fVar) {
        this.mUriHandlers.remove(fVar);
    }

    @Override // com.facebook.fbreact.specs.NativeNetworkingAndroidSpec
    public void sendRequest(String str, String str2, double d3, ReadableArray readableArray, ReadableMap readableMap, String str3, boolean z3, double d4, boolean z4) {
        int i3 = (int) d3;
        try {
            sendRequestInternal(str, str2, i3, readableArray, readableMap, str3, z3, (int) d4, z4);
        } catch (Throwable th) {
            Y.a.n("Networking", "Failed to send url request: " + str2, th);
            o.f(getReactApplicationContextIfActiveOrWarn(), i3, th.getMessage(), th);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:85:0x0183  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void sendRequestInternal(java.lang.String r7, java.lang.String r8, final int r9, com.facebook.react.bridge.ReadableArray r10, com.facebook.react.bridge.ReadableMap r11, final java.lang.String r12, boolean r13, int r14, boolean r15) {
        /*
            Method dump skipped, instruction units count: 440
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.react.modules.network.NetworkingModule.sendRequestInternal(java.lang.String, java.lang.String, int, com.facebook.react.bridge.ReadableArray, com.facebook.react.bridge.ReadableMap, java.lang.String, boolean, int, boolean):void");
    }

    NetworkingModule(ReactApplicationContext reactApplicationContext, String str, z zVar) {
        this(reactApplicationContext, str, zVar, null);
    }

    public NetworkingModule(ReactApplicationContext reactApplicationContext) {
        this(reactApplicationContext, null, g.b(reactApplicationContext), null);
    }

    public NetworkingModule(ReactApplicationContext reactApplicationContext, List<Object> list) {
        this(reactApplicationContext, null, g.b(reactApplicationContext), list);
    }

    public NetworkingModule(ReactApplicationContext reactApplicationContext, String str) {
        this(reactApplicationContext, str, g.b(reactApplicationContext), null);
    }

    private static void applyCustomBuilder(z.a aVar) {
    }
}
