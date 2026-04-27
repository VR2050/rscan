package com.facebook.react.devsupport;

import B2.B;
import B2.InterfaceC0167e;
import B2.InterfaceC0168f;
import B2.z;
import G1.e;
import android.content.Context;
import android.net.Uri;
import android.os.AsyncTask;
import android.provider.Settings;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.devsupport.C0384b;
import j1.InterfaceC0593b;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/* JADX INFO: renamed from: com.facebook.react.devsupport.k, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0393k {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final B1.a f6864a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final G1.d f6865b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final B2.z f6866c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final C0384b f6867d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final W f6868e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final Context f6869f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final String f6870g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private G1.b f6871h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private M f6872i;

    /* JADX INFO: renamed from: com.facebook.react.devsupport.k$a */
    class a extends AsyncTask {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ g f6873a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ String f6874b;

        /* JADX INFO: renamed from: com.facebook.react.devsupport.k$a$a, reason: collision with other inner class name */
        class C0108a extends G1.c {
            C0108a() {
            }

            @Override // G1.f
            public void b(Object obj) {
                a.this.f6873a.e();
            }
        }

        /* JADX INFO: renamed from: com.facebook.react.devsupport.k$a$b */
        class b extends G1.c {
            b() {
            }

            @Override // G1.f
            public void b(Object obj) {
                a.this.f6873a.c();
            }
        }

        /* JADX INFO: renamed from: com.facebook.react.devsupport.k$a$c */
        class c implements e.b {
            c() {
            }

            @Override // G1.e.b
            public void a() {
                a.this.f6873a.a();
            }

            @Override // G1.e.b
            public void b() {
                a.this.f6873a.b();
            }
        }

        a(g gVar, String str) {
            this.f6873a = gVar;
            this.f6874b = str;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public Void doInBackground(Void... voidArr) {
            HashMap map = new HashMap();
            map.put("reload", new C0108a());
            map.put("devMenu", new b());
            Map mapD = this.f6873a.d();
            if (mapD != null) {
                map.putAll(mapD);
            }
            map.putAll(new G1.a().d());
            c cVar = new c();
            C0393k.this.f6871h = new G1.b(this.f6874b, C0393k.this.f6865b, map, cVar);
            C0393k.this.f6871h.f();
            return null;
        }
    }

    /* JADX INFO: renamed from: com.facebook.react.devsupport.k$b */
    class b extends AsyncTask {
        b() {
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public Void doInBackground(Void... voidArr) {
            if (C0393k.this.f6871h != null) {
                C0393k.this.f6871h.e();
                C0393k.this.f6871h = null;
            }
            return null;
        }
    }

    /* JADX INFO: renamed from: com.facebook.react.devsupport.k$c */
    class c extends AsyncTask {
        c() {
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public Void doInBackground(Void... voidArr) {
            Map mapE = com.facebook.react.modules.systeminfo.a.e(C0393k.this.f6869f);
            C0393k.this.f6872i = new CxxInspectorPackagerConnection(C0393k.this.s(), (String) mapE.get("deviceName"), C0393k.this.f6870g);
            C0393k.this.f6872i.connect();
            return null;
        }
    }

    /* JADX INFO: renamed from: com.facebook.react.devsupport.k$d */
    class d extends AsyncTask {
        d() {
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public Void doInBackground(Void... voidArr) {
            if (C0393k.this.f6872i != null) {
                C0393k.this.f6872i.closeQuietly();
                C0393k.this.f6872i = null;
            }
            return null;
        }
    }

    /* JADX INFO: renamed from: com.facebook.react.devsupport.k$f */
    private enum f {
        BUNDLE("bundle"),
        MAP("map");


        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final String f6888b;

        f(String str) {
            this.f6888b = str;
        }

        public String b() {
            return this.f6888b;
        }
    }

    /* JADX INFO: renamed from: com.facebook.react.devsupport.k$g */
    public interface g {
        void a();

        void b();

        void c();

        Map d();

        void e();
    }

    public C0393k(B1.a aVar, Context context, G1.d dVar) {
        this.f6864a = aVar;
        this.f6865b = dVar;
        z.a aVar2 = new z.a();
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        B2.z zVarC = aVar2.f(5000L, timeUnit).S(0L, timeUnit).W(0L, timeUnit).c();
        this.f6866c = zVarC;
        this.f6867d = new C0384b(zVarC);
        this.f6868e = new W(zVarC);
        this.f6869f = context;
        this.f6870g = context.getPackageName();
    }

    private String k(String str, f fVar) {
        return l(str, fVar, this.f6865b.b());
    }

    private String l(String str, f fVar, String str2) {
        return m(str, fVar, str2, false, true);
    }

    private String m(String str, f fVar, String str2, boolean z3, boolean z4) {
        boolean zP = p();
        StringBuilder sb = new StringBuilder();
        for (Map.Entry entry : this.f6865b.a().entrySet()) {
            if (((String) entry.getValue()).length() != 0) {
                sb.append("&" + ((String) entry.getKey()) + "=" + Uri.encode((String) entry.getValue()));
            }
        }
        StringBuilder sb2 = new StringBuilder();
        sb2.append(String.format(Locale.US, "http://%s/%s.%s?platform=android&dev=%s&lazy=%s&minify=%s&app=%s&modulesOnly=%s&runModule=%s", str2, str, fVar.b(), Boolean.valueOf(zP), Boolean.valueOf(zP), Boolean.valueOf(t()), this.f6870g, z3 ? "true" : "false", z4 ? "true" : "false"));
        sb2.append(InspectorFlags.getFuseboxEnabled() ? "&excludeSource=true&sourcePaths=url-server" : "");
        sb2.append(sb.toString());
        return sb2.toString();
    }

    private boolean p() {
        return this.f6864a.m();
    }

    private String r() {
        return u(String.format(Locale.US, "android-%s-%s-%s", this.f6870g, Settings.Secure.getString(this.f6869f.getContentResolver(), "android_id"), InspectorFlags.getFuseboxEnabled() ? "fusebox" : "legacy"));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public String s() {
        return String.format(Locale.US, "http://%s/inspector/device?name=%s&app=%s&device=%s&profiling=%b", this.f6865b.b(), Uri.encode(com.facebook.react.modules.systeminfo.a.d()), Uri.encode(this.f6870g), Uri.encode(r()), Boolean.valueOf(InspectorFlags.getIsProfilingBuild()));
    }

    private boolean t() {
        return this.f6864a.k();
    }

    private static String u(String str) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.reset();
            try {
                byte[] bArrDigest = messageDigest.digest(str.getBytes("UTF-8"));
                return String.format("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", Byte.valueOf(bArrDigest[0]), Byte.valueOf(bArrDigest[1]), Byte.valueOf(bArrDigest[2]), Byte.valueOf(bArrDigest[3]), Byte.valueOf(bArrDigest[4]), Byte.valueOf(bArrDigest[5]), Byte.valueOf(bArrDigest[6]), Byte.valueOf(bArrDigest[7]), Byte.valueOf(bArrDigest[8]), Byte.valueOf(bArrDigest[9]), Byte.valueOf(bArrDigest[10]), Byte.valueOf(bArrDigest[11]), Byte.valueOf(bArrDigest[12]), Byte.valueOf(bArrDigest[13]), Byte.valueOf(bArrDigest[14]), Byte.valueOf(bArrDigest[15]), Byte.valueOf(bArrDigest[16]), Byte.valueOf(bArrDigest[17]), Byte.valueOf(bArrDigest[18]), Byte.valueOf(bArrDigest[19]));
            } catch (UnsupportedEncodingException e3) {
                throw new AssertionError("This environment doesn't support UTF-8 encoding", e3);
            }
        } catch (NoSuchAlgorithmException e4) {
            throw new AssertionError("Could not get standard SHA-256 algorithm", e4);
        }
    }

    public void i() {
        new d().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, new Void[0]);
    }

    public void j() {
        new b().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, new Void[0]);
    }

    public void n() {
        M m3 = this.f6872i;
        if (m3 != null) {
            m3.sendEventToAllConnections("{ \"id\":1,\"method\":\"Debugger.disable\" }");
        }
    }

    public void o(InterfaceC0593b interfaceC0593b, File file, String str, C0384b.c cVar) {
        this.f6867d.e(interfaceC0593b, file, str, cVar);
    }

    public String q(String str) {
        return l(str, f.BUNDLE, this.f6865b.b());
    }

    public String v(String str) {
        return k(str, f.BUNDLE);
    }

    public void w(j1.g gVar) {
        String strB = this.f6865b.b();
        if (strB != null) {
            this.f6868e.a(strB, gVar);
        } else {
            Y.a.I("ReactNative", "No packager host configured.");
            gVar.a(false);
        }
    }

    public void x(ReactContext reactContext, String str) {
        this.f6866c.a(new B.a().m(String.format(Locale.US, "http://%s/open-debugger?device=%s", this.f6865b.b(), Uri.encode(r()))).g("POST", B2.C.d(null, "")).b()).p(new e(reactContext, str));
    }

    public void y() {
        if (this.f6872i != null) {
            Y.a.I("ReactNative", "Inspector connection already open, nooping.");
        } else {
            new c().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, new Void[0]);
        }
    }

    public void z(String str, g gVar) {
        if (this.f6871h != null) {
            Y.a.I("ReactNative", "Packager connection already open, nooping.");
        } else {
            new a(gVar, str).executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, new Void[0]);
        }
    }

    /* JADX INFO: renamed from: com.facebook.react.devsupport.k$e */
    class e implements InterfaceC0168f {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ ReactContext f6882a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ String f6883b;

        e(ReactContext reactContext, String str) {
            this.f6882a = reactContext;
            this.f6883b = str;
        }

        @Override // B2.InterfaceC0168f
        public void b(InterfaceC0167e interfaceC0167e, IOException iOException) {
            S1.c.d(this.f6882a, this.f6883b);
        }

        @Override // B2.InterfaceC0168f
        public void a(InterfaceC0167e interfaceC0167e, B2.D d3) {
        }
    }
}
