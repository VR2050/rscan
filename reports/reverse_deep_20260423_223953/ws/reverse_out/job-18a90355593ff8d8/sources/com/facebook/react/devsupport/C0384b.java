package com.facebook.react.devsupport;

import B2.B;
import B2.InterfaceC0167e;
import B2.InterfaceC0168f;
import com.facebook.react.devsupport.V;
import d1.C0507c;
import j1.InterfaceC0593b;
import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONException;
import org.json.JSONObject;

/* JADX INFO: renamed from: com.facebook.react.devsupport.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0384b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final B2.z f6799a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private InterfaceC0167e f6800b;

    /* JADX INFO: renamed from: com.facebook.react.devsupport.b$a */
    class a implements InterfaceC0168f {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ InterfaceC0593b f6801a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ File f6802b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ c f6803c;

        a(InterfaceC0593b interfaceC0593b, File file, c cVar) {
            this.f6801a = interfaceC0593b;
            this.f6802b = file;
            this.f6803c = cVar;
        }

        @Override // B2.InterfaceC0168f
        public void a(InterfaceC0167e interfaceC0167e, B2.D d3) {
            try {
                if (C0384b.this.f6800b != null && !C0384b.this.f6800b.r()) {
                    C0384b.this.f6800b = null;
                    String string = d3.y0().l().toString();
                    Matcher matcher = Pattern.compile("multipart/mixed;.*boundary=\"([^\"]+)\"").matcher(d3.W("content-type"));
                    if (matcher.find()) {
                        C0384b.this.i(string, d3, matcher.group(1), this.f6802b, this.f6803c, this.f6801a);
                    } else {
                        B2.E eR = d3.r();
                        try {
                            C0384b.this.h(string, d3.A(), d3.e0(), d3.r().y(), this.f6802b, this.f6803c, this.f6801a);
                            if (eR != null) {
                                eR.close();
                            }
                        } finally {
                        }
                    }
                    d3.close();
                    return;
                }
                C0384b.this.f6800b = null;
                if (d3 != null) {
                    d3.close();
                }
            } catch (Throwable th) {
                if (d3 != null) {
                    try {
                        d3.close();
                    } catch (Throwable th2) {
                        th.addSuppressed(th2);
                    }
                }
                throw th;
            }
        }

        @Override // B2.InterfaceC0168f
        public void b(InterfaceC0167e interfaceC0167e, IOException iOException) {
            if (C0384b.this.f6800b == null || C0384b.this.f6800b.r()) {
                C0384b.this.f6800b = null;
                return;
            }
            C0384b.this.f6800b = null;
            String string = interfaceC0167e.i().l().toString();
            this.f6801a.c(C0507c.b(string, "Could not connect to development server.", "URL: " + string, iOException));
        }
    }

    /* JADX INFO: renamed from: com.facebook.react.devsupport.b$b, reason: collision with other inner class name */
    class C0104b implements V.a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ B2.D f6805a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ String f6806b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ File f6807c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ c f6808d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ InterfaceC0593b f6809e;

        C0104b(B2.D d3, String str, File file, c cVar, InterfaceC0593b interfaceC0593b) {
            this.f6805a = d3;
            this.f6806b = str;
            this.f6807c = file;
            this.f6808d = cVar;
            this.f6809e = interfaceC0593b;
        }

        @Override // com.facebook.react.devsupport.V.a
        public void a(Map map, long j3, long j4) {
            if ("application/javascript".equals(map.get("Content-Type"))) {
                this.f6809e.b("Downloading", Integer.valueOf((int) (j3 / 1024)), Integer.valueOf((int) (j4 / 1024)));
            }
        }

        @Override // com.facebook.react.devsupport.V.a
        public void b(Map map, Q2.i iVar, boolean z3) throws IOException {
            if (z3) {
                int iA = this.f6805a.A();
                if (map.containsKey("X-Http-Status")) {
                    iA = Integer.parseInt((String) map.get("X-Http-Status"));
                }
                C0384b.this.h(this.f6806b, iA, B2.t.f(map), iVar, this.f6807c, this.f6808d, this.f6809e);
                return;
            }
            if (map.containsKey("Content-Type") && ((String) map.get("Content-Type")).equals("application/json")) {
                try {
                    JSONObject jSONObject = new JSONObject(iVar.O());
                    this.f6809e.b(jSONObject.has("status") ? jSONObject.getString("status") : "Bundling", jSONObject.has("done") ? Integer.valueOf(jSONObject.getInt("done")) : null, jSONObject.has("total") ? Integer.valueOf(jSONObject.getInt("total")) : null);
                } catch (JSONException e3) {
                    Y.a.m("ReactNative", "Error parsing progress JSON. " + e3.toString());
                }
            }
        }
    }

    /* JADX INFO: renamed from: com.facebook.react.devsupport.b$c */
    public static class c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private String f6811a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private int f6812b;

        public String c() {
            JSONObject jSONObject = new JSONObject();
            try {
                jSONObject.put("url", this.f6811a);
                jSONObject.put("filesChangedCount", this.f6812b);
                return jSONObject.toString();
            } catch (JSONException e3) {
                Y.a.n("BundleDownloader", "Can't serialize bundle info: ", e3);
                return null;
            }
        }
    }

    public C0384b(B2.z zVar) {
        this.f6799a = zVar;
    }

    private static void g(String str, B2.t tVar, c cVar) {
        cVar.f6811a = str;
        String strA = tVar.a("X-Metro-Files-Changed-Count");
        if (strA != null) {
            try {
                cVar.f6812b = Integer.parseInt(strA);
            } catch (NumberFormatException unused) {
                cVar.f6812b = -2;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void h(String str, int i3, B2.t tVar, Q2.k kVar, File file, c cVar, InterfaceC0593b interfaceC0593b) throws IOException {
        if (i3 != 200) {
            String strO = kVar.O();
            C0507c c0507cD = C0507c.d(str, strO);
            if (c0507cD != null) {
                interfaceC0593b.c(c0507cD);
                return;
            }
            interfaceC0593b.c(new C0507c("The development server returned response error code: " + i3 + "\n\nURL: " + str + "\n\nBody:\n" + strO));
            return;
        }
        if (cVar != null) {
            g(str, tVar, cVar);
        }
        File file2 = new File(file.getPath() + ".tmp");
        if (!j(kVar, file2) || file2.renameTo(file)) {
            interfaceC0593b.a();
            return;
        }
        throw new IOException("Couldn't rename " + file2 + " to " + file);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void i(String str, B2.D d3, String str2, File file, c cVar, InterfaceC0593b interfaceC0593b) {
        if (new V(d3.r().y(), str2).d(new C0104b(d3, str, file, cVar, interfaceC0593b))) {
            return;
        }
        interfaceC0593b.c(new C0507c("Error while reading multipart response.\n\nResponse code: " + d3.A() + "\n\nURL: " + str.toString() + "\n\n"));
    }

    private static boolean j(Q2.k kVar, File file) throws Throwable {
        Q2.D dF;
        try {
            dF = Q2.t.f(file);
        } catch (Throwable th) {
            th = th;
            dF = null;
        }
        try {
            kVar.h0(dF);
            if (dF == null) {
                return true;
            }
            dF.close();
            return true;
        } catch (Throwable th2) {
            th = th2;
            if (dF != null) {
                dF.close();
            }
            throw th;
        }
    }

    public void e(InterfaceC0593b interfaceC0593b, File file, String str, c cVar) {
        f(interfaceC0593b, file, str, cVar, new B.a());
    }

    public void f(InterfaceC0593b interfaceC0593b, File file, String str, c cVar, B.a aVar) {
        InterfaceC0167e interfaceC0167e = (InterfaceC0167e) Z0.a.c(this.f6799a.a(aVar.m(str).a("Accept", "multipart/mixed").b()));
        this.f6800b = interfaceC0167e;
        interfaceC0167e.p(new a(interfaceC0593b, file, cVar));
    }
}
