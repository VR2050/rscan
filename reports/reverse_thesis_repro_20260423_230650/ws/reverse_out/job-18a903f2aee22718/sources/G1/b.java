package G1;

import G1.e;
import Q2.l;
import android.net.Uri;
import java.util.Map;
import org.json.JSONObject;

/* JADX INFO: loaded from: classes.dex */
public final class b implements e.c {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static final String f852c = "b";

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private e f853a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private Map f854b;

    private class a implements h {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private Object f855a;

        public a(Object obj) {
            this.f855a = obj;
        }

        @Override // G1.h
        public void a(Object obj) {
            try {
                JSONObject jSONObject = new JSONObject();
                jSONObject.put("version", 2);
                jSONObject.put("id", this.f855a);
                jSONObject.put("result", obj);
                b.this.f853a.n(jSONObject.toString());
            } catch (Exception e3) {
                Y.a.n(b.f852c, "Responding failed", e3);
            }
        }

        @Override // G1.h
        public void b(Object obj) {
            try {
                JSONObject jSONObject = new JSONObject();
                jSONObject.put("version", 2);
                jSONObject.put("id", this.f855a);
                jSONObject.put("error", obj);
                b.this.f853a.n(jSONObject.toString());
            } catch (Exception e3) {
                Y.a.n(b.f852c, "Responding with error failed", e3);
            }
        }
    }

    public b(String str, d dVar, Map map, e.b bVar) {
        Uri.Builder builder = new Uri.Builder();
        builder.scheme("ws").encodedAuthority(dVar.b()).appendPath("message").appendQueryParameter("device", com.facebook.react.modules.systeminfo.a.d()).appendQueryParameter("app", dVar.c()).appendQueryParameter("clientid", str);
        this.f853a = new e(builder.build().toString(), this, bVar);
        this.f854b = map;
    }

    private void d(Object obj, String str) {
        if (obj != null) {
            new a(obj).b(str);
        }
        Y.a.m(f852c, "Handling the message failed with reason: " + str);
    }

    @Override // G1.e.c
    public void a(l lVar) {
        Y.a.I(f852c, "Websocket received message with payload of unexpected type binary");
    }

    public void e() {
        this.f853a.i();
    }

    public void f() {
        this.f853a.k();
    }

    @Override // G1.e.c
    public void onMessage(String str) {
        try {
            JSONObject jSONObject = new JSONObject(str);
            int iOptInt = jSONObject.optInt("version");
            String strOptString = jSONObject.optString("method");
            Object objOpt = jSONObject.opt("id");
            Object objOpt2 = jSONObject.opt("params");
            if (iOptInt != 2) {
                Y.a.m(f852c, "Message with incompatible or missing version of protocol received: " + iOptInt);
                return;
            }
            if (strOptString == null) {
                d(objOpt, "No method provided");
                return;
            }
            f fVar = (f) this.f854b.get(strOptString);
            if (fVar == null) {
                d(objOpt, "No request handler for method: " + strOptString);
                return;
            }
            if (objOpt == null) {
                fVar.b(objOpt2);
            } else {
                fVar.a(objOpt2, new a(objOpt));
            }
        } catch (Exception e3) {
            Y.a.n(f852c, "Handling the message failed", e3);
        }
    }
}
