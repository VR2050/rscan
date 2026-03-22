package p448i.p449a.p450a;

import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.WeakHashMap;
import kotlin.jvm.internal.Intrinsics;
import p005b.p131d.p132a.p133a.C1499a;
import p448i.p449a.p450a.p451c.C4350a;
import p448i.p449a.p450a.p451c.C4352c;
import p458k.C4381g0;
import p458k.C4389k0;
import p458k.C4487x;
import p458k.C4488y;
import p458k.EnumC4377e0;
import p458k.InterfaceC4369a0;
import p458k.p459p0.p462f.C4413c;
import p458k.p459p0.p463g.C4430g;

/* renamed from: i.a.a.b */
/* loaded from: classes2.dex */
public final class C4349b {

    /* renamed from: a */
    public static volatile C4349b f11208a;

    /* renamed from: b */
    public static final boolean f11209b;

    /* renamed from: c */
    public final Map<String, List<InterfaceC4348a>> f11210c = new WeakHashMap();

    /* renamed from: d */
    public final Map<String, List<InterfaceC4348a>> f11211d = new WeakHashMap();

    /* renamed from: g */
    public int f11214g = 150;

    /* renamed from: e */
    public final Handler f11212e = new Handler(Looper.getMainLooper());

    /* renamed from: f */
    public final InterfaceC4369a0 f11213f = new a();

    /* renamed from: i.a.a.b$a */
    public class a implements InterfaceC4369a0 {
        public a() {
        }

        @Override // p458k.InterfaceC4369a0
        /* renamed from: a */
        public C4389k0 mo280a(InterfaceC4369a0.a aVar) {
            C4349b c4349b = C4349b.this;
            C4430g c4430g = (C4430g) aVar;
            C4381g0 c4381g0 = c4430g.f11739f;
            Objects.requireNonNull(c4349b);
            if (c4381g0 != null) {
                String str = c4381g0.f11440b.f12054l;
                if (str.contains("?JessYan=")) {
                    C4381g0.a aVar2 = new C4381g0.a(c4381g0);
                    aVar2.m4978h(str.substring(0, str.indexOf("?JessYan=")));
                    aVar2.m4973c("JessYan", str);
                    c4381g0 = aVar2.m4972b();
                }
                if (c4381g0.f11443e != null && c4349b.f11210c.containsKey(str)) {
                    List<InterfaceC4348a> list = c4349b.f11210c.get(str);
                    C4381g0.a aVar3 = new C4381g0.a(c4381g0);
                    aVar3.m4975e(c4381g0.f11441c, new C4350a(c4349b.f11212e, c4381g0.f11443e, list, c4349b.f11214g));
                    c4381g0 = aVar3.m4972b();
                }
            }
            C4389k0 response = c4430g.m5139d(c4381g0);
            C4381g0 c4381g02 = response.f11485e;
            String str2 = c4381g02.f11440b.f12054l;
            if (!TextUtils.isEmpty(c4381g02.m4970b("JessYan"))) {
                str2 = response.f11485e.m4970b("JessYan");
            }
            String valueOf = String.valueOf(response.f11488h);
            if (!TextUtils.isEmpty(valueOf) && (valueOf.contains("301") || valueOf.contains("302") || valueOf.contains("303") || valueOf.contains("307"))) {
                c4349b.m4919c(c4349b.f11210c, response, str2);
                String m4919c = c4349b.m4919c(c4349b.f11211d, response, str2);
                if (TextUtils.isEmpty(m4919c) || !m4919c.contains("?JessYan=")) {
                    return response;
                }
                C4389k0.a aVar4 = new C4389k0.a(response);
                aVar4.m4993d("Location", m4919c);
                return aVar4.m4990a();
            }
            if (response.f11491k == null || !c4349b.f11211d.containsKey(str2)) {
                return response;
            }
            List<InterfaceC4348a> list2 = c4349b.f11211d.get(str2);
            Intrinsics.checkParameterIsNotNull(response, "response");
            C4381g0 c4381g03 = response.f11485e;
            EnumC4377e0 enumC4377e0 = response.f11486f;
            int i2 = response.f11488h;
            String str3 = response.f11487g;
            C4487x c4487x = response.f11489i;
            C4488y.a m5279c = response.f11490j.m5279c();
            C4389k0 c4389k0 = response.f11492l;
            C4389k0 c4389k02 = response.f11493m;
            C4389k0 c4389k03 = response.f11494n;
            long j2 = response.f11495o;
            long j3 = response.f11496p;
            C4413c c4413c = response.f11497q;
            C4352c c4352c = new C4352c(c4349b.f11212e, response.f11491k, list2, c4349b.f11214g);
            if (!(i2 >= 0)) {
                throw new IllegalStateException(C1499a.m626l("code < 0: ", i2).toString());
            }
            if (c4381g03 == null) {
                throw new IllegalStateException("request == null".toString());
            }
            if (enumC4377e0 == null) {
                throw new IllegalStateException("protocol == null".toString());
            }
            if (str3 != null) {
                return new C4389k0(c4381g03, enumC4377e0, str3, i2, c4487x, m5279c.m5285d(), c4352c, c4389k0, c4389k02, c4389k03, j2, j3, c4413c);
            }
            throw new IllegalStateException("message == null".toString());
        }
    }

    static {
        boolean z;
        try {
            Class.forName("k.d0");
            z = true;
        } catch (ClassNotFoundException unused) {
            z = false;
        }
        f11209b = z;
    }

    /* renamed from: b */
    public static final C4349b m4917b() {
        if (f11208a == null) {
            if (!f11209b) {
                throw new IllegalStateException("Must be dependency Okhttp");
            }
            synchronized (C4349b.class) {
                if (f11208a == null) {
                    f11208a = new C4349b();
                }
            }
        }
        return f11208a;
    }

    /* renamed from: a */
    public void m4918a(String str, InterfaceC4348a interfaceC4348a) {
        List<InterfaceC4348a> list;
        synchronized (C4349b.class) {
            list = this.f11211d.get(str);
            if (list == null) {
                list = new LinkedList<>();
                this.f11211d.put(str, list);
            }
        }
        list.add(interfaceC4348a);
    }

    /* renamed from: c */
    public final String m4919c(Map<String, List<InterfaceC4348a>> map, C4389k0 c4389k0, String str) {
        List<InterfaceC4348a> list = map.get(str);
        String str2 = null;
        if (list != null && list.size() > 0) {
            str2 = C4389k0.m4987d(c4389k0, "Location", null, 2);
            if (!TextUtils.isEmpty(str2)) {
                if (str.contains("?JessYan=") && !str2.contains("?JessYan=")) {
                    StringBuilder m586H = C1499a.m586H(str2);
                    m586H.append(str.substring(str.indexOf("?JessYan="), str.length()));
                    str2 = m586H.toString();
                }
                if (map.containsKey(str2)) {
                    List<InterfaceC4348a> list2 = map.get(str2);
                    for (InterfaceC4348a interfaceC4348a : list) {
                        if (!list2.contains(interfaceC4348a)) {
                            list2.add(interfaceC4348a);
                        }
                    }
                } else {
                    map.put(str2, list);
                }
            }
        }
        return str2;
    }
}
