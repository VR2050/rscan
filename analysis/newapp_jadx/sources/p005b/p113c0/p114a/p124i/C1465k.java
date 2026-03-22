package p005b.p113c0.p114a.p124i;

import android.text.TextUtils;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.StringTokenizer;
import java.util.zip.GZIPInputStream;
import p005b.p113c0.p114a.C1411c;
import p005b.p113c0.p114a.C1412d;
import p005b.p113c0.p114a.p115g.C1421g;
import p005b.p113c0.p114a.p124i.C1467m;
import p005b.p113c0.p114a.p124i.p127p.C1481d;
import p005b.p113c0.p114a.p130l.C1491c;
import p005b.p113c0.p114a.p130l.C1492d;
import p005b.p113c0.p114a.p130l.C1494f;
import p005b.p113c0.p114a.p130l.C1495g;
import p005b.p113c0.p114a.p130l.InterfaceC1497i;
import p005b.p131d.p132a.p133a.C1499a;
import p476m.p477a.p478a.p483b.C4784a;
import p476m.p477a.p485b.InterfaceC4799e0;
import p476m.p477a.p485b.InterfaceC4800f;
import p476m.p477a.p485b.InterfaceC4846k;
import p476m.p477a.p485b.InterfaceC4852l;
import p476m.p477a.p485b.InterfaceC4895o;

/* renamed from: b.c0.a.i.k */
/* loaded from: classes2.dex */
public class C1465k implements InterfaceC1457c {

    /* renamed from: a */
    public InterfaceC4895o f1425a;

    /* renamed from: b */
    public InterfaceC1455a f1426b;

    /* renamed from: c */
    public C1412d f1427c;

    /* renamed from: d */
    public InterfaceC4799e0 f1428d;

    /* renamed from: e */
    public C1467m f1429e;

    /* renamed from: f */
    public boolean f1430f;

    /* renamed from: g */
    public InterfaceC1497i<String, String> f1431g;

    /* renamed from: h */
    public boolean f1432h;

    /* renamed from: i */
    public InterfaceC1497i<String, String> f1433i;

    /* renamed from: j */
    public boolean f1434j;

    /* renamed from: b.c0.a.i.k$b */
    public static class b implements InterfaceC1460f {

        /* renamed from: a */
        public InterfaceC4846k f1435a;

        public b(InterfaceC4846k interfaceC4846k, a aVar) {
            this.f1435a = interfaceC4846k;
        }

        @Nullable
        /* renamed from: a */
        public C1495g m536a() {
            InterfaceC4800f contentType = this.f1435a.getContentType();
            if (contentType == null) {
                return null;
            }
            return C1495g.m568k(contentType.getValue());
        }

        @NonNull
        /* renamed from: b */
        public InputStream m537b() {
            InputStream mo542d = this.f1435a.mo542d();
            InterfaceC4800f contentType = this.f1435a.getContentType();
            return (contentType == null ? "" : contentType.getValue()).toLowerCase().contains("gzip") ? new GZIPInputStream(mo542d) : mo542d;
        }

        @NonNull
        /* renamed from: c */
        public String m538c() {
            C1495g m536a = m536a();
            Charset m574d = m536a == null ? null : m536a.m574d();
            if (m574d == null) {
                InputStream m537b = m537b();
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                C1492d.m563b(m537b, byteArrayOutputStream);
                byteArrayOutputStream.close();
                return new String(byteArrayOutputStream.toByteArray());
            }
            InputStream m537b2 = m537b();
            ByteArrayOutputStream byteArrayOutputStream2 = new ByteArrayOutputStream();
            C1492d.m563b(m537b2, byteArrayOutputStream2);
            byteArrayOutputStream2.close();
            return new String(byteArrayOutputStream2.toByteArray(), m574d);
        }
    }

    public C1465k(InterfaceC4895o interfaceC4895o, InterfaceC1455a interfaceC1455a, C1412d c1412d, C1481d c1481d) {
        this.f1425a = interfaceC4895o;
        this.f1426b = interfaceC1455a;
        this.f1427c = c1412d;
        this.f1428d = interfaceC4895o.mo5525k();
    }

    @NonNull
    /* renamed from: m */
    public static InterfaceC1497i<String, String> m532m(@NonNull String str) {
        C1494f c1494f = new C1494f();
        StringTokenizer stringTokenizer = new StringTokenizer(str, "&");
        while (stringTokenizer.hasMoreElements()) {
            String nextToken = stringTokenizer.nextToken();
            int indexOf = nextToken.indexOf("=");
            if (indexOf > 0 && indexOf < nextToken.length() - 1) {
                String substring = nextToken.substring(0, indexOf);
                String substring2 = nextToken.substring(indexOf + 1);
                try {
                    substring2 = URLDecoder.decode(substring2, C4784a.m5463a("utf-8").name());
                } catch (UnsupportedEncodingException unused) {
                }
                c1494f.m566a(substring, substring2);
            }
        }
        return c1494f;
    }

    @Override // p005b.p113c0.p114a.p124i.InterfaceC1455a
    @Nullable
    /* renamed from: a */
    public Object mo518a(@NonNull String str) {
        return this.f1426b.mo518a(str);
    }

    @Override // p005b.p113c0.p114a.p124i.InterfaceC1455a
    /* renamed from: b */
    public void mo519b(@NonNull String str, @Nullable Object obj) {
        this.f1426b.mo519b(str, obj);
    }

    @Override // p005b.p113c0.p114a.p124i.InterfaceC1457c
    @NonNull
    /* renamed from: c */
    public List<String> mo522c(@NonNull String str) {
        InterfaceC4800f[] mo5513c = this.f1425a.mo5513c(str);
        if (mo5513c == null || mo5513c.length == 0) {
            return Collections.emptyList();
        }
        ArrayList arrayList = new ArrayList();
        for (InterfaceC4800f interfaceC4800f : mo5513c) {
            arrayList.add(interfaceC4800f.getValue());
        }
        return arrayList;
    }

    @Override // p005b.p113c0.p114a.p124i.InterfaceC1457c
    @NonNull
    /* renamed from: d */
    public EnumC1456b mo523d() {
        return EnumC1456b.m520b(this.f1428d.mo5474d());
    }

    @Override // p005b.p113c0.p114a.p124i.InterfaceC1457c
    @NonNull
    /* renamed from: e */
    public InterfaceC1497i<String, String> mo524e() {
        m534n();
        return this.f1431g;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // p005b.p113c0.p114a.p124i.InterfaceC1457c
    @Nullable
    /* renamed from: f */
    public InterfaceC1461g mo525f(@NonNull String str) {
        C1412d c1412d = this.f1427c;
        Objects.requireNonNull(c1412d);
        InterfaceC1457c interfaceC1457c = this;
        while (interfaceC1457c instanceof C1462h) {
            interfaceC1457c = ((C1462h) this).f1423a;
        }
        C1465k c1465k = (C1465k) interfaceC1457c;
        c1465k.m535o();
        C1467m.b bVar = new C1467m.b(c1465k.f1429e.toString(), null);
        bVar.f1449d = C1467m.m546a(str);
        c1465k.f1429e = new C1467m(bVar, null);
        if (c1412d.m487c(interfaceC1457c) != null) {
            return new C1411c(c1412d);
        }
        throw new C1421g(getPath());
    }

    @Override // p005b.p113c0.p114a.p124i.InterfaceC1457c
    @Nullable
    public C1495g getContentType() {
        String mo528j = mo528j("Content-Type");
        if (TextUtils.isEmpty(mo528j)) {
            return null;
        }
        return C1495g.m568k(mo528j);
    }

    @Override // p005b.p113c0.p114a.p124i.InterfaceC1457c
    @NonNull
    public String getPath() {
        m535o();
        return this.f1429e.f1443i;
    }

    @Override // p005b.p113c0.p114a.p124i.InterfaceC1457c
    @Nullable
    /* renamed from: h */
    public InterfaceC1460f mo526h() {
        InterfaceC4846k mo5510b;
        if (!mo523d().m521a()) {
            throw new UnsupportedOperationException("This method does not allow body.");
        }
        InterfaceC4895o interfaceC4895o = this.f1425a;
        if (!(interfaceC4895o instanceof InterfaceC4852l) || (mo5510b = ((InterfaceC4852l) interfaceC4895o).mo5510b()) == null) {
            return null;
        }
        return new b(mo5510b, null);
    }

    @Override // p005b.p113c0.p114a.p124i.InterfaceC1457c
    @Nullable
    /* renamed from: i */
    public String mo527i(@NonNull String str) {
        m533l();
        String str2 = (String) ((C1494f) this.f1433i).m567c(str);
        if (!TextUtils.isEmpty(str2)) {
            return str2;
        }
        m534n();
        return (String) ((C1494f) this.f1431g).m567c(str);
    }

    @Override // p005b.p113c0.p114a.p124i.InterfaceC1457c
    @Nullable
    /* renamed from: j */
    public String mo528j(@NonNull String str) {
        InterfaceC4800f mo5519n = this.f1425a.mo5519n(str);
        if (mo5519n == null) {
            return null;
        }
        return mo5519n.getValue();
    }

    @Override // p005b.p113c0.p114a.p124i.InterfaceC1457c
    /* renamed from: k */
    public long mo529k(@NonNull String str) {
        InterfaceC4800f mo5519n = this.f1425a.mo5519n(str);
        if (mo5519n == null) {
            return -1L;
        }
        String value = mo5519n.getValue();
        long m561a = C1491c.m561a(value);
        if (m561a != -1) {
            return m561a;
        }
        throw new IllegalStateException(String.format("The %s cannot be converted to date.", value));
    }

    /* renamed from: l */
    public final void m533l() {
        if (this.f1434j) {
            return;
        }
        if (!mo523d().m521a()) {
            this.f1433i = new C1494f();
            return;
        }
        if (C1495g.f1508i.m570j(getContentType())) {
            try {
                InterfaceC1460f mo526h = mo526h();
                this.f1433i = m532m(mo526h == null ? "" : ((b) mo526h).m538c());
            } catch (Exception unused) {
            }
        }
        if (this.f1433i == null) {
            this.f1433i = new C1494f();
        }
        this.f1434j = true;
    }

    /* renamed from: n */
    public final void m534n() {
        if (this.f1432h) {
            return;
        }
        m535o();
        this.f1431g = C1467m.m547b(this.f1429e.f1444j);
        this.f1432h = true;
    }

    /* renamed from: o */
    public final void m535o() {
        if (this.f1430f) {
            return;
        }
        String uri = this.f1428d.getUri();
        if (TextUtils.isEmpty(uri)) {
            uri = "/";
        }
        String m637w = C1499a.m637w("scheme://host:ip", uri);
        int i2 = C1467m.f1439e;
        this.f1429e = new C1467m(new C1467m.b(m637w, null), null);
        this.f1430f = true;
    }
}
