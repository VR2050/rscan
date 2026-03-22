package p505n;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;
import javax.annotation.Nullable;
import kotlin.jvm.internal.Intrinsics;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.AbstractC4387j0;
import p458k.C4371b0;
import p458k.C4373c0;
import p458k.C4381g0;
import p458k.C4486w;
import p458k.C4488y;
import p458k.C4489z;
import p474l.InterfaceC4745g;

/* renamed from: n.w */
/* loaded from: classes3.dex */
public final class C5028w {

    /* renamed from: a */
    public static final char[] f12906a = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    /* renamed from: b */
    public static final Pattern f12907b = Pattern.compile("(.*/)?(\\.|%2e|%2E){1,2}(/.*)?");

    /* renamed from: c */
    public final String f12908c;

    /* renamed from: d */
    public final C4489z f12909d;

    /* renamed from: e */
    @Nullable
    public String f12910e;

    /* renamed from: f */
    @Nullable
    public C4489z.a f12911f;

    /* renamed from: g */
    public final C4381g0.a f12912g = new C4381g0.a();

    /* renamed from: h */
    public final C4488y.a f12913h;

    /* renamed from: i */
    @Nullable
    public C4371b0 f12914i;

    /* renamed from: j */
    public final boolean f12915j;

    /* renamed from: k */
    @Nullable
    public C4373c0.a f12916k;

    /* renamed from: l */
    @Nullable
    public C4486w.a f12917l;

    /* renamed from: m */
    @Nullable
    public AbstractC4387j0 f12918m;

    /* renamed from: n.w$a */
    public static class a extends AbstractC4387j0 {

        /* renamed from: b */
        public final AbstractC4387j0 f12919b;

        /* renamed from: c */
        public final C4371b0 f12920c;

        public a(AbstractC4387j0 abstractC4387j0, C4371b0 c4371b0) {
            this.f12919b = abstractC4387j0;
            this.f12920c = c4371b0;
        }

        @Override // p458k.AbstractC4387j0
        /* renamed from: a */
        public long mo4920a() {
            return this.f12919b.mo4920a();
        }

        @Override // p458k.AbstractC4387j0
        /* renamed from: b */
        public C4371b0 mo4921b() {
            return this.f12920c;
        }

        @Override // p458k.AbstractC4387j0
        /* renamed from: d */
        public void mo4922d(InterfaceC4745g interfaceC4745g) {
            this.f12919b.mo4922d(interfaceC4745g);
        }
    }

    public C5028w(String str, C4489z c4489z, @Nullable String str2, @Nullable C4488y c4488y, @Nullable C4371b0 c4371b0, boolean z, boolean z2, boolean z3) {
        this.f12908c = str;
        this.f12909d = c4489z;
        this.f12910e = str2;
        this.f12914i = c4371b0;
        this.f12915j = z;
        if (c4488y != null) {
            this.f12913h = c4488y.m5279c();
        } else {
            this.f12913h = new C4488y.a();
        }
        if (z2) {
            this.f12917l = new C4486w.a(null, 1);
            return;
        }
        if (z3) {
            C4373c0.a aVar = new C4373c0.a();
            this.f12916k = aVar;
            C4371b0 type = C4373c0.f11315c;
            Objects.requireNonNull(aVar);
            Intrinsics.checkParameterIsNotNull(type, "type");
            if (Intrinsics.areEqual(type.f11311e, "multipart")) {
                aVar.f11325b = type;
                return;
            }
            throw new IllegalArgumentException(("multipart != " + type).toString());
        }
    }

    /* renamed from: a */
    public void m5677a(String name, String value, boolean z) {
        if (!z) {
            this.f12917l.m5271a(name, value);
            return;
        }
        C4486w.a aVar = this.f12917l;
        Objects.requireNonNull(aVar);
        Intrinsics.checkParameterIsNotNull(name, "name");
        Intrinsics.checkParameterIsNotNull(value, "value");
        List<String> list = aVar.f12029a;
        C4489z.b bVar = C4489z.f12044b;
        list.add(C4489z.b.m5303a(bVar, name, 0, 0, " \"':;<=>@[]^`{}|/\\?#&!$(),~", true, false, true, false, aVar.f12031c, 83));
        aVar.f12030b.add(C4489z.b.m5303a(bVar, value, 0, 0, " \"':;<=>@[]^`{}|/\\?#&!$(),~", true, false, true, false, aVar.f12031c, 83));
    }

    /* renamed from: b */
    public void m5678b(String str, String str2) {
        if (!"Content-Type".equalsIgnoreCase(str)) {
            this.f12913h.m5282a(str, str2);
            return;
        }
        try {
            C4371b0.a aVar = C4371b0.f11309c;
            this.f12914i = C4371b0.a.m4945a(str2);
        } catch (IllegalArgumentException e2) {
            throw new IllegalArgumentException(C1499a.m637w("Malformed content type: ", str2), e2);
        }
    }

    /* renamed from: c */
    public void m5679c(C4488y c4488y, AbstractC4387j0 body) {
        C4373c0.a aVar = this.f12916k;
        Objects.requireNonNull(aVar);
        Intrinsics.checkParameterIsNotNull(body, "body");
        Intrinsics.checkParameterIsNotNull(body, "body");
        if (!((c4488y != null ? c4488y.m5277a("Content-Type") : null) == null)) {
            throw new IllegalArgumentException("Unexpected header: Content-Type".toString());
        }
        if (!((c4488y != null ? c4488y.m5277a("Content-Length") : null) == null)) {
            throw new IllegalArgumentException("Unexpected header: Content-Length".toString());
        }
        C4373c0.b part = new C4373c0.b(c4488y, body, null);
        Intrinsics.checkParameterIsNotNull(part, "part");
        aVar.f11326c.add(part);
    }

    /* renamed from: d */
    public void m5680d(String name, @Nullable String str, boolean z) {
        String str2 = this.f12910e;
        if (str2 != null) {
            C4489z.a m5296f = this.f12909d.m5296f(str2);
            this.f12911f = m5296f;
            if (m5296f == null) {
                StringBuilder m586H = C1499a.m586H("Malformed URL. Base: ");
                m586H.append(this.f12909d);
                m586H.append(", Relative: ");
                m586H.append(this.f12910e);
                throw new IllegalArgumentException(m586H.toString());
            }
            this.f12910e = null;
        }
        if (z) {
            C4489z.a aVar = this.f12911f;
            Objects.requireNonNull(aVar);
            Intrinsics.checkParameterIsNotNull(name, "encodedName");
            if (aVar.f12062h == null) {
                aVar.f12062h = new ArrayList();
            }
            List<String> list = aVar.f12062h;
            if (list == null) {
                Intrinsics.throwNpe();
            }
            C4489z.b bVar = C4489z.f12044b;
            list.add(C4489z.b.m5303a(bVar, name, 0, 0, " \"'<>#&=", true, false, true, false, null, 211));
            List<String> list2 = aVar.f12062h;
            if (list2 == null) {
                Intrinsics.throwNpe();
            }
            list2.add(str != null ? C4489z.b.m5303a(bVar, str, 0, 0, " \"'<>#&=", true, false, true, false, null, 211) : null);
            return;
        }
        C4489z.a aVar2 = this.f12911f;
        Objects.requireNonNull(aVar2);
        Intrinsics.checkParameterIsNotNull(name, "name");
        if (aVar2.f12062h == null) {
            aVar2.f12062h = new ArrayList();
        }
        List<String> list3 = aVar2.f12062h;
        if (list3 == null) {
            Intrinsics.throwNpe();
        }
        C4489z.b bVar2 = C4489z.f12044b;
        list3.add(C4489z.b.m5303a(bVar2, name, 0, 0, " !\"#$&'(),/:;<=>?@[]\\^`{|}~", false, false, true, false, null, 219));
        List<String> list4 = aVar2.f12062h;
        if (list4 == null) {
            Intrinsics.throwNpe();
        }
        list4.add(str != null ? C4489z.b.m5303a(bVar2, str, 0, 0, " !\"#$&'(),/:;<=>?@[]\\^`{|}~", false, false, true, false, null, 219) : null);
    }
}
