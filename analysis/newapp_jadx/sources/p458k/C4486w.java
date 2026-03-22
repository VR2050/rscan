package p458k;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p458k.C4371b0;
import p458k.C4489z;
import p458k.p459p0.C4401c;
import p474l.C4744f;
import p474l.InterfaceC4745g;

/* renamed from: k.w */
/* loaded from: classes3.dex */
public final class C4486w extends AbstractC4387j0 {

    /* renamed from: b */
    public static final C4371b0 f12026b;

    /* renamed from: c */
    public final List<String> f12027c;

    /* renamed from: d */
    public final List<String> f12028d;

    /* renamed from: k.w$a */
    public static final class a {

        /* renamed from: c */
        public final Charset f12031c = null;

        /* renamed from: a */
        public final List<String> f12029a = new ArrayList();

        /* renamed from: b */
        public final List<String> f12030b = new ArrayList();

        public a(Charset charset, int i2) {
            int i3 = i2 & 1;
        }

        @NotNull
        /* renamed from: a */
        public final a m5271a(@NotNull String name, @NotNull String value) {
            Intrinsics.checkParameterIsNotNull(name, "name");
            Intrinsics.checkParameterIsNotNull(value, "value");
            List<String> list = this.f12029a;
            C4489z.b bVar = C4489z.f12044b;
            list.add(C4489z.b.m5303a(bVar, name, 0, 0, " \"':;<=>@[]^`{}|/\\?#&!$(),~", false, false, true, false, this.f12031c, 91));
            this.f12030b.add(C4489z.b.m5303a(bVar, value, 0, 0, " \"':;<=>@[]^`{}|/\\?#&!$(),~", false, false, true, false, this.f12031c, 91));
            return this;
        }
    }

    static {
        C4371b0.a aVar = C4371b0.f11309c;
        f12026b = C4371b0.a.m4945a("application/x-www-form-urlencoded");
    }

    public C4486w(@NotNull List<String> encodedNames, @NotNull List<String> encodedValues) {
        Intrinsics.checkParameterIsNotNull(encodedNames, "encodedNames");
        Intrinsics.checkParameterIsNotNull(encodedValues, "encodedValues");
        this.f12027c = C4401c.m5038w(encodedNames);
        this.f12028d = C4401c.m5038w(encodedValues);
    }

    @Override // p458k.AbstractC4387j0
    /* renamed from: a */
    public long mo4920a() {
        return m5270e(null, true);
    }

    @Override // p458k.AbstractC4387j0
    @NotNull
    /* renamed from: b */
    public C4371b0 mo4921b() {
        return f12026b;
    }

    @Override // p458k.AbstractC4387j0
    /* renamed from: d */
    public void mo4922d(@NotNull InterfaceC4745g sink) {
        Intrinsics.checkParameterIsNotNull(sink, "sink");
        m5270e(sink, false);
    }

    /* renamed from: e */
    public final long m5270e(InterfaceC4745g interfaceC4745g, boolean z) {
        C4744f buffer;
        if (z) {
            buffer = new C4744f();
        } else {
            if (interfaceC4745g == null) {
                Intrinsics.throwNpe();
            }
            buffer = interfaceC4745g.getBuffer();
        }
        int size = this.f12027c.size();
        for (int i2 = 0; i2 < size; i2++) {
            if (i2 > 0) {
                buffer.m5374a0(38);
            }
            buffer.m5381f0(this.f12027c.get(i2));
            buffer.m5374a0(61);
            buffer.m5381f0(this.f12028d.get(i2));
        }
        if (!z) {
            return 0L;
        }
        long j2 = buffer.f12133e;
        buffer.skip(j2);
        return j2;
    }
}
