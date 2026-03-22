package p458k;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import kotlin.jvm.JvmField;
import kotlin.jvm.JvmOverloads;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p458k.C4371b0;
import p474l.C4744f;
import p474l.C4747i;
import p474l.InterfaceC4745g;

/* renamed from: k.c0 */
/* loaded from: classes3.dex */
public final class C4373c0 extends AbstractC4387j0 {

    /* renamed from: b */
    @JvmField
    @NotNull
    public static final C4371b0 f11314b;

    /* renamed from: c */
    @JvmField
    @NotNull
    public static final C4371b0 f11315c;

    /* renamed from: d */
    public static final byte[] f11316d;

    /* renamed from: e */
    public static final byte[] f11317e;

    /* renamed from: f */
    public static final byte[] f11318f;

    /* renamed from: g */
    public final C4371b0 f11319g;

    /* renamed from: h */
    public long f11320h;

    /* renamed from: i */
    public final C4747i f11321i;

    /* renamed from: j */
    @NotNull
    public final C4371b0 f11322j;

    /* renamed from: k */
    @NotNull
    public final List<b> f11323k;

    /* renamed from: k.c0$a */
    public static final class a {

        /* renamed from: a */
        public final C4747i f11324a;

        /* renamed from: b */
        public C4371b0 f11325b;

        /* renamed from: c */
        public final List<b> f11326c;

        @JvmOverloads
        public a() {
            String boundary = UUID.randomUUID().toString();
            Intrinsics.checkExpressionValueIsNotNull(boundary, "UUID.randomUUID().toString()");
            Intrinsics.checkParameterIsNotNull(boundary, "boundary");
            this.f11324a = C4747i.f12136e.m5412c(boundary);
            this.f11325b = C4373c0.f11314b;
            this.f11326c = new ArrayList();
        }
    }

    /* renamed from: k.c0$b */
    public static final class b {

        /* renamed from: a */
        @Nullable
        public final C4488y f11327a;

        /* renamed from: b */
        @NotNull
        public final AbstractC4387j0 f11328b;

        public b(C4488y c4488y, AbstractC4387j0 abstractC4387j0, DefaultConstructorMarker defaultConstructorMarker) {
            this.f11327a = c4488y;
            this.f11328b = abstractC4387j0;
        }
    }

    static {
        C4371b0.a aVar = C4371b0.f11309c;
        f11314b = C4371b0.a.m4945a("multipart/mixed");
        C4371b0.a.m4945a("multipart/alternative");
        C4371b0.a.m4945a("multipart/digest");
        C4371b0.a.m4945a("multipart/parallel");
        f11315c = C4371b0.a.m4945a("multipart/form-data");
        f11316d = new byte[]{(byte) 58, (byte) 32};
        f11317e = new byte[]{(byte) 13, (byte) 10};
        byte b2 = (byte) 45;
        f11318f = new byte[]{b2, b2};
    }

    public C4373c0(@NotNull C4747i boundaryByteString, @NotNull C4371b0 type, @NotNull List<b> parts) {
        Intrinsics.checkParameterIsNotNull(boundaryByteString, "boundaryByteString");
        Intrinsics.checkParameterIsNotNull(type, "type");
        Intrinsics.checkParameterIsNotNull(parts, "parts");
        this.f11321i = boundaryByteString;
        this.f11322j = type;
        this.f11323k = parts;
        C4371b0.a aVar = C4371b0.f11309c;
        this.f11319g = C4371b0.a.m4945a(type + "; boundary=" + boundaryByteString.m5407j());
        this.f11320h = -1L;
    }

    @Override // p458k.AbstractC4387j0
    /* renamed from: a */
    public long mo4920a() {
        long j2 = this.f11320h;
        if (j2 != -1) {
            return j2;
        }
        long m4947e = m4947e(null, true);
        this.f11320h = m4947e;
        return m4947e;
    }

    @Override // p458k.AbstractC4387j0
    @NotNull
    /* renamed from: b */
    public C4371b0 mo4921b() {
        return this.f11319g;
    }

    @Override // p458k.AbstractC4387j0
    /* renamed from: d */
    public void mo4922d(@NotNull InterfaceC4745g sink) {
        Intrinsics.checkParameterIsNotNull(sink, "sink");
        m4947e(sink, false);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: e */
    public final long m4947e(InterfaceC4745g interfaceC4745g, boolean z) {
        C4744f c4744f;
        if (z) {
            interfaceC4745g = new C4744f();
            c4744f = interfaceC4745g;
        } else {
            c4744f = 0;
        }
        int size = this.f11323k.size();
        long j2 = 0;
        for (int i2 = 0; i2 < size; i2++) {
            b bVar = this.f11323k.get(i2);
            C4488y c4488y = bVar.f11327a;
            AbstractC4387j0 abstractC4387j0 = bVar.f11328b;
            if (interfaceC4745g == null) {
                Intrinsics.throwNpe();
            }
            interfaceC4745g.mo5356G(f11318f);
            interfaceC4745g.mo5357H(this.f11321i);
            interfaceC4745g.mo5356G(f11317e);
            if (c4488y != null) {
                int size2 = c4488y.size();
                for (int i3 = 0; i3 < size2; i3++) {
                    interfaceC4745g.mo5393u(c4488y.m5278b(i3)).mo5356G(f11316d).mo5393u(c4488y.m5280d(i3)).mo5356G(f11317e);
                }
            }
            C4371b0 mo4921b = abstractC4387j0.mo4921b();
            if (mo4921b != null) {
                interfaceC4745g.mo5393u("Content-Type: ").mo5393u(mo4921b.f11310d).mo5356G(f11317e);
            }
            long mo4920a = abstractC4387j0.mo4920a();
            if (mo4920a != -1) {
                interfaceC4745g.mo5393u("Content-Length: ").mo5361N(mo4920a).mo5356G(f11317e);
            } else if (z) {
                if (c4744f == 0) {
                    Intrinsics.throwNpe();
                }
                c4744f.skip(c4744f.f12133e);
                return -1L;
            }
            byte[] bArr = f11317e;
            interfaceC4745g.mo5356G(bArr);
            if (z) {
                j2 += mo4920a;
            } else {
                abstractC4387j0.mo4922d(interfaceC4745g);
            }
            interfaceC4745g.mo5356G(bArr);
        }
        if (interfaceC4745g == null) {
            Intrinsics.throwNpe();
        }
        byte[] bArr2 = f11318f;
        interfaceC4745g.mo5356G(bArr2);
        interfaceC4745g.mo5357H(this.f11321i);
        interfaceC4745g.mo5356G(bArr2);
        interfaceC4745g.mo5356G(f11317e);
        if (!z) {
            return j2;
        }
        if (c4744f == 0) {
            Intrinsics.throwNpe();
        }
        long j3 = c4744f.f12133e;
        long j4 = j2 + j3;
        c4744f.skip(j3);
        return j4;
    }
}
