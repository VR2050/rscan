package p005b.p143g.p144a.p147m.p154u;

import androidx.annotation.NonNull;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import p005b.p143g.p144a.EnumC1556f;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.EnumC1569a;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1590d;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;
import p005b.p143g.p144a.p169r.C1798d;

/* renamed from: b.g.a.m.u.b */
/* loaded from: classes.dex */
public class C1660b<Data> implements InterfaceC1672n<byte[], Data> {

    /* renamed from: a */
    public final b<Data> f2343a;

    /* renamed from: b.g.a.m.u.b$a */
    public static class a implements InterfaceC1673o<byte[], ByteBuffer> {

        /* renamed from: b.g.a.m.u.b$a$a, reason: collision with other inner class name */
        public class C5109a implements b<ByteBuffer> {
            public C5109a(a aVar) {
            }

            @Override // p005b.p143g.p144a.p147m.p154u.C1660b.b
            /* renamed from: a */
            public Class<ByteBuffer> mo964a() {
                return ByteBuffer.class;
            }

            @Override // p005b.p143g.p144a.p147m.p154u.C1660b.b
            /* renamed from: b */
            public ByteBuffer mo965b(byte[] bArr) {
                return ByteBuffer.wrap(bArr);
            }
        }

        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        @NonNull
        /* renamed from: b */
        public InterfaceC1672n<byte[], ByteBuffer> mo963b(@NonNull C1676r c1676r) {
            return new C1660b(new C5109a(this));
        }
    }

    /* renamed from: b.g.a.m.u.b$b */
    public interface b<Data> {
        /* renamed from: a */
        Class<Data> mo964a();

        /* renamed from: b */
        Data mo965b(byte[] bArr);
    }

    /* renamed from: b.g.a.m.u.b$c */
    public static class c<Data> implements InterfaceC1590d<Data> {

        /* renamed from: c */
        public final byte[] f2344c;

        /* renamed from: e */
        public final b<Data> f2345e;

        public c(byte[] bArr, b<Data> bVar) {
            this.f2344c = bArr;
            this.f2345e = bVar;
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        @NonNull
        /* renamed from: a */
        public Class<Data> mo832a() {
            return this.f2345e.mo964a();
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        /* renamed from: b */
        public void mo835b() {
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        public void cancel() {
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        /* renamed from: d */
        public void mo837d(@NonNull EnumC1556f enumC1556f, @NonNull InterfaceC1590d.a<? super Data> aVar) {
            aVar.mo840e(this.f2345e.mo965b(this.f2344c));
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        @NonNull
        public EnumC1569a getDataSource() {
            return EnumC1569a.LOCAL;
        }
    }

    /* renamed from: b.g.a.m.u.b$d */
    public static class d implements InterfaceC1673o<byte[], InputStream> {

        /* renamed from: b.g.a.m.u.b$d$a */
        public class a implements b<InputStream> {
            public a(d dVar) {
            }

            @Override // p005b.p143g.p144a.p147m.p154u.C1660b.b
            /* renamed from: a */
            public Class<InputStream> mo964a() {
                return InputStream.class;
            }

            @Override // p005b.p143g.p144a.p147m.p154u.C1660b.b
            /* renamed from: b */
            public InputStream mo965b(byte[] bArr) {
                return new ByteArrayInputStream(bArr);
            }
        }

        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        @NonNull
        /* renamed from: b */
        public InterfaceC1672n<byte[], InputStream> mo963b(@NonNull C1676r c1676r) {
            return new C1660b(new a(this));
        }
    }

    public C1660b(b<Data> bVar) {
        this.f2343a = bVar;
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: a */
    public /* bridge */ /* synthetic */ boolean mo960a(@NonNull byte[] bArr) {
        return true;
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: b */
    public InterfaceC1672n.a mo961b(@NonNull byte[] bArr, int i2, int i3, @NonNull C1582n c1582n) {
        byte[] bArr2 = bArr;
        return new InterfaceC1672n.a(new C1798d(bArr2), new c(bArr2, this.f2343a));
    }
}
