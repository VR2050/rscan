package p005b.p143g.p144a.p147m.p154u;

import android.util.Log;
import androidx.annotation.NonNull;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import p005b.p143g.p144a.EnumC1556f;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.EnumC1569a;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1590d;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;
import p005b.p143g.p144a.p169r.C1798d;
import p005b.p143g.p144a.p170s.C1799a;

/* renamed from: b.g.a.m.u.d */
/* loaded from: classes.dex */
public class C1662d implements InterfaceC1672n<File, ByteBuffer> {

    /* renamed from: b.g.a.m.u.d$a */
    public static final class a implements InterfaceC1590d<ByteBuffer> {

        /* renamed from: c */
        public final File f2346c;

        public a(File file) {
            this.f2346c = file;
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        @NonNull
        /* renamed from: a */
        public Class<ByteBuffer> mo832a() {
            return ByteBuffer.class;
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
        public void mo837d(@NonNull EnumC1556f enumC1556f, @NonNull InterfaceC1590d.a<? super ByteBuffer> aVar) {
            try {
                aVar.mo840e(C1799a.m1134a(this.f2346c));
            } catch (IOException e2) {
                Log.isLoggable("ByteBufferFileLoader", 3);
                aVar.mo839c(e2);
            }
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        @NonNull
        public EnumC1569a getDataSource() {
            return EnumC1569a.LOCAL;
        }
    }

    /* renamed from: b.g.a.m.u.d$b */
    public static class b implements InterfaceC1673o<File, ByteBuffer> {
        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        @NonNull
        /* renamed from: b */
        public InterfaceC1672n<File, ByteBuffer> mo963b(@NonNull C1676r c1676r) {
            return new C1662d();
        }
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: a */
    public /* bridge */ /* synthetic */ boolean mo960a(@NonNull File file) {
        return true;
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: b */
    public InterfaceC1672n.a<ByteBuffer> mo961b(@NonNull File file, int i2, int i3, @NonNull C1582n c1582n) {
        File file2 = file;
        return new InterfaceC1672n.a<>(new C1798d(file2), new a(file2));
    }
}
