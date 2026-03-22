package p005b.p143g.p144a.p147m.p154u;

import android.os.ParcelFileDescriptor;
import android.util.Log;
import androidx.annotation.NonNull;
import com.alibaba.fastjson.asm.Label;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import p005b.p143g.p144a.EnumC1556f;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.EnumC1569a;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1590d;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;
import p005b.p143g.p144a.p169r.C1798d;

/* renamed from: b.g.a.m.u.f */
/* loaded from: classes.dex */
public class C1664f<Data> implements InterfaceC1672n<File, Data> {

    /* renamed from: a */
    public final d<Data> f2352a;

    /* renamed from: b.g.a.m.u.f$a */
    public static class a<Data> implements InterfaceC1673o<File, Data> {

        /* renamed from: a */
        public final d<Data> f2353a;

        public a(d<Data> dVar) {
            this.f2353a = dVar;
        }

        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        @NonNull
        /* renamed from: b */
        public final InterfaceC1672n<File, Data> mo963b(@NonNull C1676r c1676r) {
            return new C1664f(this.f2353a);
        }
    }

    /* renamed from: b.g.a.m.u.f$b */
    public static class b extends a<ParcelFileDescriptor> {

        /* renamed from: b.g.a.m.u.f$b$a */
        public class a implements d<ParcelFileDescriptor> {
            @Override // p005b.p143g.p144a.p147m.p154u.C1664f.d
            /* renamed from: a */
            public Class<ParcelFileDescriptor> mo967a() {
                return ParcelFileDescriptor.class;
            }

            @Override // p005b.p143g.p144a.p147m.p154u.C1664f.d
            /* renamed from: b */
            public ParcelFileDescriptor mo968b(File file) {
                return ParcelFileDescriptor.open(file, Label.FORWARD_REFERENCE_TYPE_SHORT);
            }

            @Override // p005b.p143g.p144a.p147m.p154u.C1664f.d
            /* renamed from: c */
            public void mo969c(ParcelFileDescriptor parcelFileDescriptor) {
                parcelFileDescriptor.close();
            }
        }

        public b() {
            super(new a());
        }
    }

    /* renamed from: b.g.a.m.u.f$c */
    public static final class c<Data> implements InterfaceC1590d<Data> {

        /* renamed from: c */
        public final File f2354c;

        /* renamed from: e */
        public final d<Data> f2355e;

        /* renamed from: f */
        public Data f2356f;

        public c(File file, d<Data> dVar) {
            this.f2354c = file;
            this.f2355e = dVar;
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        @NonNull
        /* renamed from: a */
        public Class<Data> mo832a() {
            return this.f2355e.mo967a();
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        /* renamed from: b */
        public void mo835b() {
            Data data = this.f2356f;
            if (data != null) {
                try {
                    this.f2355e.mo969c(data);
                } catch (IOException unused) {
                }
            }
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        public void cancel() {
        }

        /* JADX WARN: Type inference failed for: r3v3, types: [Data, java.lang.Object] */
        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        /* renamed from: d */
        public void mo837d(@NonNull EnumC1556f enumC1556f, @NonNull InterfaceC1590d.a<? super Data> aVar) {
            try {
                Data mo968b = this.f2355e.mo968b(this.f2354c);
                this.f2356f = mo968b;
                aVar.mo840e(mo968b);
            } catch (FileNotFoundException e2) {
                Log.isLoggable("FileLoader", 3);
                aVar.mo839c(e2);
            }
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        @NonNull
        public EnumC1569a getDataSource() {
            return EnumC1569a.LOCAL;
        }
    }

    /* renamed from: b.g.a.m.u.f$d */
    public interface d<Data> {
        /* renamed from: a */
        Class<Data> mo967a();

        /* renamed from: b */
        Data mo968b(File file);

        /* renamed from: c */
        void mo969c(Data data);
    }

    /* renamed from: b.g.a.m.u.f$e */
    public static class e extends a<InputStream> {

        /* renamed from: b.g.a.m.u.f$e$a */
        public class a implements d<InputStream> {
            @Override // p005b.p143g.p144a.p147m.p154u.C1664f.d
            /* renamed from: a */
            public Class<InputStream> mo967a() {
                return InputStream.class;
            }

            @Override // p005b.p143g.p144a.p147m.p154u.C1664f.d
            /* renamed from: b */
            public InputStream mo968b(File file) {
                return new FileInputStream(file);
            }

            @Override // p005b.p143g.p144a.p147m.p154u.C1664f.d
            /* renamed from: c */
            public void mo969c(InputStream inputStream) {
                inputStream.close();
            }
        }

        public e() {
            super(new a());
        }
    }

    public C1664f(d<Data> dVar) {
        this.f2352a = dVar;
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: a */
    public /* bridge */ /* synthetic */ boolean mo960a(@NonNull File file) {
        return true;
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: b */
    public InterfaceC1672n.a mo961b(@NonNull File file, int i2, int i3, @NonNull C1582n c1582n) {
        File file2 = file;
        return new InterfaceC1672n.a(new C1798d(file2), new c(file2, this.f2352a));
    }
}
