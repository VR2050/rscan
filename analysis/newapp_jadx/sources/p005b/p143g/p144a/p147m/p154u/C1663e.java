package p005b.p143g.p144a.p147m.p154u;

import android.util.Base64;
import androidx.annotation.NonNull;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import p005b.p143g.p144a.EnumC1556f;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.EnumC1569a;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1590d;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;
import p005b.p143g.p144a.p169r.C1798d;

/* renamed from: b.g.a.m.u.e */
/* loaded from: classes.dex */
public final class C1663e<Model, Data> implements InterfaceC1672n<Model, Data> {

    /* renamed from: a */
    public final a<Data> f2347a;

    /* renamed from: b.g.a.m.u.e$a */
    public interface a<Data> {
    }

    /* renamed from: b.g.a.m.u.e$b */
    public static final class b<Data> implements InterfaceC1590d<Data> {

        /* renamed from: c */
        public final String f2348c;

        /* renamed from: e */
        public final a<Data> f2349e;

        /* renamed from: f */
        public Data f2350f;

        public b(String str, a<Data> aVar) {
            this.f2348c = str;
            this.f2349e = aVar;
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        @NonNull
        /* renamed from: a */
        public Class<Data> mo832a() {
            Objects.requireNonNull((c.a) this.f2349e);
            return InputStream.class;
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        /* renamed from: b */
        public void mo835b() {
            try {
                a<Data> aVar = this.f2349e;
                Data data = this.f2350f;
                Objects.requireNonNull((c.a) aVar);
                ((InputStream) data).close();
            } catch (IOException unused) {
            }
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        public void cancel() {
        }

        /* JADX WARN: Type inference failed for: r2v4, types: [Data, java.lang.Object] */
        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        /* renamed from: d */
        public void mo837d(@NonNull EnumC1556f enumC1556f, @NonNull InterfaceC1590d.a<? super Data> aVar) {
            try {
                ?? r2 = (Data) ((c.a) this.f2349e).m966a(this.f2348c);
                this.f2350f = r2;
                aVar.mo840e(r2);
            } catch (IllegalArgumentException e2) {
                aVar.mo839c(e2);
            }
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        @NonNull
        public EnumC1569a getDataSource() {
            return EnumC1569a.LOCAL;
        }
    }

    /* renamed from: b.g.a.m.u.e$c */
    public static final class c<Model> implements InterfaceC1673o<Model, InputStream> {

        /* renamed from: a */
        public final a<InputStream> f2351a = new a(this);

        /* renamed from: b.g.a.m.u.e$c$a */
        public class a implements a<InputStream> {
            public a(c cVar) {
            }

            /* renamed from: a */
            public Object m966a(String str) {
                if (!str.startsWith("data:image")) {
                    throw new IllegalArgumentException("Not a valid image data URL.");
                }
                int indexOf = str.indexOf(44);
                if (indexOf == -1) {
                    throw new IllegalArgumentException("Missing comma in data URL.");
                }
                if (str.substring(0, indexOf).endsWith(";base64")) {
                    return new ByteArrayInputStream(Base64.decode(str.substring(indexOf + 1), 0));
                }
                throw new IllegalArgumentException("Not a base64 image data URL.");
            }
        }

        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        @NonNull
        /* renamed from: b */
        public InterfaceC1672n<Model, InputStream> mo963b(@NonNull C1676r c1676r) {
            return new C1663e(this.f2351a);
        }
    }

    public C1663e(a<Data> aVar) {
        this.f2347a = aVar;
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: a */
    public boolean mo960a(@NonNull Model model) {
        return model.toString().startsWith("data:image");
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: b */
    public InterfaceC1672n.a<Data> mo961b(@NonNull Model model, int i2, int i3, @NonNull C1582n c1582n) {
        return new InterfaceC1672n.a<>(new C1798d(model), new b(model.toString(), this.f2347a));
    }
}
