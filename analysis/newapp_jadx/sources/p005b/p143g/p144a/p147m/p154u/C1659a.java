package p005b.p143g.p144a.p147m.p154u;

import android.content.res.AssetManager;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import androidx.annotation.NonNull;
import java.io.InputStream;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.p148s.C1594h;
import p005b.p143g.p144a.p147m.p148s.C1600n;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1590d;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;
import p005b.p143g.p144a.p169r.C1798d;

/* renamed from: b.g.a.m.u.a */
/* loaded from: classes.dex */
public class C1659a<Data> implements InterfaceC1672n<Uri, Data> {

    /* renamed from: a */
    public final AssetManager f2339a;

    /* renamed from: b */
    public final a<Data> f2340b;

    /* renamed from: b.g.a.m.u.a$a */
    public interface a<Data> {
        /* renamed from: a */
        InterfaceC1590d<Data> mo962a(AssetManager assetManager, String str);
    }

    /* renamed from: b.g.a.m.u.a$b */
    public static class b implements InterfaceC1673o<Uri, ParcelFileDescriptor>, a<ParcelFileDescriptor> {

        /* renamed from: a */
        public final AssetManager f2341a;

        public b(AssetManager assetManager) {
            this.f2341a = assetManager;
        }

        @Override // p005b.p143g.p144a.p147m.p154u.C1659a.a
        /* renamed from: a */
        public InterfaceC1590d<ParcelFileDescriptor> mo962a(AssetManager assetManager, String str) {
            return new C1594h(assetManager, str);
        }

        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        @NonNull
        /* renamed from: b */
        public InterfaceC1672n<Uri, ParcelFileDescriptor> mo963b(C1676r c1676r) {
            return new C1659a(this.f2341a, this);
        }
    }

    /* renamed from: b.g.a.m.u.a$c */
    public static class c implements InterfaceC1673o<Uri, InputStream>, a<InputStream> {

        /* renamed from: a */
        public final AssetManager f2342a;

        public c(AssetManager assetManager) {
            this.f2342a = assetManager;
        }

        @Override // p005b.p143g.p144a.p147m.p154u.C1659a.a
        /* renamed from: a */
        public InterfaceC1590d<InputStream> mo962a(AssetManager assetManager, String str) {
            return new C1600n(assetManager, str);
        }

        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        @NonNull
        /* renamed from: b */
        public InterfaceC1672n<Uri, InputStream> mo963b(C1676r c1676r) {
            return new C1659a(this.f2342a, this);
        }
    }

    public C1659a(AssetManager assetManager, a<Data> aVar) {
        this.f2339a = assetManager;
        this.f2340b = aVar;
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: a */
    public boolean mo960a(@NonNull Uri uri) {
        Uri uri2 = uri;
        return "file".equals(uri2.getScheme()) && !uri2.getPathSegments().isEmpty() && "android_asset".equals(uri2.getPathSegments().get(0));
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: b */
    public InterfaceC1672n.a mo961b(@NonNull Uri uri, int i2, int i3, @NonNull C1582n c1582n) {
        Uri uri2 = uri;
        return new InterfaceC1672n.a(new C1798d(uri2), this.f2340b.mo962a(this.f2339a, uri2.toString().substring(22)));
    }
}
