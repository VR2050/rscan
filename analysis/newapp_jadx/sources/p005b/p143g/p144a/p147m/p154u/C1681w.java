package p005b.p143g.p144a.p147m.p154u;

import android.content.ContentResolver;
import android.content.res.AssetFileDescriptor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import androidx.annotation.NonNull;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.p148s.C1587a;
import p005b.p143g.p144a.p147m.p148s.C1595i;
import p005b.p143g.p144a.p147m.p148s.C1601o;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1590d;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;
import p005b.p143g.p144a.p169r.C1798d;

/* renamed from: b.g.a.m.u.w */
/* loaded from: classes.dex */
public class C1681w<Data> implements InterfaceC1672n<Uri, Data> {

    /* renamed from: a */
    public static final Set<String> f2417a = Collections.unmodifiableSet(new HashSet(Arrays.asList("file", "android.resource", "content")));

    /* renamed from: b */
    public final c<Data> f2418b;

    /* renamed from: b.g.a.m.u.w$a */
    public static final class a implements InterfaceC1673o<Uri, AssetFileDescriptor>, c<AssetFileDescriptor> {

        /* renamed from: a */
        public final ContentResolver f2419a;

        public a(ContentResolver contentResolver) {
            this.f2419a = contentResolver;
        }

        @Override // p005b.p143g.p144a.p147m.p154u.C1681w.c
        /* renamed from: a */
        public InterfaceC1590d<AssetFileDescriptor> mo982a(Uri uri) {
            return new C1587a(this.f2419a, uri);
        }

        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        /* renamed from: b */
        public InterfaceC1672n<Uri, AssetFileDescriptor> mo963b(C1676r c1676r) {
            return new C1681w(this);
        }
    }

    /* renamed from: b.g.a.m.u.w$b */
    public static class b implements InterfaceC1673o<Uri, ParcelFileDescriptor>, c<ParcelFileDescriptor> {

        /* renamed from: a */
        public final ContentResolver f2420a;

        public b(ContentResolver contentResolver) {
            this.f2420a = contentResolver;
        }

        @Override // p005b.p143g.p144a.p147m.p154u.C1681w.c
        /* renamed from: a */
        public InterfaceC1590d<ParcelFileDescriptor> mo982a(Uri uri) {
            return new C1595i(this.f2420a, uri);
        }

        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        @NonNull
        /* renamed from: b */
        public InterfaceC1672n<Uri, ParcelFileDescriptor> mo963b(C1676r c1676r) {
            return new C1681w(this);
        }
    }

    /* renamed from: b.g.a.m.u.w$c */
    public interface c<Data> {
        /* renamed from: a */
        InterfaceC1590d<Data> mo982a(Uri uri);
    }

    /* renamed from: b.g.a.m.u.w$d */
    public static class d implements InterfaceC1673o<Uri, InputStream>, c<InputStream> {

        /* renamed from: a */
        public final ContentResolver f2421a;

        public d(ContentResolver contentResolver) {
            this.f2421a = contentResolver;
        }

        @Override // p005b.p143g.p144a.p147m.p154u.C1681w.c
        /* renamed from: a */
        public InterfaceC1590d<InputStream> mo982a(Uri uri) {
            return new C1601o(this.f2421a, uri);
        }

        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        @NonNull
        /* renamed from: b */
        public InterfaceC1672n<Uri, InputStream> mo963b(C1676r c1676r) {
            return new C1681w(this);
        }
    }

    public C1681w(c<Data> cVar) {
        this.f2418b = cVar;
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: a */
    public boolean mo960a(@NonNull Uri uri) {
        return f2417a.contains(uri.getScheme());
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: b */
    public InterfaceC1672n.a mo961b(@NonNull Uri uri, int i2, int i3, @NonNull C1582n c1582n) {
        Uri uri2 = uri;
        return new InterfaceC1672n.a(new C1798d(uri2), this.f2418b.mo982a(uri2));
    }
}
