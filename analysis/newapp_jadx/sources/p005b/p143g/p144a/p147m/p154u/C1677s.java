package p005b.p143g.p144a.p147m.p154u;

import android.content.res.AssetFileDescriptor;
import android.content.res.Resources;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import androidx.annotation.NonNull;
import java.io.InputStream;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;

/* renamed from: b.g.a.m.u.s */
/* loaded from: classes.dex */
public class C1677s<Data> implements InterfaceC1672n<Integer, Data> {

    /* renamed from: a */
    public final InterfaceC1672n<Uri, Data> f2406a;

    /* renamed from: b */
    public final Resources f2407b;

    /* renamed from: b.g.a.m.u.s$a */
    public static final class a implements InterfaceC1673o<Integer, AssetFileDescriptor> {

        /* renamed from: a */
        public final Resources f2408a;

        public a(Resources resources) {
            this.f2408a = resources;
        }

        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        /* renamed from: b */
        public InterfaceC1672n<Integer, AssetFileDescriptor> mo963b(C1676r c1676r) {
            return new C1677s(this.f2408a, c1676r.m979b(Uri.class, AssetFileDescriptor.class));
        }
    }

    /* renamed from: b.g.a.m.u.s$b */
    public static class b implements InterfaceC1673o<Integer, ParcelFileDescriptor> {

        /* renamed from: a */
        public final Resources f2409a;

        public b(Resources resources) {
            this.f2409a = resources;
        }

        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        @NonNull
        /* renamed from: b */
        public InterfaceC1672n<Integer, ParcelFileDescriptor> mo963b(C1676r c1676r) {
            return new C1677s(this.f2409a, c1676r.m979b(Uri.class, ParcelFileDescriptor.class));
        }
    }

    /* renamed from: b.g.a.m.u.s$c */
    public static class c implements InterfaceC1673o<Integer, InputStream> {

        /* renamed from: a */
        public final Resources f2410a;

        public c(Resources resources) {
            this.f2410a = resources;
        }

        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        @NonNull
        /* renamed from: b */
        public InterfaceC1672n<Integer, InputStream> mo963b(C1676r c1676r) {
            return new C1677s(this.f2410a, c1676r.m979b(Uri.class, InputStream.class));
        }
    }

    /* renamed from: b.g.a.m.u.s$d */
    public static class d implements InterfaceC1673o<Integer, Uri> {

        /* renamed from: a */
        public final Resources f2411a;

        public d(Resources resources) {
            this.f2411a = resources;
        }

        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        @NonNull
        /* renamed from: b */
        public InterfaceC1672n<Integer, Uri> mo963b(C1676r c1676r) {
            return new C1677s(this.f2411a, C1680v.f2414a);
        }
    }

    public C1677s(Resources resources, InterfaceC1672n<Uri, Data> interfaceC1672n) {
        this.f2407b = resources;
        this.f2406a = interfaceC1672n;
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: a */
    public /* bridge */ /* synthetic */ boolean mo960a(@NonNull Integer num) {
        return true;
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: b */
    public InterfaceC1672n.a mo961b(@NonNull Integer num, int i2, int i3, @NonNull C1582n c1582n) {
        Uri uri;
        Integer num2 = num;
        try {
            uri = Uri.parse("android.resource://" + this.f2407b.getResourcePackageName(num2.intValue()) + '/' + this.f2407b.getResourceTypeName(num2.intValue()) + '/' + this.f2407b.getResourceEntryName(num2.intValue()));
        } catch (Resources.NotFoundException unused) {
            if (Log.isLoggable("ResourceLoader", 5)) {
                String str = "Received invalid resource id: " + num2;
            }
            uri = null;
        }
        if (uri == null) {
            return null;
        }
        return this.f2406a.mo961b(uri, i2, i3, c1582n);
    }
}
