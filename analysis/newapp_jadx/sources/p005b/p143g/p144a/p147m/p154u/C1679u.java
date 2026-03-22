package p005b.p143g.p144a.p147m.p154u;

import android.content.res.AssetFileDescriptor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.text.TextUtils;
import androidx.annotation.NonNull;
import java.io.File;
import java.io.InputStream;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;

/* renamed from: b.g.a.m.u.u */
/* loaded from: classes.dex */
public class C1679u<Data> implements InterfaceC1672n<String, Data> {

    /* renamed from: a */
    public final InterfaceC1672n<Uri, Data> f2413a;

    /* renamed from: b.g.a.m.u.u$a */
    public static final class a implements InterfaceC1673o<String, AssetFileDescriptor> {
        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        /* renamed from: b */
        public InterfaceC1672n<String, AssetFileDescriptor> mo963b(@NonNull C1676r c1676r) {
            return new C1679u(c1676r.m979b(Uri.class, AssetFileDescriptor.class));
        }
    }

    /* renamed from: b.g.a.m.u.u$b */
    public static class b implements InterfaceC1673o<String, ParcelFileDescriptor> {
        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        @NonNull
        /* renamed from: b */
        public InterfaceC1672n<String, ParcelFileDescriptor> mo963b(@NonNull C1676r c1676r) {
            return new C1679u(c1676r.m979b(Uri.class, ParcelFileDescriptor.class));
        }
    }

    /* renamed from: b.g.a.m.u.u$c */
    public static class c implements InterfaceC1673o<String, InputStream> {
        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        @NonNull
        /* renamed from: b */
        public InterfaceC1672n<String, InputStream> mo963b(@NonNull C1676r c1676r) {
            return new C1679u(c1676r.m979b(Uri.class, InputStream.class));
        }
    }

    public C1679u(InterfaceC1672n<Uri, Data> interfaceC1672n) {
        this.f2413a = interfaceC1672n;
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: a */
    public /* bridge */ /* synthetic */ boolean mo960a(@NonNull String str) {
        return true;
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: b */
    public InterfaceC1672n.a mo961b(@NonNull String str, int i2, int i3, @NonNull C1582n c1582n) {
        Uri fromFile;
        String str2 = str;
        if (TextUtils.isEmpty(str2)) {
            fromFile = null;
        } else if (str2.charAt(0) == '/') {
            fromFile = Uri.fromFile(new File(str2));
        } else {
            Uri parse = Uri.parse(str2);
            fromFile = parse.getScheme() == null ? Uri.fromFile(new File(str2)) : parse;
        }
        if (fromFile == null || !this.f2413a.mo960a(fromFile)) {
            return null;
        }
        return this.f2413a.mo961b(fromFile, i2, i3, c1582n);
    }
}
