package p005b.p143g.p144a.p147m.p154u;

import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.text.TextUtils;
import androidx.annotation.NonNull;
import java.io.File;
import java.io.FileNotFoundException;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.EnumC1556f;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.EnumC1569a;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1590d;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;
import p005b.p143g.p144a.p169r.C1798d;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.g.a.m.u.k */
/* loaded from: classes.dex */
public final class C1669k implements InterfaceC1672n<Uri, File> {

    /* renamed from: a */
    public final Context f2371a;

    /* renamed from: b.g.a.m.u.k$a */
    public static final class a implements InterfaceC1673o<Uri, File> {

        /* renamed from: a */
        public final Context f2372a;

        public a(Context context) {
            this.f2372a = context;
        }

        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        @NonNull
        /* renamed from: b */
        public InterfaceC1672n<Uri, File> mo963b(C1676r c1676r) {
            return new C1669k(this.f2372a);
        }
    }

    /* renamed from: b.g.a.m.u.k$b */
    public static class b implements InterfaceC1590d<File> {

        /* renamed from: c */
        public static final String[] f2373c = {"_data"};

        /* renamed from: e */
        public final Context f2374e;

        /* renamed from: f */
        public final Uri f2375f;

        public b(Context context, Uri uri) {
            this.f2374e = context;
            this.f2375f = uri;
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        @NonNull
        /* renamed from: a */
        public Class<File> mo832a() {
            return File.class;
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
        public void mo837d(@NonNull EnumC1556f enumC1556f, @NonNull InterfaceC1590d.a<? super File> aVar) {
            Cursor query = this.f2374e.getContentResolver().query(this.f2375f, f2373c, null, null, null);
            if (query != null) {
                try {
                    r0 = query.moveToFirst() ? query.getString(query.getColumnIndexOrThrow("_data")) : null;
                } finally {
                    query.close();
                }
            }
            if (!TextUtils.isEmpty(r0)) {
                aVar.mo840e(new File(r0));
                return;
            }
            StringBuilder m586H = C1499a.m586H("Failed to find file path for: ");
            m586H.append(this.f2375f);
            aVar.mo839c(new FileNotFoundException(m586H.toString()));
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        @NonNull
        public EnumC1569a getDataSource() {
            return EnumC1569a.LOCAL;
        }
    }

    public C1669k(Context context) {
        this.f2371a = context;
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: a */
    public boolean mo960a(@NonNull Uri uri) {
        return C4195m.m4831s0(uri);
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: b */
    public InterfaceC1672n.a<File> mo961b(@NonNull Uri uri, int i2, int i3, @NonNull C1582n c1582n) {
        Uri uri2 = uri;
        return new InterfaceC1672n.a<>(new C1798d(uri2), new b(this.f2371a, uri2));
    }
}
