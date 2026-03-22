package p005b.p143g.p144a.p147m.p154u.p155y;

import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.os.ParcelFileDescriptor;
import android.provider.MediaStore;
import android.text.TextUtils;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.InputStream;
import p005b.p143g.p144a.EnumC1556f;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.EnumC1569a;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1590d;
import p005b.p143g.p144a.p147m.p154u.C1676r;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1672n;
import p005b.p143g.p144a.p147m.p154u.InterfaceC1673o;
import p005b.p143g.p144a.p169r.C1798d;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@RequiresApi(29)
/* renamed from: b.g.a.m.u.y.e */
/* loaded from: classes.dex */
public final class C1687e<DataT> implements InterfaceC1672n<Uri, DataT> {

    /* renamed from: a */
    public final Context f2433a;

    /* renamed from: b */
    public final InterfaceC1672n<File, DataT> f2434b;

    /* renamed from: c */
    public final InterfaceC1672n<Uri, DataT> f2435c;

    /* renamed from: d */
    public final Class<DataT> f2436d;

    /* renamed from: b.g.a.m.u.y.e$a */
    public static abstract class a<DataT> implements InterfaceC1673o<Uri, DataT> {

        /* renamed from: a */
        public final Context f2437a;

        /* renamed from: b */
        public final Class<DataT> f2438b;

        public a(Context context, Class<DataT> cls) {
            this.f2437a = context;
            this.f2438b = cls;
        }

        @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1673o
        @NonNull
        /* renamed from: b */
        public final InterfaceC1672n<Uri, DataT> mo963b(@NonNull C1676r c1676r) {
            return new C1687e(this.f2437a, c1676r.m979b(File.class, this.f2438b), c1676r.m979b(Uri.class, this.f2438b), this.f2438b);
        }
    }

    @RequiresApi(29)
    /* renamed from: b.g.a.m.u.y.e$b */
    public static final class b extends a<ParcelFileDescriptor> {
        public b(Context context) {
            super(context, ParcelFileDescriptor.class);
        }
    }

    @RequiresApi(29)
    /* renamed from: b.g.a.m.u.y.e$c */
    public static final class c extends a<InputStream> {
        public c(Context context) {
            super(context, InputStream.class);
        }
    }

    /* renamed from: b.g.a.m.u.y.e$d */
    public static final class d<DataT> implements InterfaceC1590d<DataT> {

        /* renamed from: c */
        public static final String[] f2439c = {"_data"};

        /* renamed from: e */
        public final Context f2440e;

        /* renamed from: f */
        public final InterfaceC1672n<File, DataT> f2441f;

        /* renamed from: g */
        public final InterfaceC1672n<Uri, DataT> f2442g;

        /* renamed from: h */
        public final Uri f2443h;

        /* renamed from: i */
        public final int f2444i;

        /* renamed from: j */
        public final int f2445j;

        /* renamed from: k */
        public final C1582n f2446k;

        /* renamed from: l */
        public final Class<DataT> f2447l;

        /* renamed from: m */
        public volatile boolean f2448m;

        /* renamed from: n */
        @Nullable
        public volatile InterfaceC1590d<DataT> f2449n;

        public d(Context context, InterfaceC1672n<File, DataT> interfaceC1672n, InterfaceC1672n<Uri, DataT> interfaceC1672n2, Uri uri, int i2, int i3, C1582n c1582n, Class<DataT> cls) {
            this.f2440e = context.getApplicationContext();
            this.f2441f = interfaceC1672n;
            this.f2442g = interfaceC1672n2;
            this.f2443h = uri;
            this.f2444i = i2;
            this.f2445j = i3;
            this.f2446k = c1582n;
            this.f2447l = cls;
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        @NonNull
        /* renamed from: a */
        public Class<DataT> mo832a() {
            return this.f2447l;
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        /* renamed from: b */
        public void mo835b() {
            InterfaceC1590d<DataT> interfaceC1590d = this.f2449n;
            if (interfaceC1590d != null) {
                interfaceC1590d.mo835b();
            }
        }

        @Nullable
        /* renamed from: c */
        public final InterfaceC1590d<DataT> m983c() {
            InterfaceC1672n.a<DataT> mo961b;
            Cursor cursor = null;
            if (Environment.isExternalStorageLegacy()) {
                InterfaceC1672n<File, DataT> interfaceC1672n = this.f2441f;
                Uri uri = this.f2443h;
                try {
                    Cursor query = this.f2440e.getContentResolver().query(uri, f2439c, null, null, null);
                    if (query != null) {
                        try {
                            if (query.moveToFirst()) {
                                String string = query.getString(query.getColumnIndexOrThrow("_data"));
                                if (TextUtils.isEmpty(string)) {
                                    throw new FileNotFoundException("File path was empty in media store for: " + uri);
                                }
                                File file = new File(string);
                                query.close();
                                mo961b = interfaceC1672n.mo961b(file, this.f2444i, this.f2445j, this.f2446k);
                            }
                        } catch (Throwable th) {
                            th = th;
                            cursor = query;
                            if (cursor != null) {
                                cursor.close();
                            }
                            throw th;
                        }
                    }
                    throw new FileNotFoundException("Failed to media store entry for: " + uri);
                } catch (Throwable th2) {
                    th = th2;
                }
            } else {
                mo961b = this.f2442g.mo961b(this.f2440e.checkSelfPermission("android.permission.ACCESS_MEDIA_LOCATION") == 0 ? MediaStore.setRequireOriginal(this.f2443h) : this.f2443h, this.f2444i, this.f2445j, this.f2446k);
            }
            if (mo961b != null) {
                return mo961b.f2383c;
            }
            return null;
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        public void cancel() {
            this.f2448m = true;
            InterfaceC1590d<DataT> interfaceC1590d = this.f2449n;
            if (interfaceC1590d != null) {
                interfaceC1590d.cancel();
            }
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        /* renamed from: d */
        public void mo837d(@NonNull EnumC1556f enumC1556f, @NonNull InterfaceC1590d.a<? super DataT> aVar) {
            try {
                InterfaceC1590d<DataT> m983c = m983c();
                if (m983c == null) {
                    aVar.mo839c(new IllegalArgumentException("Failed to build fetcher for: " + this.f2443h));
                    return;
                }
                this.f2449n = m983c;
                if (this.f2448m) {
                    cancel();
                } else {
                    m983c.mo837d(enumC1556f, aVar);
                }
            } catch (FileNotFoundException e2) {
                aVar.mo839c(e2);
            }
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1590d
        @NonNull
        public EnumC1569a getDataSource() {
            return EnumC1569a.LOCAL;
        }
    }

    public C1687e(Context context, InterfaceC1672n<File, DataT> interfaceC1672n, InterfaceC1672n<Uri, DataT> interfaceC1672n2, Class<DataT> cls) {
        this.f2433a = context.getApplicationContext();
        this.f2434b = interfaceC1672n;
        this.f2435c = interfaceC1672n2;
        this.f2436d = cls;
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: a */
    public boolean mo960a(@NonNull Uri uri) {
        return Build.VERSION.SDK_INT >= 29 && C4195m.m4831s0(uri);
    }

    @Override // p005b.p143g.p144a.p147m.p154u.InterfaceC1672n
    /* renamed from: b */
    public InterfaceC1672n.a mo961b(@NonNull Uri uri, int i2, int i3, @NonNull C1582n c1582n) {
        Uri uri2 = uri;
        return new InterfaceC1672n.a(new C1798d(uri2), new d(this.f2433a, this.f2434b, this.f2435c, uri2, i2, i3, c1582n, this.f2436d));
    }
}
