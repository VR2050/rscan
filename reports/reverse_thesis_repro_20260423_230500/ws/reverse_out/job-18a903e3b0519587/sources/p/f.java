package p;

import android.content.Context;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import java.util.ArrayList;
import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import l.C0610e;
import l.C0612g;
import p.g;
import q.InterfaceC0651a;

/* JADX INFO: loaded from: classes.dex */
abstract class f {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    static final C0610e f9751a = new C0610e(16);

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final ExecutorService f9752b = h.a("fonts-androidx", 10, 10000);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    static final Object f9753c = new Object();

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    static final C0612g f9754d = new C0612g();

    class a implements Callable {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ String f9755a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ Context f9756b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ p.e f9757c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ int f9758d;

        a(String str, Context context, p.e eVar, int i3) {
            this.f9755a = str;
            this.f9756b = context;
            this.f9757c = eVar;
            this.f9758d = i3;
        }

        @Override // java.util.concurrent.Callable
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public e call() {
            return f.c(this.f9755a, this.f9756b, this.f9757c, this.f9758d);
        }
    }

    class b implements InterfaceC0651a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ C0641a f9759a;

        b(C0641a c0641a) {
            this.f9759a = c0641a;
        }

        @Override // q.InterfaceC0651a
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public void a(e eVar) {
            if (eVar == null) {
                eVar = new e(-3);
            }
            this.f9759a.b(eVar);
        }
    }

    class c implements Callable {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ String f9760a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ Context f9761b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ p.e f9762c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ int f9763d;

        c(String str, Context context, p.e eVar, int i3) {
            this.f9760a = str;
            this.f9761b = context;
            this.f9762c = eVar;
            this.f9763d = i3;
        }

        @Override // java.util.concurrent.Callable
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public e call() {
            try {
                return f.c(this.f9760a, this.f9761b, this.f9762c, this.f9763d);
            } catch (Throwable unused) {
                return new e(-3);
            }
        }
    }

    class d implements InterfaceC0651a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ String f9764a;

        d(String str) {
            this.f9764a = str;
        }

        @Override // q.InterfaceC0651a
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public void a(e eVar) {
            synchronized (f.f9753c) {
                try {
                    C0612g c0612g = f.f9754d;
                    ArrayList arrayList = (ArrayList) c0612g.get(this.f9764a);
                    if (arrayList == null) {
                        return;
                    }
                    c0612g.remove(this.f9764a);
                    for (int i3 = 0; i3 < arrayList.size(); i3++) {
                        ((InterfaceC0651a) arrayList.get(i3)).a(eVar);
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
    }

    private static String a(p.e eVar, int i3) {
        return eVar.d() + "-" + i3;
    }

    private static int b(g.a aVar) {
        int i3 = 1;
        if (aVar.c() != 0) {
            return aVar.c() != 1 ? -3 : -2;
        }
        g.b[] bVarArrB = aVar.b();
        if (bVarArrB != null && bVarArrB.length != 0) {
            i3 = 0;
            for (g.b bVar : bVarArrB) {
                int iB = bVar.b();
                if (iB != 0) {
                    if (iB < 0) {
                        return -3;
                    }
                    return iB;
                }
            }
        }
        return i3;
    }

    static e c(String str, Context context, p.e eVar, int i3) {
        C0610e c0610e = f9751a;
        Typeface typeface = (Typeface) c0610e.c(str);
        if (typeface != null) {
            return new e(typeface);
        }
        try {
            g.a aVarE = p.d.e(context, eVar, null);
            int iB = b(aVarE);
            if (iB != 0) {
                return new e(iB);
            }
            Typeface typefaceB = androidx.core.graphics.d.b(context, null, aVarE.b(), i3);
            if (typefaceB == null) {
                return new e(-3);
            }
            c0610e.d(str, typefaceB);
            return new e(typefaceB);
        } catch (PackageManager.NameNotFoundException unused) {
            return new e(-1);
        }
    }

    static Typeface d(Context context, p.e eVar, int i3, Executor executor, C0641a c0641a) {
        String strA = a(eVar, i3);
        Typeface typeface = (Typeface) f9751a.c(strA);
        if (typeface != null) {
            c0641a.b(new e(typeface));
            return typeface;
        }
        b bVar = new b(c0641a);
        synchronized (f9753c) {
            try {
                C0612g c0612g = f9754d;
                ArrayList arrayList = (ArrayList) c0612g.get(strA);
                if (arrayList != null) {
                    arrayList.add(bVar);
                    return null;
                }
                ArrayList arrayList2 = new ArrayList();
                arrayList2.add(bVar);
                c0612g.put(strA, arrayList2);
                c cVar = new c(strA, context, eVar, i3);
                if (executor == null) {
                    executor = f9752b;
                }
                h.b(executor, cVar, new d(strA));
                return null;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    static Typeface e(Context context, p.e eVar, C0641a c0641a, int i3, int i4) {
        String strA = a(eVar, i3);
        Typeface typeface = (Typeface) f9751a.c(strA);
        if (typeface != null) {
            c0641a.b(new e(typeface));
            return typeface;
        }
        if (i4 == -1) {
            e eVarC = c(strA, context, eVar, i3);
            c0641a.b(eVarC);
            return eVarC.f9765a;
        }
        try {
            e eVar2 = (e) h.c(f9752b, new a(strA, context, eVar, i3), i4);
            c0641a.b(eVar2);
            return eVar2.f9765a;
        } catch (InterruptedException unused) {
            c0641a.b(new e(-3));
            return null;
        }
    }

    static final class e {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final Typeface f9765a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final int f9766b;

        e(int i3) {
            this.f9765a = null;
            this.f9766b = i3;
        }

        boolean a() {
            return this.f9766b == 0;
        }

        e(Typeface typeface) {
            this.f9765a = typeface;
            this.f9766b = 0;
        }
    }
}
