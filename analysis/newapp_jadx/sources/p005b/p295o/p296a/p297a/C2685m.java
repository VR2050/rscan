package p005b.p295o.p296a.p297a;

import java.util.Hashtable;

/* renamed from: b.o.a.a.m */
/* loaded from: classes2.dex */
public class C2685m {

    /* renamed from: a */
    public static e f7338a = new a();

    /* renamed from: b */
    public static c f7339b = new b();

    /* renamed from: b.o.a.a.m$a */
    public static class a implements e {

        /* renamed from: a */
        public final Hashtable f7340a = new Hashtable();
    }

    /* renamed from: b.o.a.a.m$b */
    public static class b implements c {
    }

    /* renamed from: b.o.a.a.m$c */
    public interface c {
    }

    /* renamed from: b.o.a.a.m$d */
    public static class d extends Hashtable {
        public d(a aVar) {
        }
    }

    /* renamed from: b.o.a.a.m$e */
    public interface e {
    }

    /* renamed from: a */
    public static String m3223a(String str) {
        a aVar = (a) f7338a;
        String str2 = (String) aVar.f7340a.get(str);
        if (str2 != null) {
            return str2;
        }
        aVar.f7340a.put(str, str);
        return str;
    }
}
