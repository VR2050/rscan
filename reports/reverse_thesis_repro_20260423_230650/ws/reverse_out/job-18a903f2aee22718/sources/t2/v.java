package t2;

/* JADX INFO: loaded from: classes.dex */
public class v {
    public x2.b b(Class cls) {
        return new e(cls);
    }

    public x2.c c(Class cls, String str) {
        return new o(cls, str);
    }

    public String e(g gVar) {
        String string = gVar.getClass().getGenericInterfaces()[0].toString();
        return string.startsWith("kotlin.jvm.functions.") ? string.substring(21) : string;
    }

    public String f(k kVar) {
        return e(kVar);
    }

    public x2.d a(h hVar) {
        return hVar;
    }

    public x2.e d(l lVar) {
        return lVar;
    }
}
