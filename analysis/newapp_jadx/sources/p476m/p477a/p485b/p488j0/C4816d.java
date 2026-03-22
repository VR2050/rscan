package p476m.p477a.p485b.p488j0;

import p476m.p477a.p485b.InterfaceC4896p;

/* renamed from: m.a.b.j0.d */
/* loaded from: classes3.dex */
public class C4816d implements InterfaceC4896p {

    /* renamed from: a */
    public static final C4816d f12313a = new C4816d();

    /* renamed from: b */
    public static final String[] f12314b = {"GET", "HEAD", "OPTIONS", "TRACE", "CONNECT"};

    /* renamed from: c */
    public static final String[] f12315c = {"POST", "PUT", "DELETE", "PATCH"};

    /* renamed from: a */
    public static boolean m5485a(String[] strArr, String str) {
        for (String str2 : strArr) {
            if (str2.equalsIgnoreCase(str)) {
                return true;
            }
        }
        return false;
    }
}
