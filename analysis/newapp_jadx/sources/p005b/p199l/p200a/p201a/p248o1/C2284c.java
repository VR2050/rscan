package p005b.p199l.p200a.p201a.p248o1;

import android.text.TextUtils;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.InterfaceC2362v;

/* renamed from: b.l.a.a.o1.c */
/* loaded from: classes.dex */
public final /* synthetic */ class C2284c implements InterfaceC2362v {

    /* renamed from: a */
    public static final /* synthetic */ C2284c f5788a = new C2284c();

    /* renamed from: a */
    public final boolean m2191a(Object obj) {
        String m2320L = C2344d0.m2320L((String) obj);
        return (TextUtils.isEmpty(m2320L) || (m2320L.contains("text") && !m2320L.contains("text/vtt")) || m2320L.contains("html") || m2320L.contains("xml")) ? false : true;
    }
}
