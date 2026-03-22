package p005b.p293n.p294a;

import android.content.Context;
import android.content.Intent;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.Iterator;
import java.util.List;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: b.n.a.s */
/* loaded from: classes2.dex */
public final class C2665s {

    /* renamed from: a */
    @NonNull
    public static final C2666t f7268a = new C2637a0();

    /* JADX WARN: Code restructure failed: missing block: B:72:0x0118, code lost:
    
        if (p005b.p293n.p294a.C2645e0.m3115a(r11, r12) != false) goto L13;
     */
    /* JADX WARN: Removed duplicated region for block: B:281:0x04b6  */
    /* renamed from: a */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static android.content.Intent m3159a(@androidx.annotation.NonNull android.content.Context r11, @androidx.annotation.NonNull java.lang.String r12) {
        /*
            Method dump skipped, instructions count: 1308
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p293n.p294a.C2665s.m3159a(android.content.Context, java.lang.String):android.content.Intent");
    }

    /* renamed from: b */
    public static Intent m3160b(@NonNull Context context, @Nullable List<String> list) {
        boolean z;
        if (list == null || list.isEmpty()) {
            return C2650h.m3142e(context);
        }
        if (!list.isEmpty()) {
            Iterator<String> it = list.iterator();
            while (it.hasNext()) {
                if (C2643d0.m3114b(it.next())) {
                    z = true;
                    break;
                }
            }
        }
        z = false;
        if (!z) {
            return list.size() == 1 ? m3159a(context, list.get(0)) : C2650h.m3143f(context, list);
        }
        int size = list.size();
        if (size == 1) {
            return m3159a(context, list.get(0));
        }
        if (size != 2) {
            if (size == 3 && C2354n.m2378B0() && C2645e0.m3119e(list, "android.permission.MANAGE_EXTERNAL_STORAGE") && C2645e0.m3119e(list, "android.permission.READ_EXTERNAL_STORAGE") && C2645e0.m3119e(list, "android.permission.WRITE_EXTERNAL_STORAGE")) {
                return m3159a(context, "android.permission.MANAGE_EXTERNAL_STORAGE");
            }
        } else if (!C2354n.m2384D0() && C2645e0.m3119e(list, "android.permission.NOTIFICATION_SERVICE") && C2645e0.m3119e(list, "android.permission.POST_NOTIFICATIONS")) {
            return m3159a(context, "android.permission.NOTIFICATION_SERVICE");
        }
        return C2650h.m3142e(context);
    }

    /* renamed from: c */
    public static boolean m3161c(@NonNull Context context, @NonNull String str) {
        return f7268a.mo3108a(context, str);
    }

    /* renamed from: d */
    public static boolean m3162d(@NonNull Context context, @NonNull List<String> list) {
        if (list.isEmpty()) {
            return false;
        }
        Iterator<String> it = list.iterator();
        while (it.hasNext()) {
            if (!m3161c(context, it.next())) {
                return false;
            }
        }
        return true;
    }
}
