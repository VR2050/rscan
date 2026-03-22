package p005b.p293n.p294a;

import android.content.Context;
import android.os.Handler;
import androidx.annotation.NonNull;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: b.n.a.y */
/* loaded from: classes2.dex */
public class C2671y extends C2670x {
    @Override // p005b.p293n.p294a.C2666t
    /* renamed from: a */
    public boolean mo3108a(@NonNull Context context, @NonNull String str) {
        throw null;
    }

    /* renamed from: b */
    public final boolean m3163b(Context context) {
        if (C2354n.m2384D0() && context.getApplicationInfo().targetSdkVersion >= 33) {
            Handler handler = C2645e0.f7223a;
            if ((context.checkSelfPermission("android.permission.READ_MEDIA_IMAGES") == 0) || mo3108a(context, "android.permission.MANAGE_EXTERNAL_STORAGE")) {
                return true;
            }
        } else if (!C2354n.m2378B0() || context.getApplicationInfo().targetSdkVersion < 30) {
            Handler handler2 = C2645e0.f7223a;
            if (context.checkSelfPermission("android.permission.READ_EXTERNAL_STORAGE") == 0) {
                return true;
            }
        } else {
            Handler handler3 = C2645e0.f7223a;
            if ((context.checkSelfPermission("android.permission.READ_EXTERNAL_STORAGE") == 0) || mo3108a(context, "android.permission.MANAGE_EXTERNAL_STORAGE")) {
                return true;
            }
        }
        return false;
    }
}
