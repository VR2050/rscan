package com.facebook.react.views.image;

import android.graphics.Shader;
import s0.q;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final d f7804a = new d();

    private d() {
    }

    public static final Shader.TileMode a() {
        return Shader.TileMode.CLAMP;
    }

    public static final q b() {
        q qVar = q.f10122i;
        j.e(qVar, "CENTER_CROP");
        return qVar;
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    public static final q c(String str) {
        if (str != null) {
            switch (str.hashCode()) {
                case -1881872635:
                    if (str.equals("stretch")) {
                        q qVar = q.f10114a;
                        j.e(qVar, "FIT_XY");
                        return qVar;
                    }
                    break;
                case -1364013995:
                    if (str.equals("center")) {
                        q qVar2 = q.f10121h;
                        j.e(qVar2, "CENTER_INSIDE");
                        return qVar2;
                    }
                    break;
                case -934531685:
                    if (str.equals("repeat")) {
                        return i.f7835l.a();
                    }
                    break;
                case 3387192:
                    if (str.equals("none")) {
                        return i.f7835l.a();
                    }
                    break;
                case 94852023:
                    if (str.equals("cover")) {
                        q qVar3 = q.f10122i;
                        j.e(qVar3, "CENTER_CROP");
                        return qVar3;
                    }
                    break;
                case 951526612:
                    if (str.equals("contain")) {
                        q qVar4 = q.f10118e;
                        j.e(qVar4, "FIT_CENTER");
                        return qVar4;
                    }
                    break;
            }
        }
        if (str != null) {
            Y.a.I("ReactNative", "Invalid resize mode: '" + str + "'");
        }
        return b();
    }

    public static final Shader.TileMode d(String str) {
        if (j.b("contain", str) || j.b("cover", str) || j.b("stretch", str) || j.b("center", str) || j.b("none", str)) {
            return Shader.TileMode.CLAMP;
        }
        if (j.b("repeat", str)) {
            return Shader.TileMode.REPEAT;
        }
        if (str != null) {
            Y.a.I("ReactNative", "Invalid resize mode: '" + str + "'");
        }
        return a();
    }
}
