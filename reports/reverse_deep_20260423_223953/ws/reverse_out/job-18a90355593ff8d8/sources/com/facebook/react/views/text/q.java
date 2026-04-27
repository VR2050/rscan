package com.facebook.react.views.text;

import android.os.Build;
import android.text.TextUtils;
import com.facebook.react.common.mapbuffer.a;
import com.facebook.react.uimanager.C0444f0;
import com.facebook.react.uimanager.C0448h0;
import com.facebook.react.uimanager.C0469s0;
import java.util.ArrayList;
import java.util.Iterator;
import org.chromium.support_lib_boundary.WebSettingsBoundaryInterface;

/* JADX INFO: loaded from: classes.dex */
public class q {

    /* JADX INFO: renamed from: F, reason: collision with root package name */
    private static final int f8134F = 0;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    protected int f8144e;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    protected int f8146g;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    protected float f8140a = Float.NaN;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    protected boolean f8141b = false;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    protected boolean f8142c = true;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    protected float f8143d = Float.NaN;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    protected boolean f8145f = false;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    protected float f8147h = Float.NaN;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    protected int f8148i = -1;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    protected int f8149j = -1;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    protected float f8150k = -1.0f;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    protected float f8151l = -1.0f;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    protected float f8152m = Float.NaN;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    protected int f8153n = 0;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    protected int f8154o = -1;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    protected t f8155p = t.f8178c;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    protected float f8156q = 0.0f;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    protected float f8157r = 0.0f;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    protected float f8158s = 0.0f;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    protected int f8159t = 1426063360;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    protected boolean f8160u = false;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    protected boolean f8161v = false;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    protected boolean f8162w = true;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    protected C0448h0.d f8163x = null;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    protected C0448h0.e f8164y = null;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    protected int f8165z = -1;

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    protected int f8135A = -1;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    protected String f8136B = null;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    protected String f8137C = null;

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    protected boolean f8138D = false;

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    protected float f8139E = Float.NaN;

    private q() {
    }

    private void A(float f3) {
        this.f8147h = f3;
    }

    private void B(C0448h0.e eVar) {
        this.f8164y = eVar;
    }

    private void C(String str) {
        this.f8160u = false;
        this.f8161v = false;
        if (str != null) {
            for (String str2 : str.split("-")) {
                if ("underline".equals(str2)) {
                    this.f8160u = true;
                } else if ("strikethrough".equals(str2)) {
                    this.f8161v = true;
                }
            }
        }
    }

    private void D(int i3) {
        if (i3 != this.f8159t) {
            this.f8159t = i3;
        }
    }

    private void E(float f3) {
        this.f8156q = C0444f0.h(f3);
    }

    private void F(float f3) {
        this.f8157r = C0444f0.h(f3);
    }

    private void G(float f3) {
        if (f3 != this.f8158s) {
            this.f8158s = f3;
        }
    }

    private void H(String str) {
        if (str == null || "none".equals(str)) {
            this.f8155p = t.f8178c;
            return;
        }
        if ("uppercase".equals(str)) {
            this.f8155p = t.f8179d;
            return;
        }
        if ("lowercase".equals(str)) {
            this.f8155p = t.f8180e;
            return;
        }
        if ("capitalize".equals(str)) {
            this.f8155p = t.f8181f;
            return;
        }
        Y.a.I("ReactNative", "Invalid textTransform: " + str);
        this.f8155p = t.f8178c;
    }

    public static q a(com.facebook.react.common.mapbuffer.a aVar) {
        q qVar = new q();
        Iterator it = aVar.iterator();
        while (it.hasNext()) {
            a.c cVar = (a.c) it.next();
            switch (cVar.getKey()) {
                case WebSettingsBoundaryInterface.ForceDarkBehavior.FORCE_DARK_ONLY /* 0 */:
                    qVar.q(Integer.valueOf(cVar.c()));
                    break;
                case 1:
                    qVar.p(Integer.valueOf(cVar.c()));
                    break;
                case 2:
                    qVar.A((float) cVar.e());
                    break;
                case 3:
                    qVar.r(cVar.b());
                    break;
                case 4:
                    qVar.s((float) cVar.e());
                    break;
                case 6:
                    qVar.v(cVar.b());
                    break;
                case 7:
                    qVar.t(cVar.b());
                    break;
                case 8:
                    qVar.u(cVar.d());
                    break;
                case 9:
                    qVar.o(cVar.f());
                    break;
                case 10:
                    qVar.x((float) cVar.e());
                    break;
                case 11:
                    qVar.y((float) cVar.e());
                    break;
                case 15:
                    qVar.C(cVar.b());
                    break;
                case 18:
                    qVar.G((float) cVar.e());
                    break;
                case 19:
                    qVar.D(cVar.c());
                    break;
                case 20:
                    qVar.E((float) cVar.e());
                    break;
                case 21:
                    qVar.F((float) cVar.e());
                    break;
                case 23:
                    qVar.w(cVar.b());
                    break;
                case 24:
                    qVar.n(cVar.b());
                    break;
                case 26:
                    qVar.B(C0448h0.e.values()[cVar.c()]);
                    break;
                case 27:
                    qVar.H(cVar.b());
                    break;
                case 29:
                    qVar.z((float) cVar.e());
                    break;
            }
        }
        return qVar;
    }

    public static int g(String str) {
        if (str == null) {
            return 0;
        }
        if (str.equals("normal")) {
            return 1;
        }
        return !str.equals("none") ? 2 : 0;
    }

    public static int h(C0469s0 c0469s0, int i3) {
        if (!c0469s0.c("textAlign")) {
            return i3;
        }
        if (!"justify".equals(c0469s0.b("textAlign")) || Build.VERSION.SDK_INT < 26) {
            return f8134F;
        }
        return 1;
    }

    public static int i(String str) {
        if (str == null || "undefined".equals(str)) {
            return -1;
        }
        if ("rtl".equals(str)) {
            return 1;
        }
        if ("ltr".equals(str)) {
            return 0;
        }
        Y.a.I("ReactNative", "Invalid layoutDirection: " + str);
        return -1;
    }

    public static int l(C0469s0 c0469s0, boolean z3, int i3) {
        if (!c0469s0.c("textAlign")) {
            return i3;
        }
        String strB = c0469s0.b("textAlign");
        if ("justify".equals(strB)) {
            return 3;
        }
        if (strB != null && !"auto".equals(strB)) {
            if ("left".equals(strB)) {
                return z3 ? 5 : 3;
            }
            if ("right".equals(strB)) {
                return z3 ? 3 : 5;
            }
            if ("center".equals(strB)) {
                return 1;
            }
            Y.a.I("ReactNative", "Invalid textAlign: " + strB);
        }
        return 0;
    }

    public static int m(String str) {
        if (str == null) {
            return 1;
        }
        if (str.equals("balanced")) {
            return 2;
        }
        return !str.equals("simple") ? 1 : 0;
    }

    private void n(String str) {
        if (str == null) {
            this.f8163x = null;
        } else {
            this.f8163x = C0448h0.d.c(str);
        }
    }

    private void o(boolean z3) {
        if (z3 != this.f8142c) {
            this.f8142c = z3;
            s(this.f8150k);
            y(this.f8151l);
        }
    }

    private void p(Integer num) {
        boolean z3 = num != null;
        this.f8145f = z3;
        if (z3) {
            this.f8146g = num.intValue();
        }
    }

    private void q(Integer num) {
        boolean z3 = num != null;
        this.f8141b = z3;
        if (z3) {
            this.f8144e = num.intValue();
        }
    }

    private void r(String str) {
        this.f8136B = str;
    }

    private void s(float f3) {
        this.f8150k = f3;
        if (f3 != -1.0f) {
            f3 = (float) (this.f8142c ? Math.ceil(C0444f0.k(f3, this.f8143d)) : Math.ceil(C0444f0.h(f3)));
        }
        this.f8149j = (int) f3;
    }

    private void t(String str) {
        this.f8165z = o.b(str);
    }

    private void u(com.facebook.react.common.mapbuffer.a aVar) {
        if (aVar == null || aVar.getCount() == 0) {
            this.f8137C = null;
            return;
        }
        ArrayList arrayList = new ArrayList();
        Iterator it = aVar.iterator();
        while (it.hasNext()) {
            String strB = ((a.c) it.next()).b();
            if (strB != null) {
                switch (strB) {
                    case "stylistic-thirteen":
                        arrayList.add("'ss13'");
                        break;
                    case "stylistic-fifteen":
                        arrayList.add("'ss15'");
                        break;
                    case "stylistic-eighteen":
                        arrayList.add("'ss18'");
                        break;
                    case "proportional-nums":
                        arrayList.add("'pnum'");
                        break;
                    case "lining-nums":
                        arrayList.add("'lnum'");
                        break;
                    case "tabular-nums":
                        arrayList.add("'tnum'");
                        break;
                    case "oldstyle-nums":
                        arrayList.add("'onum'");
                        break;
                    case "stylistic-eight":
                        arrayList.add("'ss08'");
                        break;
                    case "stylistic-seven":
                        arrayList.add("'ss07'");
                        break;
                    case "stylistic-three":
                        arrayList.add("'ss03'");
                        break;
                    case "stylistic-eleven":
                        arrayList.add("'ss11'");
                        break;
                    case "stylistic-five":
                        arrayList.add("'ss05'");
                        break;
                    case "stylistic-four":
                        arrayList.add("'ss04'");
                        break;
                    case "stylistic-nine":
                        arrayList.add("'ss09'");
                        break;
                    case "stylistic-one":
                        arrayList.add("'ss01'");
                        break;
                    case "stylistic-six":
                        arrayList.add("'ss06'");
                        break;
                    case "stylistic-ten":
                        arrayList.add("'ss10'");
                        break;
                    case "stylistic-two":
                        arrayList.add("'ss02'");
                        break;
                    case "stylistic-sixteen":
                        arrayList.add("'ss16'");
                        break;
                    case "stylistic-twelve":
                        arrayList.add("'ss12'");
                        break;
                    case "stylistic-twenty":
                        arrayList.add("'ss20'");
                        break;
                    case "small-caps":
                        arrayList.add("'smcp'");
                        break;
                    case "stylistic-nineteen":
                        arrayList.add("'ss19'");
                        break;
                    case "stylistic-fourteen":
                        arrayList.add("'ss14'");
                        break;
                    case "stylistic-seventeen":
                        arrayList.add("'ss17'");
                        break;
                }
            }
        }
        this.f8137C = TextUtils.join(", ", arrayList);
    }

    private void v(String str) {
        this.f8135A = o.d(str);
    }

    private void w(String str) {
        this.f8154o = i(str);
    }

    private void x(float f3) {
        this.f8152m = f3;
    }

    private void y(float f3) {
        this.f8151l = f3;
        if (f3 == -1.0f) {
            this.f8140a = Float.NaN;
        } else {
            this.f8140a = this.f8142c ? C0444f0.j(f3) : C0444f0.h(f3);
        }
    }

    private void z(float f3) {
        if (f3 != this.f8143d) {
            this.f8143d = f3;
            s(this.f8150k);
            y(this.f8151l);
        }
    }

    public int b() {
        return this.f8149j;
    }

    public float c() {
        if (!Float.isNaN(this.f8140a) && !Float.isNaN(this.f8139E)) {
            float f3 = this.f8139E;
            if (f3 > this.f8140a) {
                return f3;
            }
        }
        return this.f8140a;
    }

    public String d() {
        return this.f8136B;
    }

    public int e() {
        return this.f8165z;
    }

    public int f() {
        return this.f8135A;
    }

    public float j() {
        float fJ = this.f8142c ? C0444f0.j(this.f8152m) : C0444f0.h(this.f8152m);
        int i3 = this.f8149j;
        if (i3 > 0) {
            return fJ / i3;
        }
        throw new IllegalArgumentException("FontSize should be a positive value. Current value: " + this.f8149j);
    }

    public float k() {
        return this.f8147h;
    }
}
