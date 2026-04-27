package com.facebook.react.views.text;

import android.graphics.Color;
import android.os.Build;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.uimanager.C0438c0;
import com.facebook.react.uimanager.C0444f0;
import com.facebook.react.uimanager.C0448h0;
import com.facebook.react.uimanager.C0467r0;
import com.facebook.react.uimanager.InterfaceC0466q0;
import com.facebook.react.uimanager.P;
import com.facebook.react.uimanager.U;
import com.facebook.yoga.YogaValue;
import com.facebook.yoga.w;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public abstract class c extends U {

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    protected r f8046A;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    protected boolean f8047B;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    protected int f8048C;

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    protected boolean f8049D;

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    protected int f8050E;

    /* JADX INFO: renamed from: F, reason: collision with root package name */
    protected C0448h0.d f8051F;

    /* JADX INFO: renamed from: G, reason: collision with root package name */
    protected C0448h0.e f8052G;

    /* JADX INFO: renamed from: H, reason: collision with root package name */
    protected int f8053H;

    /* JADX INFO: renamed from: I, reason: collision with root package name */
    protected int f8054I;

    /* JADX INFO: renamed from: J, reason: collision with root package name */
    protected int f8055J;

    /* JADX INFO: renamed from: K, reason: collision with root package name */
    protected int f8056K;

    /* JADX INFO: renamed from: L, reason: collision with root package name */
    protected int f8057L;

    /* JADX INFO: renamed from: M, reason: collision with root package name */
    protected float f8058M;

    /* JADX INFO: renamed from: N, reason: collision with root package name */
    protected float f8059N;

    /* JADX INFO: renamed from: O, reason: collision with root package name */
    protected float f8060O;

    /* JADX INFO: renamed from: P, reason: collision with root package name */
    protected int f8061P;

    /* JADX INFO: renamed from: Q, reason: collision with root package name */
    protected boolean f8062Q;

    /* JADX INFO: renamed from: R, reason: collision with root package name */
    protected boolean f8063R;

    /* JADX INFO: renamed from: S, reason: collision with root package name */
    protected boolean f8064S;

    /* JADX INFO: renamed from: T, reason: collision with root package name */
    protected boolean f8065T;

    /* JADX INFO: renamed from: U, reason: collision with root package name */
    protected float f8066U;

    /* JADX INFO: renamed from: V, reason: collision with root package name */
    protected int f8067V;

    /* JADX INFO: renamed from: W, reason: collision with root package name */
    protected int f8068W;

    /* JADX INFO: renamed from: X, reason: collision with root package name */
    protected String f8069X;

    /* JADX INFO: renamed from: Y, reason: collision with root package name */
    protected String f8070Y;

    /* JADX INFO: renamed from: Z, reason: collision with root package name */
    protected boolean f8071Z;

    /* JADX INFO: renamed from: a0, reason: collision with root package name */
    protected Map f8072a0;

    public c() {
        this(null);
    }

    private static void w1(c cVar, SpannableStringBuilder spannableStringBuilder, List list, r rVar, boolean z3, Map map, int i3) {
        float fE0;
        float fU;
        r rVarA = rVar != null ? rVar.a(cVar.f8046A) : cVar.f8046A;
        int iC = cVar.C();
        for (int i4 = 0; i4 < iC; i4++) {
            C0467r0 c0467r0N = cVar.N(i4);
            if (c0467r0N instanceof d) {
                spannableStringBuilder.append((CharSequence) t.b(((d) c0467r0N).v1(), rVarA.l()));
            } else if (c0467r0N instanceof c) {
                w1((c) c0467r0N, spannableStringBuilder, list, rVarA, z3, map, spannableStringBuilder.length());
            } else if (c0467r0N instanceof X1.a) {
                spannableStringBuilder.append("0");
                list.add(new Y1.n(spannableStringBuilder.length() - 1, spannableStringBuilder.length(), ((X1.a) c0467r0N).w1()));
            } else {
                if (!z3) {
                    throw new P("Unexpected view type nested under a <Text> or <TextInput> node: " + c0467r0N.getClass());
                }
                int iH = c0467r0N.H();
                YogaValue yogaValueC = c0467r0N.c();
                YogaValue yogaValueZ = c0467r0N.z();
                w wVar = yogaValueC.f8416b;
                w wVar2 = w.POINT;
                if (wVar == wVar2 && yogaValueZ.f8416b == wVar2) {
                    fE0 = yogaValueC.f8415a;
                    fU = yogaValueZ.f8415a;
                } else {
                    c0467r0N.M();
                    fE0 = c0467r0N.e0();
                    fU = c0467r0N.u();
                }
                spannableStringBuilder.append("0");
                list.add(new Y1.n(spannableStringBuilder.length() - 1, spannableStringBuilder.length(), new Y1.q(iH, (int) fE0, (int) fU)));
                map.put(Integer.valueOf(iH), c0467r0N);
                c0467r0N.d();
            }
            c0467r0N.d();
        }
        int length = spannableStringBuilder.length();
        if (length >= i3) {
            if (cVar.f8047B) {
                list.add(new Y1.n(i3, length, new Y1.g(cVar.f8048C)));
            }
            if (cVar.f8049D) {
                list.add(new Y1.n(i3, length, new Y1.e(cVar.f8050E)));
            }
            C0448h0.e eVar = cVar.f8052G;
            if (eVar == null ? cVar.f8051F == C0448h0.d.LINK : eVar == C0448h0.e.LINK) {
                list.add(new Y1.n(i3, length, new Y1.f(cVar.H())));
            }
            float fD = rVarA.d();
            if (!Float.isNaN(fD) && (rVar == null || rVar.d() != fD)) {
                list.add(new Y1.n(i3, length, new Y1.a(fD)));
            }
            int iC2 = rVarA.c();
            if (rVar == null || rVar.c() != iC2) {
                list.add(new Y1.n(i3, length, new Y1.d(iC2)));
            }
            if (cVar.f8067V != -1 || cVar.f8068W != -1 || cVar.f8069X != null) {
                list.add(new Y1.n(i3, length, new Y1.c(cVar.f8067V, cVar.f8068W, cVar.f8070Y, cVar.f8069X, cVar.l().getAssets())));
            }
            if (cVar.f8062Q) {
                list.add(new Y1.n(i3, length, new Y1.m()));
            }
            if (cVar.f8063R) {
                list.add(new Y1.n(i3, length, new Y1.j()));
            }
            if ((cVar.f8058M != 0.0f || cVar.f8059N != 0.0f || cVar.f8060O != 0.0f) && Color.alpha(cVar.f8061P) != 0) {
                list.add(new Y1.n(i3, length, new Y1.o(cVar.f8058M, cVar.f8059N, cVar.f8060O, cVar.f8061P)));
            }
            float fE = rVarA.e();
            if (!Float.isNaN(fE) && (rVar == null || rVar.e() != fE)) {
                list.add(new Y1.n(i3, length, new Y1.b(fE)));
            }
            list.add(new Y1.n(i3, length, new Y1.k(cVar.H())));
        }
    }

    @K1.a(name = "accessibilityRole")
    public void setAccessibilityRole(String str) {
        if (R()) {
            this.f8051F = C0448h0.d.c(str);
            y0();
        }
    }

    @K1.a(name = "adjustsFontSizeToFit")
    public void setAdjustFontSizeToFit(boolean z3) {
        if (z3 != this.f8065T) {
            this.f8065T = z3;
            y0();
        }
    }

    @K1.a(defaultBoolean = true, name = "allowFontScaling")
    public void setAllowFontScaling(boolean z3) {
        if (z3 != this.f8046A.b()) {
            this.f8046A.m(z3);
            y0();
        }
    }

    @K1.a(customType = "Color", name = "backgroundColor")
    public void setBackgroundColor(Integer num) {
        if (R()) {
            boolean z3 = num != null;
            this.f8049D = z3;
            if (z3) {
                this.f8050E = num.intValue();
            }
            y0();
        }
    }

    @K1.a(customType = "Color", name = "color")
    public void setColor(Integer num) {
        boolean z3 = num != null;
        this.f8047B = z3;
        if (z3) {
            this.f8048C = num.intValue();
        }
        y0();
    }

    @K1.a(name = "fontFamily")
    public void setFontFamily(String str) {
        this.f8069X = str;
        y0();
    }

    @K1.a(defaultFloat = Float.NaN, name = "fontSize")
    public void setFontSize(float f3) {
        this.f8046A.n(f3);
        y0();
    }

    @K1.a(name = "fontStyle")
    public void setFontStyle(String str) {
        int iB = o.b(str);
        if (iB != this.f8067V) {
            this.f8067V = iB;
            y0();
        }
    }

    @K1.a(name = "fontVariant")
    public void setFontVariant(ReadableArray readableArray) {
        String strC = o.c(readableArray);
        if (TextUtils.equals(strC, this.f8070Y)) {
            return;
        }
        this.f8070Y = strC;
        y0();
    }

    @K1.a(name = "fontWeight")
    public void setFontWeight(String str) {
        int iD = o.d(str);
        if (iD != this.f8068W) {
            this.f8068W = iD;
            y0();
        }
    }

    @K1.a(defaultBoolean = true, name = "includeFontPadding")
    public void setIncludeFontPadding(boolean z3) {
        this.f8064S = z3;
    }

    @K1.a(defaultFloat = 0.0f, name = "letterSpacing")
    public void setLetterSpacing(float f3) {
        this.f8046A.p(f3);
        y0();
    }

    @K1.a(defaultFloat = Float.NaN, name = "lineHeight")
    public void setLineHeight(float f3) {
        this.f8046A.q(f3);
        y0();
    }

    @K1.a(defaultFloat = Float.NaN, name = "maxFontSizeMultiplier")
    public void setMaxFontSizeMultiplier(float f3) {
        if (f3 != this.f8046A.k()) {
            this.f8046A.r(f3);
            y0();
        }
    }

    @K1.a(name = "minimumFontScale")
    public void setMinimumFontScale(float f3) {
        if (f3 != this.f8066U) {
            this.f8066U = f3;
            y0();
        }
    }

    @K1.a(defaultInt = -1, name = "numberOfLines")
    public void setNumberOfLines(int i3) {
        if (i3 == 0) {
            i3 = -1;
        }
        this.f8053H = i3;
        y0();
    }

    @K1.a(name = "role")
    public void setRole(String str) {
        if (R()) {
            this.f8052G = C0448h0.e.b(str);
            y0();
        }
    }

    @K1.a(name = "textAlign")
    public void setTextAlign(String str) {
        if ("justify".equals(str)) {
            if (Build.VERSION.SDK_INT >= 26) {
                this.f8057L = 1;
            }
            this.f8054I = 3;
        } else {
            if (Build.VERSION.SDK_INT >= 26) {
                this.f8057L = 0;
            }
            if (str == null || "auto".equals(str)) {
                this.f8054I = 0;
            } else if ("left".equals(str)) {
                this.f8054I = 3;
            } else if ("right".equals(str)) {
                this.f8054I = 5;
            } else if ("center".equals(str)) {
                this.f8054I = 1;
            } else {
                Y.a.I("ReactNative", "Invalid textAlign: " + str);
                this.f8054I = 0;
            }
        }
        y0();
    }

    @K1.a(name = "textBreakStrategy")
    public void setTextBreakStrategy(String str) {
        if (str == null || "highQuality".equals(str)) {
            this.f8055J = 1;
        } else if ("simple".equals(str)) {
            this.f8055J = 0;
        } else if ("balanced".equals(str)) {
            this.f8055J = 2;
        } else {
            Y.a.I("ReactNative", "Invalid textBreakStrategy: " + str);
            this.f8055J = 1;
        }
        y0();
    }

    @K1.a(name = "textDecorationLine")
    public void setTextDecorationLine(String str) {
        this.f8062Q = false;
        this.f8063R = false;
        if (str != null) {
            for (String str2 : str.split(" ")) {
                if ("underline".equals(str2)) {
                    this.f8062Q = true;
                } else if ("line-through".equals(str2)) {
                    this.f8063R = true;
                }
            }
        }
        y0();
    }

    @K1.a(customType = "Color", defaultInt = 1426063360, name = "textShadowColor")
    public void setTextShadowColor(int i3) {
        if (i3 != this.f8061P) {
            this.f8061P = i3;
            y0();
        }
    }

    @K1.a(name = "textShadowOffset")
    public void setTextShadowOffset(ReadableMap readableMap) {
        this.f8058M = 0.0f;
        this.f8059N = 0.0f;
        if (readableMap != null) {
            if (readableMap.hasKey("width") && !readableMap.isNull("width")) {
                this.f8058M = C0444f0.g(readableMap.getDouble("width"));
            }
            if (readableMap.hasKey("height") && !readableMap.isNull("height")) {
                this.f8059N = C0444f0.g(readableMap.getDouble("height"));
            }
        }
        y0();
    }

    @K1.a(defaultInt = 1, name = "textShadowRadius")
    public void setTextShadowRadius(float f3) {
        if (f3 != this.f8060O) {
            this.f8060O = f3;
            y0();
        }
    }

    @K1.a(name = "textTransform")
    public void setTextTransform(String str) {
        if (str == null) {
            this.f8046A.s(t.f8182g);
        } else if ("none".equals(str)) {
            this.f8046A.s(t.f8178c);
        } else if ("uppercase".equals(str)) {
            this.f8046A.s(t.f8179d);
        } else if ("lowercase".equals(str)) {
            this.f8046A.s(t.f8180e);
        } else if ("capitalize".equals(str)) {
            this.f8046A.s(t.f8181f);
        } else {
            Y.a.I("ReactNative", "Invalid textTransform: " + str);
            this.f8046A.s(t.f8182g);
        }
        y0();
    }

    protected Spannable x1(c cVar, String str, boolean z3, C0438c0 c0438c0) {
        int iB;
        Z0.a.b((z3 && c0438c0 == null) ? false : true, "nativeViewHierarchyOptimizer is required when inline views are supported");
        SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder();
        ArrayList arrayList = new ArrayList();
        HashMap map = z3 ? new HashMap() : null;
        if (str != null) {
            spannableStringBuilder.append((CharSequence) t.b(str, cVar.f8046A.l()));
        }
        w1(cVar, spannableStringBuilder, arrayList, null, z3, map, 0);
        cVar.f8071Z = false;
        cVar.f8072a0 = map;
        float f3 = Float.NaN;
        for (int i3 = 0; i3 < arrayList.size(); i3++) {
            Y1.n nVar = (Y1.n) arrayList.get((arrayList.size() - i3) - 1);
            Y1.i iVar = nVar.f2896c;
            boolean z4 = iVar instanceof Y1.p;
            if (z4 || (iVar instanceof Y1.q)) {
                if (z4) {
                    iB = ((Y1.p) iVar).b();
                    cVar.f8071Z = true;
                } else {
                    Y1.q qVar = (Y1.q) iVar;
                    int iA = qVar.a();
                    InterfaceC0466q0 interfaceC0466q0 = (InterfaceC0466q0) map.get(Integer.valueOf(qVar.b()));
                    c0438c0.h(interfaceC0466q0);
                    interfaceC0466q0.w(cVar);
                    iB = iA;
                }
                if (Float.isNaN(f3) || iB > f3) {
                    f3 = iB;
                }
            }
            nVar.a(spannableStringBuilder, i3);
        }
        cVar.f8046A.o(f3);
        return spannableStringBuilder;
    }

    public c(n nVar) {
        this.f8047B = false;
        this.f8049D = false;
        this.f8051F = null;
        this.f8052G = null;
        this.f8053H = -1;
        this.f8054I = 0;
        this.f8055J = 1;
        this.f8056K = 0;
        this.f8057L = 0;
        this.f8058M = 0.0f;
        this.f8059N = 0.0f;
        this.f8060O = 0.0f;
        this.f8061P = 1426063360;
        this.f8062Q = false;
        this.f8063R = false;
        this.f8064S = true;
        this.f8065T = false;
        this.f8066U = 0.0f;
        this.f8067V = -1;
        this.f8068W = -1;
        this.f8069X = null;
        this.f8070Y = null;
        this.f8071Z = false;
        this.f8046A = new r();
    }
}
