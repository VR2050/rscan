package androidx.appcompat.view;

import android.app.Activity;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.content.res.XmlResourceParser;
import android.graphics.PorterDuff;
import android.util.AttributeSet;
import android.util.Log;
import android.util.Xml;
import android.view.InflateException;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.SubMenu;
import android.view.View;
import androidx.appcompat.widget.O;
import androidx.appcompat.widget.g0;
import androidx.core.view.AbstractC0254b;
import androidx.core.view.AbstractC0286x;
import d.j;
import i.MenuItemC0568c;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import n.InterfaceMenuC0630a;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

/* JADX INFO: loaded from: classes.dex */
public class g extends MenuInflater {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    static final Class[] f3342e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    static final Class[] f3343f;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    final Object[] f3344a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    final Object[] f3345b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    Context f3346c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private Object f3347d;

    private static class a implements MenuItem.OnMenuItemClickListener {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private static final Class[] f3348c = {MenuItem.class};

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private Object f3349a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private Method f3350b;

        public a(Object obj, String str) {
            this.f3349a = obj;
            Class<?> cls = obj.getClass();
            try {
                this.f3350b = cls.getMethod(str, f3348c);
            } catch (Exception e3) {
                InflateException inflateException = new InflateException("Couldn't resolve menu item onClick handler " + str + " in class " + cls.getName());
                inflateException.initCause(e3);
                throw inflateException;
            }
        }

        @Override // android.view.MenuItem.OnMenuItemClickListener
        public boolean onMenuItemClick(MenuItem menuItem) {
            try {
                if (this.f3350b.getReturnType() == Boolean.TYPE) {
                    return ((Boolean) this.f3350b.invoke(this.f3349a, menuItem)).booleanValue();
                }
                this.f3350b.invoke(this.f3349a, menuItem);
                return true;
            } catch (Exception e3) {
                throw new RuntimeException(e3);
            }
        }
    }

    private class b {

        /* JADX INFO: renamed from: A, reason: collision with root package name */
        AbstractC0254b f3351A;

        /* JADX INFO: renamed from: B, reason: collision with root package name */
        private CharSequence f3352B;

        /* JADX INFO: renamed from: C, reason: collision with root package name */
        private CharSequence f3353C;

        /* JADX INFO: renamed from: D, reason: collision with root package name */
        private ColorStateList f3354D = null;

        /* JADX INFO: renamed from: E, reason: collision with root package name */
        private PorterDuff.Mode f3355E = null;

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private Menu f3357a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private int f3358b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private int f3359c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private int f3360d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private int f3361e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private boolean f3362f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private boolean f3363g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private boolean f3364h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private int f3365i;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        private int f3366j;

        /* JADX INFO: renamed from: k, reason: collision with root package name */
        private CharSequence f3367k;

        /* JADX INFO: renamed from: l, reason: collision with root package name */
        private CharSequence f3368l;

        /* JADX INFO: renamed from: m, reason: collision with root package name */
        private int f3369m;

        /* JADX INFO: renamed from: n, reason: collision with root package name */
        private char f3370n;

        /* JADX INFO: renamed from: o, reason: collision with root package name */
        private int f3371o;

        /* JADX INFO: renamed from: p, reason: collision with root package name */
        private char f3372p;

        /* JADX INFO: renamed from: q, reason: collision with root package name */
        private int f3373q;

        /* JADX INFO: renamed from: r, reason: collision with root package name */
        private int f3374r;

        /* JADX INFO: renamed from: s, reason: collision with root package name */
        private boolean f3375s;

        /* JADX INFO: renamed from: t, reason: collision with root package name */
        private boolean f3376t;

        /* JADX INFO: renamed from: u, reason: collision with root package name */
        private boolean f3377u;

        /* JADX INFO: renamed from: v, reason: collision with root package name */
        private int f3378v;

        /* JADX INFO: renamed from: w, reason: collision with root package name */
        private int f3379w;

        /* JADX INFO: renamed from: x, reason: collision with root package name */
        private String f3380x;

        /* JADX INFO: renamed from: y, reason: collision with root package name */
        private String f3381y;

        /* JADX INFO: renamed from: z, reason: collision with root package name */
        private String f3382z;

        public b(Menu menu) {
            this.f3357a = menu;
            h();
        }

        private char c(String str) {
            if (str == null) {
                return (char) 0;
            }
            return str.charAt(0);
        }

        private Object e(String str, Class[] clsArr, Object[] objArr) {
            try {
                Constructor<?> constructor = Class.forName(str, false, g.this.f3346c.getClassLoader()).getConstructor(clsArr);
                constructor.setAccessible(true);
                return constructor.newInstance(objArr);
            } catch (Exception e3) {
                Log.w("SupportMenuInflater", "Cannot instantiate class: " + str, e3);
                return null;
            }
        }

        private void i(MenuItem menuItem) {
            boolean z3 = false;
            menuItem.setChecked(this.f3375s).setVisible(this.f3376t).setEnabled(this.f3377u).setCheckable(this.f3374r >= 1).setTitleCondensed(this.f3368l).setIcon(this.f3369m);
            int i3 = this.f3378v;
            if (i3 >= 0) {
                menuItem.setShowAsAction(i3);
            }
            if (this.f3382z != null) {
                if (g.this.f3346c.isRestricted()) {
                    throw new IllegalStateException("The android:onClick attribute cannot be used within a restricted context");
                }
                menuItem.setOnMenuItemClickListener(new a(g.this.b(), this.f3382z));
            }
            if (this.f3374r >= 2) {
                if (menuItem instanceof androidx.appcompat.view.menu.g) {
                    ((androidx.appcompat.view.menu.g) menuItem).t(true);
                } else if (menuItem instanceof MenuItemC0568c) {
                    ((MenuItemC0568c) menuItem).h(true);
                }
            }
            String str = this.f3380x;
            if (str != null) {
                menuItem.setActionView((View) e(str, g.f3342e, g.this.f3344a));
                z3 = true;
            }
            int i4 = this.f3379w;
            if (i4 > 0) {
                if (z3) {
                    Log.w("SupportMenuInflater", "Ignoring attribute 'itemActionViewLayout'. Action view already specified.");
                } else {
                    menuItem.setActionView(i4);
                }
            }
            AbstractC0254b abstractC0254b = this.f3351A;
            if (abstractC0254b != null) {
                AbstractC0286x.a(menuItem, abstractC0254b);
            }
            AbstractC0286x.c(menuItem, this.f3352B);
            AbstractC0286x.g(menuItem, this.f3353C);
            AbstractC0286x.b(menuItem, this.f3370n, this.f3371o);
            AbstractC0286x.f(menuItem, this.f3372p, this.f3373q);
            PorterDuff.Mode mode = this.f3355E;
            if (mode != null) {
                AbstractC0286x.e(menuItem, mode);
            }
            ColorStateList colorStateList = this.f3354D;
            if (colorStateList != null) {
                AbstractC0286x.d(menuItem, colorStateList);
            }
        }

        public void a() {
            this.f3364h = true;
            i(this.f3357a.add(this.f3358b, this.f3365i, this.f3366j, this.f3367k));
        }

        public SubMenu b() {
            this.f3364h = true;
            SubMenu subMenuAddSubMenu = this.f3357a.addSubMenu(this.f3358b, this.f3365i, this.f3366j, this.f3367k);
            i(subMenuAddSubMenu.getItem());
            return subMenuAddSubMenu;
        }

        public boolean d() {
            return this.f3364h;
        }

        public void f(AttributeSet attributeSet) {
            TypedArray typedArrayObtainStyledAttributes = g.this.f3346c.obtainStyledAttributes(attributeSet, j.f9100o1);
            this.f3358b = typedArrayObtainStyledAttributes.getResourceId(j.f9108q1, 0);
            this.f3359c = typedArrayObtainStyledAttributes.getInt(j.f9116s1, 0);
            this.f3360d = typedArrayObtainStyledAttributes.getInt(j.f9120t1, 0);
            this.f3361e = typedArrayObtainStyledAttributes.getInt(j.f9124u1, 0);
            this.f3362f = typedArrayObtainStyledAttributes.getBoolean(j.f9112r1, true);
            this.f3363g = typedArrayObtainStyledAttributes.getBoolean(j.f9104p1, true);
            typedArrayObtainStyledAttributes.recycle();
        }

        public void g(AttributeSet attributeSet) {
            g0 g0VarT = g0.t(g.this.f3346c, attributeSet, j.f9128v1);
            this.f3365i = g0VarT.m(j.f9140y1, 0);
            this.f3366j = (g0VarT.j(j.f8951B1, this.f3359c) & (-65536)) | (g0VarT.j(j.f8955C1, this.f3360d) & 65535);
            this.f3367k = g0VarT.o(j.f8959D1);
            this.f3368l = g0VarT.o(j.f8963E1);
            this.f3369m = g0VarT.m(j.f9132w1, 0);
            this.f3370n = c(g0VarT.n(j.f8967F1));
            this.f3371o = g0VarT.j(j.f8995M1, 4096);
            this.f3372p = c(g0VarT.n(j.f8971G1));
            this.f3373q = g0VarT.j(j.f9011Q1, 4096);
            if (g0VarT.r(j.f8975H1)) {
                this.f3374r = g0VarT.a(j.f8975H1, false) ? 1 : 0;
            } else {
                this.f3374r = this.f3361e;
            }
            this.f3375s = g0VarT.a(j.f9144z1, false);
            this.f3376t = g0VarT.a(j.f8947A1, this.f3362f);
            this.f3377u = g0VarT.a(j.f9136x1, this.f3363g);
            this.f3378v = g0VarT.j(j.f9015R1, -1);
            this.f3382z = g0VarT.n(j.f8979I1);
            this.f3379w = g0VarT.m(j.f8983J1, 0);
            this.f3380x = g0VarT.n(j.f8991L1);
            String strN = g0VarT.n(j.f8987K1);
            this.f3381y = strN;
            boolean z3 = strN != null;
            if (z3 && this.f3379w == 0 && this.f3380x == null) {
                this.f3351A = (AbstractC0254b) e(strN, g.f3343f, g.this.f3345b);
            } else {
                if (z3) {
                    Log.w("SupportMenuInflater", "Ignoring attribute 'actionProviderClass'. Action view already specified.");
                }
                this.f3351A = null;
            }
            this.f3352B = g0VarT.o(j.f8999N1);
            this.f3353C = g0VarT.o(j.f9019S1);
            if (g0VarT.r(j.f9007P1)) {
                this.f3355E = O.d(g0VarT.j(j.f9007P1, -1), this.f3355E);
            } else {
                this.f3355E = null;
            }
            if (g0VarT.r(j.f9003O1)) {
                this.f3354D = g0VarT.c(j.f9003O1);
            } else {
                this.f3354D = null;
            }
            g0VarT.w();
            this.f3364h = false;
        }

        public void h() {
            this.f3358b = 0;
            this.f3359c = 0;
            this.f3360d = 0;
            this.f3361e = 0;
            this.f3362f = true;
            this.f3363g = true;
        }
    }

    static {
        Class[] clsArr = {Context.class};
        f3342e = clsArr;
        f3343f = clsArr;
    }

    public g(Context context) {
        super(context);
        this.f3346c = context;
        Object[] objArr = {context};
        this.f3344a = objArr;
        this.f3345b = objArr;
    }

    private Object a(Object obj) {
        return (!(obj instanceof Activity) && (obj instanceof ContextWrapper)) ? a(((ContextWrapper) obj).getBaseContext()) : obj;
    }

    private void c(XmlPullParser xmlPullParser, AttributeSet attributeSet, Menu menu) throws XmlPullParserException, IOException {
        b bVar = new b(menu);
        int eventType = xmlPullParser.getEventType();
        while (true) {
            if (eventType == 2) {
                String name = xmlPullParser.getName();
                if (!name.equals("menu")) {
                    throw new RuntimeException("Expecting menu, got " + name);
                }
                eventType = xmlPullParser.next();
            } else {
                eventType = xmlPullParser.next();
                if (eventType == 1) {
                    break;
                }
            }
        }
        boolean z3 = false;
        boolean z4 = false;
        String str = null;
        while (!z3) {
            if (eventType == 1) {
                throw new RuntimeException("Unexpected end of document");
            }
            if (eventType != 2) {
                if (eventType == 3) {
                    String name2 = xmlPullParser.getName();
                    if (z4 && name2.equals(str)) {
                        z4 = false;
                        str = null;
                    } else if (name2.equals("group")) {
                        bVar.h();
                    } else if (name2.equals("item")) {
                        if (!bVar.d()) {
                            AbstractC0254b abstractC0254b = bVar.f3351A;
                            if (abstractC0254b == null || !abstractC0254b.a()) {
                                bVar.a();
                            } else {
                                bVar.b();
                            }
                        }
                    } else if (name2.equals("menu")) {
                        z3 = true;
                    }
                }
            } else if (!z4) {
                String name3 = xmlPullParser.getName();
                if (name3.equals("group")) {
                    bVar.f(attributeSet);
                } else if (name3.equals("item")) {
                    bVar.g(attributeSet);
                } else if (name3.equals("menu")) {
                    c(xmlPullParser, attributeSet, bVar.b());
                } else {
                    str = name3;
                    z4 = true;
                }
            }
            eventType = xmlPullParser.next();
        }
    }

    Object b() {
        if (this.f3347d == null) {
            this.f3347d = a(this.f3346c);
        }
        return this.f3347d;
    }

    @Override // android.view.MenuInflater
    public void inflate(int i3, Menu menu) {
        if (!(menu instanceof InterfaceMenuC0630a)) {
            super.inflate(i3, menu);
            return;
        }
        XmlResourceParser layout = null;
        boolean z3 = false;
        try {
            try {
                layout = this.f3346c.getResources().getLayout(i3);
                AttributeSet attributeSetAsAttributeSet = Xml.asAttributeSet(layout);
                if (menu instanceof androidx.appcompat.view.menu.e) {
                    androidx.appcompat.view.menu.e eVar = (androidx.appcompat.view.menu.e) menu;
                    if (eVar.F()) {
                        eVar.e0();
                        z3 = true;
                    }
                }
                c(layout, attributeSetAsAttributeSet, menu);
                if (z3) {
                    ((androidx.appcompat.view.menu.e) menu).d0();
                }
                if (layout != null) {
                    layout.close();
                }
            } catch (IOException e3) {
                throw new InflateException("Error inflating menu XML", e3);
            } catch (XmlPullParserException e4) {
                throw new InflateException("Error inflating menu XML", e4);
            }
        } catch (Throwable th) {
            if (z3) {
                ((androidx.appcompat.view.menu.e) menu).d0();
            }
            if (layout != null) {
                layout.close();
            }
            throw th;
        }
    }
}
