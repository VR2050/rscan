package com.facebook.react.animated;

import i2.AbstractC0586n;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public abstract class b {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final a f6503e = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public List f6504a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public int f6505b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public int f6506c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public int f6507d = -1;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public final void b(b bVar) {
        t2.j.f(bVar, "child");
        List arrayList = this.f6504a;
        if (arrayList == null) {
            arrayList = new ArrayList(1);
            this.f6504a = arrayList;
        }
        arrayList.add(bVar);
        bVar.c(this);
    }

    public void c(b bVar) {
        t2.j.f(bVar, "parent");
    }

    public void d(b bVar) {
        t2.j.f(bVar, "parent");
    }

    public abstract String e();

    public final String f() {
        String str;
        List list = this.f6504a;
        String strJ = list != null ? AbstractC0586n.J(list, " ", null, null, 0, null, null, 62, null) : null;
        String strE = e();
        if (strJ == null || z2.g.L(strJ)) {
            str = "";
        } else {
            str = " children: " + strJ;
        }
        return strE + str;
    }

    public final void g(b bVar) {
        t2.j.f(bVar, "child");
        List list = this.f6504a;
        if (list == null) {
            return;
        }
        bVar.d(this);
        list.remove(bVar);
    }

    public void h() {
    }
}
