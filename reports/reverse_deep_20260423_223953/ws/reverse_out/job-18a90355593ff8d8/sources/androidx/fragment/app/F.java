package androidx.fragment.app;

import android.view.ViewGroup;
import androidx.lifecycle.f;
import java.lang.reflect.Modifier;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes.dex */
public abstract class F {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final o f4726a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final ClassLoader f4727b;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    int f4729d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    int f4730e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    int f4731f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    int f4732g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    int f4733h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    boolean f4734i;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    String f4736k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    int f4737l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    CharSequence f4738m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    int f4739n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    CharSequence f4740o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    ArrayList f4741p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    ArrayList f4742q;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    ArrayList f4744s;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    ArrayList f4728c = new ArrayList();

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    boolean f4735j = true;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    boolean f4743r = false;

    static final class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        int f4745a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        Fragment f4746b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        boolean f4747c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        int f4748d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        int f4749e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        int f4750f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        int f4751g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        f.b f4752h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        f.b f4753i;

        a() {
        }

        a(int i3, Fragment fragment) {
            this.f4745a = i3;
            this.f4746b = fragment;
            this.f4747c = false;
            f.b bVar = f.b.RESUMED;
            this.f4752h = bVar;
            this.f4753i = bVar;
        }

        a(int i3, Fragment fragment, boolean z3) {
            this.f4745a = i3;
            this.f4746b = fragment;
            this.f4747c = z3;
            f.b bVar = f.b.RESUMED;
            this.f4752h = bVar;
            this.f4753i = bVar;
        }
    }

    F(o oVar, ClassLoader classLoader) {
        this.f4726a = oVar;
        this.f4727b = classLoader;
    }

    public F b(int i3, Fragment fragment, String str) {
        k(i3, fragment, str, 1);
        return this;
    }

    F c(ViewGroup viewGroup, Fragment fragment, String str) {
        fragment.f4763I = viewGroup;
        return b(viewGroup.getId(), fragment, str);
    }

    public F d(Fragment fragment, String str) {
        k(0, fragment, str, 1);
        return this;
    }

    void e(a aVar) {
        this.f4728c.add(aVar);
        aVar.f4748d = this.f4729d;
        aVar.f4749e = this.f4730e;
        aVar.f4750f = this.f4731f;
        aVar.f4751g = this.f4732g;
    }

    public abstract int f();

    public abstract int g();

    public abstract void h();

    public abstract void i();

    public F j() {
        if (this.f4734i) {
            throw new IllegalStateException("This transaction is already being added to the back stack");
        }
        this.f4735j = false;
        return this;
    }

    void k(int i3, Fragment fragment, String str, int i4) {
        String str2 = fragment.f4772R;
        if (str2 != null) {
            B.c.f(fragment, str2);
        }
        Class<?> cls = fragment.getClass();
        int modifiers = cls.getModifiers();
        if (cls.isAnonymousClass() || !Modifier.isPublic(modifiers) || (cls.isMemberClass() && !Modifier.isStatic(modifiers))) {
            throw new IllegalStateException("Fragment " + cls.getCanonicalName() + " must be a public static class to be  properly recreated from instance state.");
        }
        if (str != null) {
            String str3 = fragment.f4755A;
            if (str3 != null && !str.equals(str3)) {
                throw new IllegalStateException("Can't change tag of fragment " + fragment + ": was " + fragment.f4755A + " now " + str);
            }
            fragment.f4755A = str;
        }
        if (i3 != 0) {
            if (i3 == -1) {
                throw new IllegalArgumentException("Can't add fragment " + fragment + " with tag " + str + " to container view with no id");
            }
            int i5 = fragment.f4806y;
            if (i5 != 0 && i5 != i3) {
                throw new IllegalStateException("Can't change container ID of fragment " + fragment + ": was " + fragment.f4806y + " now " + i3);
            }
            fragment.f4806y = i3;
            fragment.f4807z = i3;
        }
        e(new a(i4, fragment));
    }

    public F l(Fragment fragment) {
        e(new a(3, fragment));
        return this;
    }

    public F m(boolean z3) {
        this.f4743r = z3;
        return this;
    }
}
