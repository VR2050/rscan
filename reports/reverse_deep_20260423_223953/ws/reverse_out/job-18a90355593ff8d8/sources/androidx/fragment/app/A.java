package androidx.fragment.app;

import android.util.Log;
import androidx.lifecycle.z;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;

/* JADX INFO: loaded from: classes.dex */
final class A extends androidx.lifecycle.y {

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private static final z.b f4693k = new a();

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final boolean f4697g;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final HashMap f4694d = new HashMap();

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final HashMap f4695e = new HashMap();

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final HashMap f4696f = new HashMap();

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private boolean f4698h = false;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private boolean f4699i = false;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private boolean f4700j = false;

    class a implements z.b {
        a() {
        }

        @Override // androidx.lifecycle.z.b
        public androidx.lifecycle.y a(Class cls) {
            return new A(true);
        }
    }

    A(boolean z3) {
        this.f4697g = z3;
    }

    private void h(String str) {
        A a3 = (A) this.f4695e.get(str);
        if (a3 != null) {
            a3.d();
            this.f4695e.remove(str);
        }
        androidx.lifecycle.B b3 = (androidx.lifecycle.B) this.f4696f.get(str);
        if (b3 != null) {
            b3.a();
            this.f4696f.remove(str);
        }
    }

    static A k(androidx.lifecycle.B b3) {
        return (A) new androidx.lifecycle.z(b3, f4693k).a(A.class);
    }

    @Override // androidx.lifecycle.y
    protected void d() {
        if (x.G0(3)) {
            Log.d("FragmentManager", "onCleared called for " + this);
        }
        this.f4698h = true;
    }

    void e(Fragment fragment) {
        if (this.f4700j) {
            if (x.G0(2)) {
                Log.v("FragmentManager", "Ignoring addRetainedFragment as the state is already saved");
            }
        } else {
            if (this.f4694d.containsKey(fragment.f4788g)) {
                return;
            }
            this.f4694d.put(fragment.f4788g, fragment);
            if (x.G0(2)) {
                Log.v("FragmentManager", "Updating retained Fragments: Added " + fragment);
            }
        }
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || A.class != obj.getClass()) {
            return false;
        }
        A a3 = (A) obj;
        return this.f4694d.equals(a3.f4694d) && this.f4695e.equals(a3.f4695e) && this.f4696f.equals(a3.f4696f);
    }

    void f(Fragment fragment) {
        if (x.G0(3)) {
            Log.d("FragmentManager", "Clearing non-config state for " + fragment);
        }
        h(fragment.f4788g);
    }

    void g(String str) {
        if (x.G0(3)) {
            Log.d("FragmentManager", "Clearing non-config state for saved state of Fragment " + str);
        }
        h(str);
    }

    public int hashCode() {
        return (((this.f4694d.hashCode() * 31) + this.f4695e.hashCode()) * 31) + this.f4696f.hashCode();
    }

    Fragment i(String str) {
        return (Fragment) this.f4694d.get(str);
    }

    A j(Fragment fragment) {
        A a3 = (A) this.f4695e.get(fragment.f4788g);
        if (a3 != null) {
            return a3;
        }
        A a4 = new A(this.f4697g);
        this.f4695e.put(fragment.f4788g, a4);
        return a4;
    }

    Collection l() {
        return new ArrayList(this.f4694d.values());
    }

    androidx.lifecycle.B m(Fragment fragment) {
        androidx.lifecycle.B b3 = (androidx.lifecycle.B) this.f4696f.get(fragment.f4788g);
        if (b3 != null) {
            return b3;
        }
        androidx.lifecycle.B b4 = new androidx.lifecycle.B();
        this.f4696f.put(fragment.f4788g, b4);
        return b4;
    }

    boolean n() {
        return this.f4698h;
    }

    void o(Fragment fragment) {
        if (this.f4700j) {
            if (x.G0(2)) {
                Log.v("FragmentManager", "Ignoring removeRetainedFragment as the state is already saved");
            }
        } else {
            if (this.f4694d.remove(fragment.f4788g) == null || !x.G0(2)) {
                return;
            }
            Log.v("FragmentManager", "Updating retained Fragments: Removed " + fragment);
        }
    }

    void p(boolean z3) {
        this.f4700j = z3;
    }

    boolean q(Fragment fragment) {
        if (this.f4694d.containsKey(fragment.f4788g)) {
            return this.f4697g ? this.f4698h : !this.f4699i;
        }
        return true;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder("FragmentManagerViewModel{");
        sb.append(Integer.toHexString(System.identityHashCode(this)));
        sb.append("} Fragments (");
        Iterator it = this.f4694d.values().iterator();
        while (it.hasNext()) {
            sb.append(it.next());
            if (it.hasNext()) {
                sb.append(", ");
            }
        }
        sb.append(") Child Non Config (");
        Iterator it2 = this.f4695e.keySet().iterator();
        while (it2.hasNext()) {
            sb.append((String) it2.next());
            if (it2.hasNext()) {
                sb.append(", ");
            }
        }
        sb.append(") ViewModelStores (");
        Iterator it3 = this.f4696f.keySet().iterator();
        while (it3.hasNext()) {
            sb.append((String) it3.next());
            if (it3.hasNext()) {
                sb.append(", ");
            }
        }
        sb.append(')');
        return sb.toString();
    }
}
