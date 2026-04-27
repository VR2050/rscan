package androidx.fragment.app;

import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
class E {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final ArrayList f4722a = new ArrayList();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final HashMap f4723b = new HashMap();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final HashMap f4724c = new HashMap();

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private A f4725d;

    E() {
    }

    void A(A a3) {
        this.f4725d = a3;
    }

    C B(String str, C c3) {
        return c3 != null ? (C) this.f4724c.put(str, c3) : (C) this.f4724c.remove(str);
    }

    void a(Fragment fragment) {
        if (this.f4722a.contains(fragment)) {
            throw new IllegalStateException("Fragment already added: " + fragment);
        }
        synchronized (this.f4722a) {
            this.f4722a.add(fragment);
        }
        fragment.f4794m = true;
    }

    void b() {
        this.f4723b.values().removeAll(Collections.singleton(null));
    }

    boolean c(String str) {
        return this.f4723b.get(str) != null;
    }

    void d(int i3) {
        for (D d3 : this.f4723b.values()) {
            if (d3 != null) {
                d3.t(i3);
            }
        }
    }

    void e(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        String str2 = str + "    ";
        if (!this.f4723b.isEmpty()) {
            printWriter.print(str);
            printWriter.println("Active Fragments:");
            for (D d3 : this.f4723b.values()) {
                printWriter.print(str);
                if (d3 != null) {
                    Fragment fragmentK = d3.k();
                    printWriter.println(fragmentK);
                    fragmentK.e(str2, fileDescriptor, printWriter, strArr);
                } else {
                    printWriter.println("null");
                }
            }
        }
        int size = this.f4722a.size();
        if (size > 0) {
            printWriter.print(str);
            printWriter.println("Added Fragments:");
            for (int i3 = 0; i3 < size; i3++) {
                Fragment fragment = (Fragment) this.f4722a.get(i3);
                printWriter.print(str);
                printWriter.print("  #");
                printWriter.print(i3);
                printWriter.print(": ");
                printWriter.println(fragment.toString());
            }
        }
    }

    Fragment f(String str) {
        D d3 = (D) this.f4723b.get(str);
        if (d3 != null) {
            return d3.k();
        }
        return null;
    }

    Fragment g(int i3) {
        for (int size = this.f4722a.size() - 1; size >= 0; size--) {
            Fragment fragment = (Fragment) this.f4722a.get(size);
            if (fragment != null && fragment.f4806y == i3) {
                return fragment;
            }
        }
        for (D d3 : this.f4723b.values()) {
            if (d3 != null) {
                Fragment fragmentK = d3.k();
                if (fragmentK.f4806y == i3) {
                    return fragmentK;
                }
            }
        }
        return null;
    }

    Fragment h(String str) {
        if (str != null) {
            for (int size = this.f4722a.size() - 1; size >= 0; size--) {
                Fragment fragment = (Fragment) this.f4722a.get(size);
                if (fragment != null && str.equals(fragment.f4755A)) {
                    return fragment;
                }
            }
        }
        if (str == null) {
            return null;
        }
        for (D d3 : this.f4723b.values()) {
            if (d3 != null) {
                Fragment fragmentK = d3.k();
                if (str.equals(fragmentK.f4755A)) {
                    return fragmentK;
                }
            }
        }
        return null;
    }

    Fragment i(String str) {
        Fragment fragmentG;
        for (D d3 : this.f4723b.values()) {
            if (d3 != null && (fragmentG = d3.k().g(str)) != null) {
                return fragmentG;
            }
        }
        return null;
    }

    int j(Fragment fragment) {
        View view;
        View view2;
        ViewGroup viewGroup = fragment.f4763I;
        if (viewGroup == null) {
            return -1;
        }
        int iIndexOf = this.f4722a.indexOf(fragment);
        for (int i3 = iIndexOf - 1; i3 >= 0; i3--) {
            Fragment fragment2 = (Fragment) this.f4722a.get(i3);
            if (fragment2.f4763I == viewGroup && (view2 = fragment2.f4764J) != null) {
                return viewGroup.indexOfChild(view2) + 1;
            }
        }
        while (true) {
            iIndexOf++;
            if (iIndexOf >= this.f4722a.size()) {
                return -1;
            }
            Fragment fragment3 = (Fragment) this.f4722a.get(iIndexOf);
            if (fragment3.f4763I == viewGroup && (view = fragment3.f4764J) != null) {
                return viewGroup.indexOfChild(view);
            }
        }
    }

    List k() {
        ArrayList arrayList = new ArrayList();
        for (D d3 : this.f4723b.values()) {
            if (d3 != null) {
                arrayList.add(d3);
            }
        }
        return arrayList;
    }

    List l() {
        ArrayList arrayList = new ArrayList();
        for (D d3 : this.f4723b.values()) {
            if (d3 != null) {
                arrayList.add(d3.k());
            } else {
                arrayList.add(null);
            }
        }
        return arrayList;
    }

    ArrayList m() {
        return new ArrayList(this.f4724c.values());
    }

    D n(String str) {
        return (D) this.f4723b.get(str);
    }

    List o() {
        ArrayList arrayList;
        if (this.f4722a.isEmpty()) {
            return Collections.emptyList();
        }
        synchronized (this.f4722a) {
            arrayList = new ArrayList(this.f4722a);
        }
        return arrayList;
    }

    A p() {
        return this.f4725d;
    }

    C q(String str) {
        return (C) this.f4724c.get(str);
    }

    void r(D d3) {
        Fragment fragmentK = d3.k();
        if (c(fragmentK.f4788g)) {
            return;
        }
        this.f4723b.put(fragmentK.f4788g, d3);
        if (fragmentK.f4759E) {
            if (fragmentK.f4758D) {
                this.f4725d.e(fragmentK);
            } else {
                this.f4725d.o(fragmentK);
            }
            fragmentK.f4759E = false;
        }
        if (x.G0(2)) {
            Log.v("FragmentManager", "Added fragment to active set " + fragmentK);
        }
    }

    void s(D d3) {
        Fragment fragmentK = d3.k();
        if (fragmentK.f4758D) {
            this.f4725d.o(fragmentK);
        }
        if (((D) this.f4723b.put(fragmentK.f4788g, null)) != null && x.G0(2)) {
            Log.v("FragmentManager", "Removed fragment from active set " + fragmentK);
        }
    }

    void t() {
        Iterator it = this.f4722a.iterator();
        while (it.hasNext()) {
            D d3 = (D) this.f4723b.get(((Fragment) it.next()).f4788g);
            if (d3 != null) {
                d3.m();
            }
        }
        for (D d4 : this.f4723b.values()) {
            if (d4 != null) {
                d4.m();
                Fragment fragmentK = d4.k();
                if (fragmentK.f4795n && !fragmentK.X()) {
                    if (fragmentK.f4796o && !this.f4724c.containsKey(fragmentK.f4788g)) {
                        d4.r();
                    }
                    s(d4);
                }
            }
        }
    }

    void u(Fragment fragment) {
        synchronized (this.f4722a) {
            this.f4722a.remove(fragment);
        }
        fragment.f4794m = false;
    }

    void v() {
        this.f4723b.clear();
    }

    void w(List list) {
        this.f4722a.clear();
        if (list != null) {
            Iterator it = list.iterator();
            while (it.hasNext()) {
                String str = (String) it.next();
                Fragment fragmentF = f(str);
                if (fragmentF == null) {
                    throw new IllegalStateException("No instantiated fragment for (" + str + ")");
                }
                if (x.G0(2)) {
                    Log.v("FragmentManager", "restoreSaveState: added (" + str + "): " + fragmentF);
                }
                a(fragmentF);
            }
        }
    }

    void x(ArrayList arrayList) {
        this.f4724c.clear();
        Iterator it = arrayList.iterator();
        while (it.hasNext()) {
            C c3 = (C) it.next();
            this.f4724c.put(c3.f4702b, c3);
        }
    }

    ArrayList y() {
        ArrayList arrayList = new ArrayList(this.f4723b.size());
        for (D d3 : this.f4723b.values()) {
            if (d3 != null) {
                Fragment fragmentK = d3.k();
                d3.r();
                arrayList.add(fragmentK.f4788g);
                if (x.G0(2)) {
                    Log.v("FragmentManager", "Saved state of " + fragmentK + ": " + fragmentK.f4784c);
                }
            }
        }
        return arrayList;
    }

    ArrayList z() {
        synchronized (this.f4722a) {
            try {
                if (this.f4722a.isEmpty()) {
                    return null;
                }
                ArrayList arrayList = new ArrayList(this.f4722a.size());
                for (Fragment fragment : this.f4722a) {
                    arrayList.add(fragment.f4788g);
                    if (x.G0(2)) {
                        Log.v("FragmentManager", "saveAllState: adding fragment (" + fragment.f4788g + "): " + fragment);
                    }
                }
                return arrayList;
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
