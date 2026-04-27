package c1;

import com.facebook.react.bridge.ModuleHolder;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import java.util.Iterator;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public final class M {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final M f5511a = new M();

    public static final class a implements Iterable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ List f5512b;

        public a(List list) {
            this.f5512b = list;
        }

        @Override // java.lang.Iterable
        public Iterator iterator() {
            return new b(this.f5512b);
        }
    }

    public static final class b implements Iterator {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private int f5513a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ List f5514b;

        b(List list) {
            this.f5514b = list;
        }

        @Override // java.util.Iterator
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public ModuleHolder next() {
            List list = this.f5514b;
            int i3 = this.f5513a;
            this.f5513a = i3 + 1;
            return new ModuleHolder((NativeModule) list.get(i3));
        }

        @Override // java.util.Iterator
        public boolean hasNext() {
            return this.f5513a < this.f5514b.size();
        }

        @Override // java.util.Iterator
        public void remove() {
            throw new UnsupportedOperationException("Operation is not supported for read-only collection");
        }
    }

    private M() {
    }

    public final Iterable a(L l3, ReactApplicationContext reactApplicationContext) {
        t2.j.f(l3, "reactPackage");
        t2.j.f(reactApplicationContext, "reactApplicationContext");
        Y.a.b("ReactNative", l3.getClass().getSimpleName() + " is not a LazyReactPackage, falling back to old version.");
        return new a(l3.e(reactApplicationContext));
    }
}
