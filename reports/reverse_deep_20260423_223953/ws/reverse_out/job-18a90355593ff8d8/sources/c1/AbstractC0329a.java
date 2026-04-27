package c1;

import com.facebook.react.bridge.ModuleHolder;
import com.facebook.react.bridge.ModuleSpec;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.module.model.ReactModuleInfo;
import com.facebook.react.uimanager.ViewManager;
import i2.AbstractC0586n;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import javax.inject.Provider;
import q1.C0655b;
import v1.InterfaceC0708a;

/* JADX INFO: renamed from: c1.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0329a implements L {

    /* JADX INFO: renamed from: c1.a$a, reason: collision with other inner class name */
    private final class C0087a implements Provider {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final String f5545a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final ReactApplicationContext f5546b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ AbstractC0329a f5547c;

        public C0087a(AbstractC0329a abstractC0329a, String str, ReactApplicationContext reactApplicationContext) {
            t2.j.f(str, "name");
            t2.j.f(reactApplicationContext, "reactContext");
            this.f5547c = abstractC0329a;
            this.f5545a = str;
            this.f5546b = reactApplicationContext;
        }

        @Override // javax.inject.Provider
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public NativeModule get() {
            return this.f5547c.g(this.f5545a, this.f5546b);
        }
    }

    /* JADX INFO: renamed from: c1.a$b */
    public static final class b implements Iterable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ Iterator f5548b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ AbstractC0329a f5549c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ ReactApplicationContext f5550d;

        public b(Iterator it, AbstractC0329a abstractC0329a, ReactApplicationContext reactApplicationContext) {
            this.f5548b = it;
            this.f5549c = abstractC0329a;
            this.f5550d = reactApplicationContext;
        }

        @Override // java.lang.Iterable
        public Iterator iterator() {
            return new c(this.f5548b, this.f5549c, this.f5550d);
        }
    }

    /* JADX INFO: renamed from: c1.a$c */
    public static final class c implements Iterator {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private Map.Entry f5551a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ Iterator f5552b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ AbstractC0329a f5553c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ ReactApplicationContext f5554d;

        c(Iterator it, AbstractC0329a abstractC0329a, ReactApplicationContext reactApplicationContext) {
            this.f5552b = it;
            this.f5553c = abstractC0329a;
            this.f5554d = reactApplicationContext;
        }

        private final void a() {
            while (this.f5552b.hasNext()) {
                Map.Entry entry = (Map.Entry) this.f5552b.next();
                ReactModuleInfo reactModuleInfo = (ReactModuleInfo) entry.getValue();
                if (!C0655b.t() || !reactModuleInfo.e()) {
                    this.f5551a = entry;
                    return;
                }
            }
            this.f5551a = null;
        }

        @Override // java.util.Iterator
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public ModuleHolder next() {
            if (this.f5551a == null) {
                a();
            }
            Map.Entry entry = this.f5551a;
            if (entry == null) {
                throw new NoSuchElementException("ModuleHolder not found");
            }
            a();
            return new ModuleHolder((ReactModuleInfo) entry.getValue(), new C0087a(this.f5553c, (String) entry.getKey(), this.f5554d));
        }

        @Override // java.util.Iterator
        public boolean hasNext() {
            if (this.f5551a == null) {
                a();
            }
            return this.f5551a != null;
        }

        @Override // java.util.Iterator
        public void remove() {
            throw new UnsupportedOperationException("Operation is not supported for read-only collection");
        }
    }

    @Override // c1.L
    public List e(ReactApplicationContext reactApplicationContext) {
        t2.j.f(reactApplicationContext, "reactContext");
        throw new UnsupportedOperationException("createNativeModules method is not supported. Use getModule() method instead.");
    }

    @Override // c1.L
    public List f(ReactApplicationContext reactApplicationContext) {
        t2.j.f(reactApplicationContext, "reactContext");
        List listJ = j(reactApplicationContext);
        if (listJ == null || listJ.isEmpty()) {
            return AbstractC0586n.g();
        }
        ArrayList arrayList = new ArrayList();
        Iterator it = listJ.iterator();
        while (it.hasNext()) {
            Object obj = ((ModuleSpec) it.next()).getProvider().get();
            t2.j.d(obj, "null cannot be cast to non-null type com.facebook.react.uimanager.ViewManager<*, *>");
            arrayList.add((ViewManager) obj);
        }
        return arrayList;
    }

    public abstract NativeModule g(String str, ReactApplicationContext reactApplicationContext);

    public final Iterable h(ReactApplicationContext reactApplicationContext) {
        t2.j.f(reactApplicationContext, "reactContext");
        return new b(i().a().entrySet().iterator(), this, reactApplicationContext);
    }

    public abstract InterfaceC0708a i();

    protected List j(ReactApplicationContext reactApplicationContext) {
        t2.j.f(reactApplicationContext, "reactContext");
        return AbstractC0586n.g();
    }
}
