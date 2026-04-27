package c1;

import com.facebook.react.bridge.ModuleHolder;
import com.facebook.react.bridge.NativeModuleRegistry;
import com.facebook.react.bridge.ReactApplicationContext;
import java.util.HashMap;

/* JADX INFO: renamed from: c1.h, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0336h {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final ReactApplicationContext f5568a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final HashMap f5569b;

    public C0336h(ReactApplicationContext reactApplicationContext) {
        t2.j.f(reactApplicationContext, "reactApplicationContext");
        this.f5568a = reactApplicationContext;
        this.f5569b = new HashMap();
    }

    public final NativeModuleRegistry a() {
        return new NativeModuleRegistry(this.f5568a, this.f5569b);
    }

    public final void b(L l3) {
        t2.j.f(l3, "reactPackage");
        for (ModuleHolder moduleHolder : l3 instanceof AbstractC0329a ? ((AbstractC0329a) l3).h(this.f5568a) : M.f5511a.a(l3, this.f5568a)) {
            String name = moduleHolder.getName();
            ModuleHolder moduleHolder2 = (ModuleHolder) this.f5569b.get(name);
            if (moduleHolder2 != null && !moduleHolder.getCanOverrideExistingModule()) {
                throw new IllegalStateException(("\nNative module " + name + " tried to override " + moduleHolder2.getClassName() + ".\n\nCheck the getPackages() method in MainApplication.java, it might be that module is being created twice. \nIf this was your intention, set canOverrideExistingModule=true. This error may also be present if the \npackage is present only once in getPackages() but is also automatically added later during build time \nby autolinking. Try removing the existing entry and rebuild.\n").toString());
            }
            this.f5569b.put(name, moduleHolder);
        }
    }
}
