package com.facebook.react.uimanager;

import android.view.View;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.uimanager.X0;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public final class R0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final R0 f7496a = new R0();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static final Map f7497b = new HashMap();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static final Map f7498c = new HashMap();

    private static final class a implements e {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final Map f7499a;

        public a(Class cls) {
            t2.j.f(cls, "shadowNodeClass");
            Map mapH = X0.h(cls);
            t2.j.e(mapH, "getNativePropSettersForShadowNodeClass(...)");
            this.f7499a = mapH;
        }

        @Override // com.facebook.react.uimanager.R0.d
        public void b(Map map) {
            t2.j.f(map, "props");
            for (X0.m mVar : this.f7499a.values()) {
                map.put(mVar.a(), mVar.b());
            }
        }

        @Override // com.facebook.react.uimanager.R0.e
        public void c(InterfaceC0466q0 interfaceC0466q0, String str, Object obj) {
            t2.j.f(interfaceC0466q0, "node");
            t2.j.f(str, "name");
            X0.m mVar = (X0.m) this.f7499a.get(str);
            if (mVar != null) {
                mVar.d(interfaceC0466q0, obj);
            }
        }
    }

    private static final class b implements f {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final Map f7500a;

        public b(Class cls) {
            t2.j.f(cls, "viewManagerClass");
            Map mapI = X0.i(cls);
            t2.j.e(mapI, "getNativePropSettersForViewManagerClass(...)");
            this.f7500a = mapI;
        }

        @Override // com.facebook.react.uimanager.R0.f
        public void a(ViewManager viewManager, View view, String str, Object obj) {
            t2.j.f(viewManager, "manager");
            t2.j.f(view, "view");
            t2.j.f(str, "name");
            X0.m mVar = (X0.m) this.f7500a.get(str);
            if (mVar != null) {
                mVar.e(viewManager, view, obj);
            }
        }

        @Override // com.facebook.react.uimanager.R0.d
        public void b(Map map) {
            t2.j.f(map, "props");
            for (X0.m mVar : this.f7500a.values()) {
                map.put(mVar.a(), mVar.b());
            }
        }
    }

    public static final class c implements Q0 {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final ViewManager f7501a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final f f7502b;

        public c(ViewManager viewManager) {
            t2.j.f(viewManager, "manager");
            this.f7501a = viewManager;
            this.f7502b = R0.f7496a.d(viewManager.getClass());
        }

        @Override // com.facebook.react.uimanager.Q0
        public void a(View view, String str, ReadableArray readableArray) {
            t2.j.f(view, "view");
            t2.j.f(str, "commandName");
        }

        @Override // com.facebook.react.uimanager.Q0
        public void b(View view, String str, Object obj) {
            t2.j.f(view, "view");
            t2.j.f(str, "propName");
            this.f7502b.a(this.f7501a, view, str, obj);
        }
    }

    public interface d {
        void b(Map map);
    }

    public interface e extends d {
        void c(InterfaceC0466q0 interfaceC0466q0, String str, Object obj);
    }

    public interface f extends d {
        void a(ViewManager viewManager, View view, String str, Object obj);
    }

    private R0() {
    }

    public static final void b() {
        X0.b();
        f7497b.clear();
        f7498c.clear();
    }

    private final Object c(Class cls) {
        String name = cls.getName();
        try {
            return Class.forName(name + "$$PropsSetter").newInstance();
        } catch (ClassNotFoundException unused) {
            Y.a.I("ViewManagerPropertyUpdater", "Could not find generated setter for " + cls);
            return null;
        } catch (IllegalAccessException e3) {
            throw new RuntimeException("Unable to instantiate methods getter for " + name, e3);
        } catch (InstantiationException e4) {
            throw new RuntimeException("Unable to instantiate methods getter for " + name, e4);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final f d(Class cls) {
        Map map = f7497b;
        f bVar = (f) map.get(cls);
        if (bVar == null) {
            bVar = (f) c(cls);
            if (bVar == null) {
                bVar = new b(cls);
            }
            map.put(cls, bVar);
        }
        return bVar;
    }

    private final e e(Class cls) {
        Map map = f7498c;
        e aVar = (e) map.get(cls);
        if (aVar == null) {
            aVar = (e) c(cls);
            if (aVar == null) {
                t2.j.d(cls, "null cannot be cast to non-null type java.lang.Class<kotlin.Nothing>");
                aVar = new a(cls);
            }
            map.put(cls, aVar);
        }
        return aVar;
    }

    public static final Map f(Class cls, Class cls2) {
        t2.j.f(cls, "viewManagerTopClass");
        t2.j.f(cls2, "shadowNodeTopClass");
        HashMap map = new HashMap();
        R0 r02 = f7496a;
        r02.d(cls).b(map);
        r02.e(cls2).b(map);
        return map;
    }

    public static final void g(InterfaceC0466q0 interfaceC0466q0, C0469s0 c0469s0) {
        t2.j.f(interfaceC0466q0, "node");
        t2.j.f(c0469s0, "props");
        e eVarE = f7496a.e(interfaceC0466q0.getClass());
        Iterator<Map.Entry<String, Object>> entryIterator = c0469s0.f7757a.getEntryIterator();
        while (entryIterator.hasNext()) {
            Map.Entry<String, Object> next = entryIterator.next();
            eVarE.c(interfaceC0466q0, next.getKey(), next.getValue());
        }
    }
}
