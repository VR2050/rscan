package com.facebook.react.animated;

import com.facebook.react.bridge.JavaOnlyArray;
import com.facebook.react.bridge.JavaOnlyMap;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import i2.AbstractC0586n;
import java.util.ArrayList;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public final class v extends com.facebook.react.animated.b {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final o f6613f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final List f6614g;

    private final class a extends c {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private int f6615c;

        public a() {
            super();
        }

        public final int c() {
            return this.f6615c;
        }

        public final void d(int i3) {
            this.f6615c = i3;
        }
    }

    private final class b extends c {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private double f6617c;

        public b() {
            super();
        }

        public final double c() {
            return this.f6617c;
        }

        public final void d(double d3) {
            this.f6617c = d3;
        }
    }

    private class c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private String f6619a;

        public c() {
        }

        public final String a() {
            return this.f6619a;
        }

        public final void b(String str) {
            this.f6619a = str;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r4v3, types: [com.facebook.react.animated.v$b, com.facebook.react.animated.v$c] */
    /* JADX WARN: Type inference failed for: r4v4, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r4v5, types: [com.facebook.react.animated.v$a, com.facebook.react.animated.v$c] */
    public v(ReadableMap readableMap, o oVar) {
        List listG;
        ?? bVar;
        t2.j.f(readableMap, "config");
        t2.j.f(oVar, "nativeAnimatedNodesManager");
        this.f6613f = oVar;
        ReadableArray array = readableMap.getArray("transforms");
        if (array == null) {
            listG = AbstractC0586n.g();
        } else {
            int size = array.size();
            ArrayList arrayList = new ArrayList(size);
            for (int i3 = 0; i3 < size; i3++) {
                ReadableMap map = array.getMap(i3);
                if (map == null) {
                    throw new IllegalStateException("Required value was null.");
                }
                String string = map.getString("property");
                if (t2.j.b(map.getString("type"), "animated")) {
                    bVar = new a();
                    bVar.b(string);
                    bVar.d(map.getInt("nodeTag"));
                } else {
                    bVar = new b();
                    bVar.b(string);
                    bVar.d(map.getDouble("value"));
                }
                arrayList.add(bVar);
            }
            listG = arrayList;
        }
        this.f6614g = listG;
    }

    @Override // com.facebook.react.animated.b
    public String e() {
        return "TransformAnimatedNode[" + this.f6507d + "]: transformConfigs: " + this.f6614g;
    }

    public final void i(JavaOnlyMap javaOnlyMap) {
        double dC;
        t2.j.f(javaOnlyMap, "propsMap");
        int size = this.f6614g.size();
        ArrayList arrayList = new ArrayList(size);
        for (int i3 = 0; i3 < size; i3++) {
            c cVar = (c) this.f6614g.get(i3);
            if (cVar instanceof a) {
                com.facebook.react.animated.b bVarL = this.f6613f.l(((a) cVar).c());
                if (bVarL == null) {
                    throw new IllegalArgumentException("Mapped style node does not exist");
                }
                if (!(bVarL instanceof w)) {
                    throw new IllegalArgumentException("Unsupported type of node used as a transform child node " + bVarL.getClass());
                }
                dC = ((w) bVarL).l();
            } else {
                t2.j.d(cVar, "null cannot be cast to non-null type com.facebook.react.animated.TransformAnimatedNode.StaticTransformConfig");
                dC = ((b) cVar).c();
            }
            arrayList.add(JavaOnlyMap.Companion.of(cVar.a(), Double.valueOf(dC)));
        }
        javaOnlyMap.putArray("transform", JavaOnlyArray.Companion.from(arrayList));
    }
}
