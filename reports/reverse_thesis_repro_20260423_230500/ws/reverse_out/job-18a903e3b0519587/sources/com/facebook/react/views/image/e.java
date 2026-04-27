package com.facebook.react.views.image;

import android.graphics.Bitmap;
import b0.AbstractC0311a;
import i2.AbstractC0586n;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class e implements T0.d {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final a f7805b = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final List f7806a;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final T0.d a(List list) {
            j.f(list, "postprocessors");
            int size = list.size();
            DefaultConstructorMarker defaultConstructorMarker = null;
            if (size != 0) {
                return size != 1 ? new e(list, defaultConstructorMarker) : (T0.d) list.get(0);
            }
            return null;
        }

        private a() {
        }
    }

    public /* synthetic */ e(List list, DefaultConstructorMarker defaultConstructorMarker) {
        this(list);
    }

    @Override // T0.d
    public AbstractC0311a a(Bitmap bitmap, F0.b bVar) {
        Bitmap bitmap2;
        j.f(bitmap, "sourceBitmap");
        j.f(bVar, "bitmapFactory");
        AbstractC0311a abstractC0311aA = null;
        try {
            AbstractC0311a abstractC0311aClone = null;
            for (T0.d dVar : this.f7806a) {
                if (abstractC0311aClone == null || (bitmap2 = (Bitmap) abstractC0311aClone.P()) == null) {
                    bitmap2 = bitmap;
                }
                abstractC0311aA = dVar.a(bitmap2, bVar);
                AbstractC0311a.D(abstractC0311aClone);
                abstractC0311aClone = abstractC0311aA.clone();
            }
            if (abstractC0311aA != null) {
                AbstractC0311a abstractC0311aClone2 = abstractC0311aA.clone();
                j.e(abstractC0311aClone2, "clone(...)");
                AbstractC0311a.D(abstractC0311aA);
                return abstractC0311aClone2;
            }
            throw new IllegalStateException(("MultiPostprocessor returned null bitmap - Number of Postprocessors: " + this.f7806a.size()).toString());
        } catch (Throwable th) {
            AbstractC0311a.D(null);
            throw th;
        }
    }

    @Override // T0.d
    public R.d b() {
        List list = this.f7806a;
        ArrayList arrayList = new ArrayList(AbstractC0586n.o(list, 10));
        Iterator it = list.iterator();
        while (it.hasNext()) {
            arrayList.add(((T0.d) it.next()).b());
        }
        return new R.f(arrayList);
    }

    @Override // T0.d
    public String getName() {
        return "MultiPostProcessor (" + AbstractC0586n.J(this.f7806a, ",", null, null, 0, null, null, 62, null) + ")";
    }

    private e(List list) {
        this.f7806a = new LinkedList(list);
    }
}
