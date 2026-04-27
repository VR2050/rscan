package com.facebook.react.common.mapbuffer;

import android.util.SparseArray;
import com.facebook.react.common.mapbuffer.a;
import java.util.Iterator;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class WritableMapBuffer implements com.facebook.react.common.mapbuffer.a {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final SparseArray f6660b = new SparseArray();

    private final class a implements a.c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final int f6661a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final int f6662b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final a.b f6663c;

        public a(int i3) {
            this.f6661a = i3;
            this.f6662b = WritableMapBuffer.this.f6660b.keyAt(i3);
            Object objValueAt = WritableMapBuffer.this.f6660b.valueAt(i3);
            j.e(objValueAt, "valueAt(...)");
            this.f6663c = WritableMapBuffer.this.c(objValueAt, getKey());
        }

        @Override // com.facebook.react.common.mapbuffer.a.c
        public long a() {
            int key = getKey();
            Object objValueAt = WritableMapBuffer.this.f6660b.valueAt(this.f6661a);
            if (objValueAt == null) {
                throw new IllegalArgumentException(("Key not found: " + key).toString());
            }
            if (objValueAt instanceof Long) {
                return ((Number) objValueAt).longValue();
            }
            throw new IllegalStateException(("Expected " + Long.class + " for key: " + key + ", found " + objValueAt.getClass() + " instead.").toString());
        }

        @Override // com.facebook.react.common.mapbuffer.a.c
        public String b() {
            int key = getKey();
            Object objValueAt = WritableMapBuffer.this.f6660b.valueAt(this.f6661a);
            if (objValueAt == null) {
                throw new IllegalArgumentException(("Key not found: " + key).toString());
            }
            if (objValueAt instanceof String) {
                return (String) objValueAt;
            }
            throw new IllegalStateException(("Expected " + String.class + " for key: " + key + ", found " + objValueAt.getClass() + " instead.").toString());
        }

        @Override // com.facebook.react.common.mapbuffer.a.c
        public int c() {
            int key = getKey();
            Object objValueAt = WritableMapBuffer.this.f6660b.valueAt(this.f6661a);
            if (objValueAt == null) {
                throw new IllegalArgumentException(("Key not found: " + key).toString());
            }
            if (objValueAt instanceof Integer) {
                return ((Number) objValueAt).intValue();
            }
            throw new IllegalStateException(("Expected " + Integer.class + " for key: " + key + ", found " + objValueAt.getClass() + " instead.").toString());
        }

        @Override // com.facebook.react.common.mapbuffer.a.c
        public com.facebook.react.common.mapbuffer.a d() {
            int key = getKey();
            Object objValueAt = WritableMapBuffer.this.f6660b.valueAt(this.f6661a);
            if (objValueAt == null) {
                throw new IllegalArgumentException(("Key not found: " + key).toString());
            }
            if (objValueAt instanceof com.facebook.react.common.mapbuffer.a) {
                return (com.facebook.react.common.mapbuffer.a) objValueAt;
            }
            throw new IllegalStateException(("Expected " + com.facebook.react.common.mapbuffer.a.class + " for key: " + key + ", found " + objValueAt.getClass() + " instead.").toString());
        }

        @Override // com.facebook.react.common.mapbuffer.a.c
        public double e() {
            int key = getKey();
            Object objValueAt = WritableMapBuffer.this.f6660b.valueAt(this.f6661a);
            if (objValueAt == null) {
                throw new IllegalArgumentException(("Key not found: " + key).toString());
            }
            if (objValueAt instanceof Double) {
                return ((Number) objValueAt).doubleValue();
            }
            throw new IllegalStateException(("Expected " + Double.class + " for key: " + key + ", found " + objValueAt.getClass() + " instead.").toString());
        }

        @Override // com.facebook.react.common.mapbuffer.a.c
        public boolean f() {
            int key = getKey();
            Object objValueAt = WritableMapBuffer.this.f6660b.valueAt(this.f6661a);
            if (objValueAt == null) {
                throw new IllegalArgumentException(("Key not found: " + key).toString());
            }
            if (objValueAt instanceof Boolean) {
                return ((Boolean) objValueAt).booleanValue();
            }
            throw new IllegalStateException(("Expected " + Boolean.class + " for key: " + key + ", found " + objValueAt.getClass() + " instead.").toString());
        }

        @Override // com.facebook.react.common.mapbuffer.a.c
        public int getKey() {
            return this.f6662b;
        }

        @Override // com.facebook.react.common.mapbuffer.a.c
        public a.b getType() {
            return this.f6663c;
        }
    }

    public static final class b implements Iterator {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private int f6665a;

        b() {
        }

        @Override // java.util.Iterator
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public a.c next() {
            WritableMapBuffer writableMapBuffer = WritableMapBuffer.this;
            int i3 = this.f6665a;
            this.f6665a = i3 + 1;
            return writableMapBuffer.new a(i3);
        }

        @Override // java.util.Iterator
        public boolean hasNext() {
            return this.f6665a < WritableMapBuffer.this.f6660b.size();
        }

        @Override // java.util.Iterator
        public void remove() {
            throw new UnsupportedOperationException("Operation is not supported for read-only collection");
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final a.b c(Object obj, int i3) {
        if (obj instanceof Boolean) {
            return a.b.f6670b;
        }
        if (obj instanceof Integer) {
            return a.b.f6671c;
        }
        if (obj instanceof Long) {
            return a.b.f6675g;
        }
        if (obj instanceof Double) {
            return a.b.f6672d;
        }
        if (obj instanceof String) {
            return a.b.f6673e;
        }
        if (obj instanceof com.facebook.react.common.mapbuffer.a) {
            return a.b.f6674f;
        }
        throw new IllegalStateException("Key " + i3 + " has value of unknown type: " + obj.getClass());
    }

    private final int[] getKeys() {
        int size = this.f6660b.size();
        int[] iArr = new int[size];
        for (int i3 = 0; i3 < size; i3++) {
            iArr[i3] = this.f6660b.keyAt(i3);
        }
        return iArr;
    }

    private final Object[] getValues() {
        int size = this.f6660b.size();
        Object[] objArr = new Object[size];
        for (int i3 = 0; i3 < size; i3++) {
            Object objValueAt = this.f6660b.valueAt(i3);
            j.e(objValueAt, "valueAt(...)");
            objArr[i3] = objValueAt;
        }
        return objArr;
    }

    @Override // com.facebook.react.common.mapbuffer.a
    public com.facebook.react.common.mapbuffer.a d(int i3) {
        Object obj = this.f6660b.get(i3);
        if (obj == null) {
            throw new IllegalArgumentException(("Key not found: " + i3).toString());
        }
        if (obj instanceof com.facebook.react.common.mapbuffer.a) {
            return (com.facebook.react.common.mapbuffer.a) obj;
        }
        throw new IllegalStateException(("Expected " + com.facebook.react.common.mapbuffer.a.class + " for key: " + i3 + ", found " + obj.getClass() + " instead.").toString());
    }

    @Override // com.facebook.react.common.mapbuffer.a
    public boolean g(int i3) {
        return this.f6660b.get(i3) != null;
    }

    @Override // com.facebook.react.common.mapbuffer.a
    public boolean getBoolean(int i3) {
        Object obj = this.f6660b.get(i3);
        if (obj == null) {
            throw new IllegalArgumentException(("Key not found: " + i3).toString());
        }
        if (obj instanceof Boolean) {
            return ((Boolean) obj).booleanValue();
        }
        throw new IllegalStateException(("Expected " + Boolean.class + " for key: " + i3 + ", found " + obj.getClass() + " instead.").toString());
    }

    @Override // com.facebook.react.common.mapbuffer.a
    public int getCount() {
        return this.f6660b.size();
    }

    @Override // com.facebook.react.common.mapbuffer.a
    public double getDouble(int i3) {
        Object obj = this.f6660b.get(i3);
        if (obj == null) {
            throw new IllegalArgumentException(("Key not found: " + i3).toString());
        }
        if (obj instanceof Double) {
            return ((Number) obj).doubleValue();
        }
        throw new IllegalStateException(("Expected " + Double.class + " for key: " + i3 + ", found " + obj.getClass() + " instead.").toString());
    }

    @Override // com.facebook.react.common.mapbuffer.a
    public int getInt(int i3) {
        Object obj = this.f6660b.get(i3);
        if (obj == null) {
            throw new IllegalArgumentException(("Key not found: " + i3).toString());
        }
        if (obj instanceof Integer) {
            return ((Number) obj).intValue();
        }
        throw new IllegalStateException(("Expected " + Integer.class + " for key: " + i3 + ", found " + obj.getClass() + " instead.").toString());
    }

    @Override // com.facebook.react.common.mapbuffer.a
    public String getString(int i3) {
        Object obj = this.f6660b.get(i3);
        if (obj == null) {
            throw new IllegalArgumentException(("Key not found: " + i3).toString());
        }
        if (obj instanceof String) {
            return (String) obj;
        }
        throw new IllegalStateException(("Expected " + String.class + " for key: " + i3 + ", found " + obj.getClass() + " instead.").toString());
    }

    @Override // java.lang.Iterable
    public Iterator iterator() {
        return new b();
    }
}
