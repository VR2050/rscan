package androidx.dynamicanimation.animation;

import androidx.annotation.RequiresApi;
import p403d.p410b.AbstractC4197a;

/* loaded from: classes.dex */
public abstract class FloatPropertyCompat<T> {
    public final String mPropertyName;

    /* renamed from: androidx.dynamicanimation.animation.FloatPropertyCompat$1 */
    public static class C04041 extends FloatPropertyCompat<T> {
        public final /* synthetic */ AbstractC4197a val$property;

        public C04041(String str, AbstractC4197a abstractC4197a) {
            super(str);
        }

        @Override // androidx.dynamicanimation.animation.FloatPropertyCompat
        public float getValue(T t) {
            throw null;
        }

        @Override // androidx.dynamicanimation.animation.FloatPropertyCompat
        public void setValue(T t, float f2) {
            throw null;
        }
    }

    public FloatPropertyCompat(String str) {
        this.mPropertyName = str;
    }

    @RequiresApi(24)
    public static <T> FloatPropertyCompat<T> createFloatPropertyCompat(AbstractC4197a<T> abstractC4197a) {
        throw null;
    }

    public abstract float getValue(T t);

    public abstract void setValue(T t, float f2);
}
