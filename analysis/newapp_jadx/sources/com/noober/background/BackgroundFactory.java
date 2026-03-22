package com.noober.background;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.LayerDrawable;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.TextView;
import androidx.annotation.Nullable;
import androidx.collection.ArrayMap;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public class BackgroundFactory implements LayoutInflater.Factory2 {
    private LayoutInflater.Factory mViewCreateFactory;
    private LayoutInflater.Factory2 mViewCreateFactory2;
    private static final Class<?>[] sConstructorSignature = {Context.class, AttributeSet.class};
    private static final Object[] mConstructorArgs = new Object[2];
    private static final Map<String, Constructor<? extends View>> sConstructorMap = new ArrayMap();
    private static final HashMap<String, HashMap<String, Method>> methodMap = new HashMap<>();

    /* renamed from: com.noober.background.BackgroundFactory$a */
    public static class ViewOnClickListenerC4026a implements View.OnClickListener {

        /* renamed from: c */
        public final /* synthetic */ Method f10253c;

        /* renamed from: e */
        public final /* synthetic */ Context f10254e;

        public ViewOnClickListenerC4026a(Method method, Context context) {
            this.f10253c = method;
            this.f10254e = context;
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            try {
                this.f10253c.invoke(this.f10254e, new Object[0]);
            } catch (IllegalAccessException e2) {
                e2.printStackTrace();
            } catch (InvocationTargetException e3) {
                e3.printStackTrace();
            }
        }
    }

    private static View createView(Context context, String str, String str2) {
        String str3;
        Map<String, Constructor<? extends View>> map = sConstructorMap;
        Constructor<? extends View> constructor = map.get(str);
        if (constructor == null) {
            try {
                ClassLoader classLoader = context.getClassLoader();
                if (str2 != null) {
                    str3 = str2 + str;
                } else {
                    str3 = str;
                }
                constructor = classLoader.loadClass(str3).asSubclass(View.class).getConstructor(sConstructorSignature);
                map.put(str, constructor);
            } catch (Exception unused) {
                return null;
            }
        }
        constructor.setAccessible(true);
        return constructor.newInstance(mConstructorArgs);
    }

    private static View createViewFromTag(Context context, String str, AttributeSet attributeSet) {
        if (TextUtils.isEmpty(str)) {
            return null;
        }
        if (str.equals("view")) {
            str = attributeSet.getAttributeValue(null, "class");
        }
        try {
            Object[] objArr = mConstructorArgs;
            objArr[0] = context;
            objArr[1] = attributeSet;
            if (-1 != str.indexOf(46)) {
                View createView = createView(context, str, null);
                objArr[0] = null;
                objArr[1] = null;
                return createView;
            }
            View createView2 = "View".equals(str) ? createView(context, str, "android.view.") : null;
            if (createView2 == null) {
                createView2 = createView(context, str, "android.widget.");
            }
            if (createView2 == null) {
                createView2 = createView(context, str, "android.webkit.");
            }
            objArr[0] = null;
            objArr[1] = null;
            return createView2;
        } catch (Exception unused) {
            Object[] objArr2 = mConstructorArgs;
            objArr2[0] = null;
            objArr2[1] = null;
            return null;
        } catch (Throwable th) {
            Object[] objArr3 = mConstructorArgs;
            objArr3[0] = null;
            objArr3[1] = null;
            throw th;
        }
    }

    private static Method findDeclaredMethod(Class cls, String str) {
        Method method = null;
        try {
            method = cls.getDeclaredMethod(str, new Class[0]);
            method.setAccessible(true);
            return method;
        } catch (NoSuchMethodException unused) {
            return cls.getSuperclass() != null ? findDeclaredMethod(cls.getSuperclass(), str) : method;
        }
    }

    private static Method findMethod(Class cls, String str) {
        try {
            return cls.getMethod(str, new Class[0]);
        } catch (NoSuchMethodException unused) {
            return findDeclaredMethod(cls, str);
        }
    }

    private static Method getMethod(Class cls, String str) {
        Method method;
        HashMap<String, HashMap<String, Method>> hashMap = methodMap;
        HashMap<String, Method> hashMap2 = hashMap.get(cls.getCanonicalName());
        if (hashMap2 != null) {
            method = hashMap.get(cls.getCanonicalName()).get(str);
        } else {
            hashMap2 = new HashMap<>();
            hashMap.put(cls.getCanonicalName(), hashMap2);
            method = null;
        }
        if (method == null && (method = findMethod(cls, str)) != null) {
            hashMap2.put(str, method);
        }
        return method;
    }

    private static boolean hasStatus(int i2, int i3) {
        return (i2 & i3) == i3;
    }

    private static void setBackground(Drawable drawable, View view, TypedArray typedArray) {
        int i2 = C4028R.styleable.background_bl_stroke_width;
        if (typedArray.hasValue(i2)) {
            int i3 = C4028R.styleable.background_bl_stroke_position;
            if (typedArray.hasValue(i3)) {
                float dimension = typedArray.getDimension(i2, 0.0f);
                int i4 = typedArray.getInt(i3, 0);
                float f2 = hasStatus(i4, 2) ? dimension : -dimension;
                float f3 = hasStatus(i4, 4) ? dimension : -dimension;
                float f4 = hasStatus(i4, 8) ? dimension : -dimension;
                if (!hasStatus(i4, 16)) {
                    dimension = -dimension;
                }
                LayerDrawable layerDrawable = new LayerDrawable(new Drawable[]{drawable});
                layerDrawable.setLayerInset(0, (int) f2, (int) f3, (int) f4, (int) dimension);
                drawable = layerDrawable;
            }
        }
        view.setBackground(drawable);
    }

    private static void setDrawable(Drawable drawable, View view, TypedArray typedArray, TypedArray typedArray2) {
        if (!(view instanceof TextView)) {
            setBackground(drawable, view, typedArray2);
            return;
        }
        int i2 = C4028R.styleable.bl_other_bl_position;
        if (!typedArray.hasValue(i2)) {
            setBackground(drawable, view, typedArray2);
            return;
        }
        if (typedArray.getInt(i2, 0) == 1) {
            drawable.setBounds(0, 0, drawable.getMinimumWidth(), drawable.getMinimumHeight());
            ((TextView) view).setCompoundDrawables(drawable, null, null, null);
            return;
        }
        if (typedArray.getInt(i2, 0) == 2) {
            drawable.setBounds(0, 0, drawable.getMinimumWidth(), drawable.getMinimumHeight());
            ((TextView) view).setCompoundDrawables(null, drawable, null, null);
        } else if (typedArray.getInt(i2, 0) == 4) {
            drawable.setBounds(0, 0, drawable.getMinimumWidth(), drawable.getMinimumHeight());
            ((TextView) view).setCompoundDrawables(null, null, drawable, null);
        } else if (typedArray.getInt(i2, 0) == 8) {
            drawable.setBounds(0, 0, drawable.getMinimumWidth(), drawable.getMinimumHeight());
            ((TextView) view).setCompoundDrawables(null, null, null, drawable);
        }
    }

    @Nullable
    public static View setViewBackground(Context context, AttributeSet attributeSet, View view) {
        return setViewBackground(null, context, attributeSet, view);
    }

    @Override // android.view.LayoutInflater.Factory
    public View onCreateView(String str, Context context, AttributeSet attributeSet) {
        View view = null;
        if (str.startsWith("com.noober.background.view")) {
            return null;
        }
        LayoutInflater.Factory2 factory2 = this.mViewCreateFactory2;
        if (factory2 != null) {
            View onCreateView = factory2.onCreateView(str, context, attributeSet);
            view = onCreateView == null ? this.mViewCreateFactory2.onCreateView(null, str, context, attributeSet) : onCreateView;
        } else {
            LayoutInflater.Factory factory = this.mViewCreateFactory;
            if (factory != null) {
                view = factory.onCreateView(str, context, attributeSet);
            }
        }
        return setViewBackground(str, context, attributeSet, view);
    }

    public void setInterceptFactory(LayoutInflater.Factory factory) {
        this.mViewCreateFactory = factory;
    }

    public void setInterceptFactory2(LayoutInflater.Factory2 factory2) {
        this.mViewCreateFactory2 = factory2;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:52:0x0158 A[Catch: Exception -> 0x01e7, all -> 0x01e9, TryCatch #1 {Exception -> 0x01e7, blocks: (B:30:0x00b0, B:32:0x00b6, B:35:0x00bd, B:36:0x00c4, B:37:0x00c5, B:39:0x00cb, B:42:0x00d2, B:43:0x00d9, B:44:0x00da, B:46:0x00e2, B:48:0x00e6, B:50:0x0154, B:52:0x0158, B:54:0x015e, B:55:0x017d, B:57:0x0185, B:59:0x018d, B:62:0x0194, B:63:0x01a3, B:65:0x01ab, B:67:0x01b5, B:69:0x01c3, B:72:0x0169, B:74:0x016d, B:76:0x0173, B:77:0x00f4, B:79:0x00fa, B:81:0x010a, B:83:0x0110, B:84:0x011f, B:86:0x0125, B:87:0x012d, B:89:0x0133, B:90:0x013b, B:92:0x0141, B:94:0x0150), top: B:29:0x00b0 }] */
    /* JADX WARN: Removed duplicated region for block: B:57:0x0185 A[Catch: Exception -> 0x01e7, all -> 0x01e9, TryCatch #1 {Exception -> 0x01e7, blocks: (B:30:0x00b0, B:32:0x00b6, B:35:0x00bd, B:36:0x00c4, B:37:0x00c5, B:39:0x00cb, B:42:0x00d2, B:43:0x00d9, B:44:0x00da, B:46:0x00e2, B:48:0x00e6, B:50:0x0154, B:52:0x0158, B:54:0x015e, B:55:0x017d, B:57:0x0185, B:59:0x018d, B:62:0x0194, B:63:0x01a3, B:65:0x01ab, B:67:0x01b5, B:69:0x01c3, B:72:0x0169, B:74:0x016d, B:76:0x0173, B:77:0x00f4, B:79:0x00fa, B:81:0x010a, B:83:0x0110, B:84:0x011f, B:86:0x0125, B:87:0x012d, B:89:0x0133, B:90:0x013b, B:92:0x0141, B:94:0x0150), top: B:29:0x00b0 }] */
    /* JADX WARN: Removed duplicated region for block: B:65:0x01ab A[Catch: Exception -> 0x01e7, all -> 0x01e9, TryCatch #1 {Exception -> 0x01e7, blocks: (B:30:0x00b0, B:32:0x00b6, B:35:0x00bd, B:36:0x00c4, B:37:0x00c5, B:39:0x00cb, B:42:0x00d2, B:43:0x00d9, B:44:0x00da, B:46:0x00e2, B:48:0x00e6, B:50:0x0154, B:52:0x0158, B:54:0x015e, B:55:0x017d, B:57:0x0185, B:59:0x018d, B:62:0x0194, B:63:0x01a3, B:65:0x01ab, B:67:0x01b5, B:69:0x01c3, B:72:0x0169, B:74:0x016d, B:76:0x0173, B:77:0x00f4, B:79:0x00fa, B:81:0x010a, B:83:0x0110, B:84:0x011f, B:86:0x0125, B:87:0x012d, B:89:0x0133, B:90:0x013b, B:92:0x0141, B:94:0x0150), top: B:29:0x00b0 }] */
    /* JADX WARN: Removed duplicated region for block: B:74:0x016d A[Catch: Exception -> 0x01e7, all -> 0x01e9, TryCatch #1 {Exception -> 0x01e7, blocks: (B:30:0x00b0, B:32:0x00b6, B:35:0x00bd, B:36:0x00c4, B:37:0x00c5, B:39:0x00cb, B:42:0x00d2, B:43:0x00d9, B:44:0x00da, B:46:0x00e2, B:48:0x00e6, B:50:0x0154, B:52:0x0158, B:54:0x015e, B:55:0x017d, B:57:0x0185, B:59:0x018d, B:62:0x0194, B:63:0x01a3, B:65:0x01ab, B:67:0x01b5, B:69:0x01c3, B:72:0x0169, B:74:0x016d, B:76:0x0173, B:77:0x00f4, B:79:0x00fa, B:81:0x010a, B:83:0x0110, B:84:0x011f, B:86:0x0125, B:87:0x012d, B:89:0x0133, B:90:0x013b, B:92:0x0141, B:94:0x0150), top: B:29:0x00b0 }] */
    /* JADX WARN: Type inference failed for: r12v10, types: [android.graphics.drawable.Drawable, android.graphics.drawable.StateListDrawable] */
    /* JADX WARN: Type inference failed for: r12v11, types: [android.graphics.drawable.Drawable, android.graphics.drawable.StateListDrawable] */
    /* JADX WARN: Type inference failed for: r12v14, types: [android.graphics.drawable.Drawable, android.graphics.drawable.StateListDrawable] */
    @androidx.annotation.Nullable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static android.view.View setViewBackground(java.lang.String r17, android.content.Context r18, android.util.AttributeSet r19, android.view.View r20) {
        /*
            Method dump skipped, instructions count: 553
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.noober.background.BackgroundFactory.setViewBackground(java.lang.String, android.content.Context, android.util.AttributeSet, android.view.View):android.view.View");
    }

    @Override // android.view.LayoutInflater.Factory2
    public View onCreateView(View view, String str, Context context, AttributeSet attributeSet) {
        return onCreateView(str, context, attributeSet);
    }
}
