package p005b.p139f.p140a.p142b;

import android.content.res.Resources;
import android.util.DisplayMetrics;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.f.a.b.a */
/* loaded from: classes.dex */
public class RunnableC1531a implements Runnable {
    @Override // java.lang.Runnable
    public void run() {
        DisplayMetrics displayMetrics;
        Resources system = Resources.getSystem();
        float f2 = Resources.getSystem().getDisplayMetrics().xdpi;
        system.getDisplayMetrics().xdpi = f2;
        C4195m.m4792Y().getResources().getDisplayMetrics().xdpi = f2;
        List<Field> list = C4195m.f10935c;
        if (list != null) {
            Iterator<Field> it = list.iterator();
            while (it.hasNext()) {
                try {
                    DisplayMetrics displayMetrics2 = (DisplayMetrics) it.next().get(system);
                    if (displayMetrics2 != null) {
                        displayMetrics2.xdpi = f2;
                    }
                } catch (Exception e2) {
                    e2.printStackTrace();
                }
            }
            return;
        }
        C4195m.f10935c = new ArrayList();
        Class<?> cls = system.getClass();
        Field[] declaredFields = cls.getDeclaredFields();
        while (declaredFields != null && declaredFields.length > 0) {
            for (Field field : declaredFields) {
                if (field.getType().isAssignableFrom(DisplayMetrics.class)) {
                    field.setAccessible(true);
                    try {
                        displayMetrics = (DisplayMetrics) field.get(system);
                    } catch (Exception unused) {
                        displayMetrics = null;
                    }
                    if (displayMetrics != null) {
                        C4195m.f10935c.add(field);
                        displayMetrics.xdpi = f2;
                    }
                }
            }
            cls = cls.getSuperclass();
            if (cls == null) {
                return;
            } else {
                declaredFields = cls.getDeclaredFields();
            }
        }
    }
}
