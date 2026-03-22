package p005b.p006a.p007a.p008a.p009a;

import android.view.MotionEvent;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import java.lang.reflect.Field;

/* renamed from: b.a.a.a.a.s */
/* loaded from: classes2.dex */
public final class ViewOnTouchListenerC0871s implements View.OnTouchListener {

    /* renamed from: c */
    public final /* synthetic */ EditText f309c;

    public ViewOnTouchListenerC0871s(EditText editText) {
        this.f309c = editText;
    }

    @Override // android.view.View.OnTouchListener
    public boolean onTouch(View view, MotionEvent motionEvent) {
        if (motionEvent.getAction() != 0) {
            return false;
        }
        EditText editText = this.f309c;
        try {
            Field declaredField = TextView.class.getDeclaredField("mEditor");
            declaredField.setAccessible(true);
            Object obj = declaredField.get(editText);
            Class<?> cls = Class.forName("android.widget.Editor");
            Field declaredField2 = cls.getDeclaredField("mInsertionControllerEnabled");
            declaredField2.setAccessible(true);
            Boolean bool = Boolean.FALSE;
            declaredField2.set(obj, bool);
            Field declaredField3 = cls.getDeclaredField("mSelectionControllerEnabled");
            declaredField3.setAccessible(true);
            declaredField3.set(obj, bool);
            return false;
        } catch (Exception e2) {
            e2.printStackTrace();
            return false;
        }
    }
}
