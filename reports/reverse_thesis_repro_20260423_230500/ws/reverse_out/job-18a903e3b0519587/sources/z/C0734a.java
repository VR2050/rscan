package z;

import android.text.method.KeyListener;
import android.text.method.NumberKeyListener;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.widget.EditText;

/* JADX INFO: renamed from: z.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0734a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final b f10507a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int f10508b = Integer.MAX_VALUE;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private int f10509c = 0;

    /* JADX INFO: renamed from: z.a$a, reason: collision with other inner class name */
    private static class C0162a extends b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final EditText f10510a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final g f10511b;

        C0162a(EditText editText, boolean z3) {
            this.f10510a = editText;
            g gVar = new g(editText, z3);
            this.f10511b = gVar;
            editText.addTextChangedListener(gVar);
            editText.setEditableFactory(C0735b.getInstance());
        }

        @Override // z.C0734a.b
        KeyListener a(KeyListener keyListener) {
            if (keyListener instanceof e) {
                return keyListener;
            }
            if (keyListener == null) {
                return null;
            }
            return keyListener instanceof NumberKeyListener ? keyListener : new e(keyListener);
        }

        @Override // z.C0734a.b
        InputConnection b(InputConnection inputConnection, EditorInfo editorInfo) {
            return inputConnection instanceof c ? inputConnection : new c(this.f10510a, inputConnection, editorInfo);
        }

        @Override // z.C0734a.b
        void c(boolean z3) {
            this.f10511b.c(z3);
        }
    }

    /* JADX INFO: renamed from: z.a$b */
    static class b {
        b() {
        }

        abstract KeyListener a(KeyListener keyListener);

        abstract InputConnection b(InputConnection inputConnection, EditorInfo editorInfo);

        abstract void c(boolean z3);
    }

    public C0734a(EditText editText, boolean z3) {
        q.g.g(editText, "editText cannot be null");
        this.f10507a = new C0162a(editText, z3);
    }

    public KeyListener a(KeyListener keyListener) {
        return this.f10507a.a(keyListener);
    }

    public InputConnection b(InputConnection inputConnection, EditorInfo editorInfo) {
        if (inputConnection == null) {
            return null;
        }
        return this.f10507a.b(inputConnection, editorInfo);
    }

    public void c(boolean z3) {
        this.f10507a.c(z3);
    }
}
