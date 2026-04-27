package z;

import android.text.Editable;
import android.text.Selection;
import android.text.Spannable;
import android.text.TextWatcher;
import android.widget.EditText;
import androidx.emoji2.text.f;
import java.lang.ref.Reference;
import java.lang.ref.WeakReference;

/* JADX INFO: loaded from: classes.dex */
final class g implements TextWatcher {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final EditText f10528b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final boolean f10529c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private f.AbstractC0070f f10530d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private int f10531e = Integer.MAX_VALUE;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private int f10532f = 0;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private boolean f10533g = true;

    private static class a extends f.AbstractC0070f {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final Reference f10534a;

        a(EditText editText) {
            this.f10534a = new WeakReference(editText);
        }

        @Override // androidx.emoji2.text.f.AbstractC0070f
        public void b() {
            super.b();
            g.b((EditText) this.f10534a.get(), 1);
        }
    }

    g(EditText editText, boolean z3) {
        this.f10528b = editText;
        this.f10529c = z3;
    }

    private f.AbstractC0070f a() {
        if (this.f10530d == null) {
            this.f10530d = new a(this.f10528b);
        }
        return this.f10530d;
    }

    static void b(EditText editText, int i3) {
        if (i3 == 1 && editText != null && editText.isAttachedToWindow()) {
            Editable editableText = editText.getEditableText();
            int selectionStart = Selection.getSelectionStart(editableText);
            int selectionEnd = Selection.getSelectionEnd(editableText);
            androidx.emoji2.text.f.c().p(editableText);
            d.b(editableText, selectionStart, selectionEnd);
        }
    }

    private boolean d() {
        return (this.f10533g && (this.f10529c || androidx.emoji2.text.f.i())) ? false : true;
    }

    public void c(boolean z3) {
        if (this.f10533g != z3) {
            if (this.f10530d != null) {
                androidx.emoji2.text.f.c().u(this.f10530d);
            }
            this.f10533g = z3;
            if (z3) {
                b(this.f10528b, androidx.emoji2.text.f.c().e());
            }
        }
    }

    @Override // android.text.TextWatcher
    public void onTextChanged(CharSequence charSequence, int i3, int i4, int i5) {
        if (this.f10528b.isInEditMode() || d() || i4 > i5 || !(charSequence instanceof Spannable)) {
            return;
        }
        int iE = androidx.emoji2.text.f.c().e();
        if (iE != 0) {
            if (iE == 1) {
                androidx.emoji2.text.f.c().s((Spannable) charSequence, i3, i3 + i5, this.f10531e, this.f10532f);
                return;
            } else if (iE != 3) {
                return;
            }
        }
        androidx.emoji2.text.f.c().t(a());
    }

    @Override // android.text.TextWatcher
    public void afterTextChanged(Editable editable) {
    }

    @Override // android.text.TextWatcher
    public void beforeTextChanged(CharSequence charSequence, int i3, int i4, int i5) {
    }
}
