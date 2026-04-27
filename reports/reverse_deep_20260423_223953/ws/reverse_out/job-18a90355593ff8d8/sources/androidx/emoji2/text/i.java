package androidx.emoji2.text;

import android.text.Editable;
import android.text.Selection;
import android.text.Spannable;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.TextUtils;
import android.text.method.MetaKeyKeyListener;
import android.view.KeyEvent;
import android.view.inputmethod.InputConnection;
import androidx.emoji2.text.f;
import androidx.emoji2.text.n;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Set;

/* JADX INFO: loaded from: classes.dex */
final class i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final f.j f4639a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final n f4640b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private f.e f4641c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final boolean f4642d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final int[] f4643e;

    private static final class a {
        static int a(CharSequence charSequence, int i3, int i4) {
            int length = charSequence.length();
            if (i3 < 0 || length < i3 || i4 < 0) {
                return -1;
            }
            while (true) {
                boolean z3 = false;
                while (i4 != 0) {
                    i3--;
                    if (i3 < 0) {
                        return z3 ? -1 : 0;
                    }
                    char cCharAt = charSequence.charAt(i3);
                    if (z3) {
                        if (!Character.isHighSurrogate(cCharAt)) {
                            return -1;
                        }
                        i4--;
                    } else if (!Character.isSurrogate(cCharAt)) {
                        i4--;
                    } else {
                        if (Character.isHighSurrogate(cCharAt)) {
                            return -1;
                        }
                        z3 = true;
                    }
                }
                return i3;
            }
        }

        static int b(CharSequence charSequence, int i3, int i4) {
            int length = charSequence.length();
            if (i3 < 0 || length < i3 || i4 < 0) {
                return -1;
            }
            while (true) {
                boolean z3 = false;
                while (i4 != 0) {
                    if (i3 >= length) {
                        if (z3) {
                            return -1;
                        }
                        return length;
                    }
                    char cCharAt = charSequence.charAt(i3);
                    if (z3) {
                        if (!Character.isLowSurrogate(cCharAt)) {
                            return -1;
                        }
                        i4--;
                        i3++;
                    } else if (!Character.isSurrogate(cCharAt)) {
                        i4--;
                        i3++;
                    } else {
                        if (Character.isLowSurrogate(cCharAt)) {
                            return -1;
                        }
                        i3++;
                        z3 = true;
                    }
                }
                return i3;
            }
        }
    }

    private static class b implements c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public r f4644a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final f.j f4645b;

        b(r rVar, f.j jVar) {
            this.f4644a = rVar;
            this.f4645b = jVar;
        }

        @Override // androidx.emoji2.text.i.c
        public boolean b(CharSequence charSequence, int i3, int i4, p pVar) {
            if (pVar.k()) {
                return true;
            }
            if (this.f4644a == null) {
                this.f4644a = new r(charSequence instanceof Spannable ? (Spannable) charSequence : new SpannableString(charSequence));
            }
            this.f4644a.setSpan(this.f4645b.a(pVar), i3, i4, 33);
            return true;
        }

        @Override // androidx.emoji2.text.i.c
        /* JADX INFO: renamed from: c, reason: merged with bridge method [inline-methods] */
        public r a() {
            return this.f4644a;
        }
    }

    private interface c {
        Object a();

        boolean b(CharSequence charSequence, int i3, int i4, p pVar);
    }

    private static class d implements c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final String f4646a;

        d(String str) {
            this.f4646a = str;
        }

        @Override // androidx.emoji2.text.i.c
        public boolean b(CharSequence charSequence, int i3, int i4, p pVar) {
            if (!TextUtils.equals(charSequence.subSequence(i3, i4), this.f4646a)) {
                return true;
            }
            pVar.l(true);
            return false;
        }

        @Override // androidx.emoji2.text.i.c
        /* JADX INFO: renamed from: c, reason: merged with bridge method [inline-methods] */
        public d a() {
            return this;
        }
    }

    static final class e {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private int f4647a = 1;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final n.a f4648b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private n.a f4649c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private n.a f4650d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private int f4651e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private int f4652f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private final boolean f4653g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private final int[] f4654h;

        e(n.a aVar, boolean z3, int[] iArr) {
            this.f4648b = aVar;
            this.f4649c = aVar;
            this.f4653g = z3;
            this.f4654h = iArr;
        }

        private static boolean d(int i3) {
            return i3 == 65039;
        }

        private static boolean f(int i3) {
            return i3 == 65038;
        }

        private int g() {
            this.f4647a = 1;
            this.f4649c = this.f4648b;
            this.f4652f = 0;
            return 1;
        }

        private boolean h() {
            if (this.f4649c.b().j() || d(this.f4651e)) {
                return true;
            }
            if (this.f4653g) {
                if (this.f4654h == null) {
                    return true;
                }
                if (Arrays.binarySearch(this.f4654h, this.f4649c.b().b(0)) < 0) {
                    return true;
                }
            }
            return false;
        }

        int a(int i3) {
            n.a aVarA = this.f4649c.a(i3);
            int iG = 2;
            if (this.f4647a != 2) {
                if (aVarA == null) {
                    iG = g();
                } else {
                    this.f4647a = 2;
                    this.f4649c = aVarA;
                    this.f4652f = 1;
                }
            } else if (aVarA != null) {
                this.f4649c = aVarA;
                this.f4652f++;
            } else if (f(i3)) {
                iG = g();
            } else if (!d(i3)) {
                if (this.f4649c.b() != null) {
                    iG = 3;
                    if (this.f4652f != 1 || h()) {
                        this.f4650d = this.f4649c;
                        g();
                    } else {
                        iG = g();
                    }
                } else {
                    iG = g();
                }
            }
            this.f4651e = i3;
            return iG;
        }

        p b() {
            return this.f4649c.b();
        }

        p c() {
            return this.f4650d.b();
        }

        boolean e() {
            return this.f4647a == 2 && this.f4649c.b() != null && (this.f4652f > 1 || h());
        }
    }

    i(n nVar, f.j jVar, f.e eVar, boolean z3, int[] iArr, Set set) {
        this.f4639a = jVar;
        this.f4640b = nVar;
        this.f4641c = eVar;
        this.f4642d = z3;
        this.f4643e = iArr;
        g(set);
    }

    private static boolean a(Editable editable, KeyEvent keyEvent, boolean z3) {
        j[] jVarArr;
        if (f(keyEvent)) {
            return false;
        }
        int selectionStart = Selection.getSelectionStart(editable);
        int selectionEnd = Selection.getSelectionEnd(editable);
        if (!e(selectionStart, selectionEnd) && (jVarArr = (j[]) editable.getSpans(selectionStart, selectionEnd, j.class)) != null && jVarArr.length > 0) {
            for (j jVar : jVarArr) {
                int spanStart = editable.getSpanStart(jVar);
                int spanEnd = editable.getSpanEnd(jVar);
                if ((z3 && spanStart == selectionStart) || ((!z3 && spanEnd == selectionStart) || (selectionStart > spanStart && selectionStart < spanEnd))) {
                    editable.delete(spanStart, spanEnd);
                    return true;
                }
            }
        }
        return false;
    }

    static boolean b(InputConnection inputConnection, Editable editable, int i3, int i4, boolean z3) {
        int iMax;
        int iMin;
        if (editable != null && inputConnection != null && i3 >= 0 && i4 >= 0) {
            int selectionStart = Selection.getSelectionStart(editable);
            int selectionEnd = Selection.getSelectionEnd(editable);
            if (e(selectionStart, selectionEnd)) {
                return false;
            }
            if (z3) {
                iMax = a.a(editable, selectionStart, Math.max(i3, 0));
                iMin = a.b(editable, selectionEnd, Math.max(i4, 0));
                if (iMax == -1 || iMin == -1) {
                    return false;
                }
            } else {
                iMax = Math.max(selectionStart - i3, 0);
                iMin = Math.min(selectionEnd + i4, editable.length());
            }
            j[] jVarArr = (j[]) editable.getSpans(iMax, iMin, j.class);
            if (jVarArr != null && jVarArr.length > 0) {
                for (j jVar : jVarArr) {
                    int spanStart = editable.getSpanStart(jVar);
                    int spanEnd = editable.getSpanEnd(jVar);
                    iMax = Math.min(spanStart, iMax);
                    iMin = Math.max(spanEnd, iMin);
                }
                int iMax2 = Math.max(iMax, 0);
                int iMin2 = Math.min(iMin, editable.length());
                inputConnection.beginBatchEdit();
                editable.delete(iMax2, iMin2);
                inputConnection.endBatchEdit();
                return true;
            }
        }
        return false;
    }

    static boolean c(Editable editable, int i3, KeyEvent keyEvent) {
        if (!(i3 != 67 ? i3 != 112 ? false : a(editable, keyEvent, true) : a(editable, keyEvent, false))) {
            return false;
        }
        MetaKeyKeyListener.adjustMetaAfterKeypress(editable);
        return true;
    }

    private boolean d(CharSequence charSequence, int i3, int i4, p pVar) {
        if (pVar.d() == 0) {
            pVar.m(this.f4641c.a(charSequence, i3, i4, pVar.h()));
        }
        return pVar.d() == 2;
    }

    private static boolean e(int i3, int i4) {
        return i3 == -1 || i4 == -1 || i3 != i4;
    }

    private static boolean f(KeyEvent keyEvent) {
        return !KeyEvent.metaStateHasNoModifiers(keyEvent.getMetaState());
    }

    private void g(Set set) {
        if (set.isEmpty()) {
            return;
        }
        Iterator it = set.iterator();
        while (it.hasNext()) {
            int[] iArr = (int[]) it.next();
            String str = new String(iArr, 0, iArr.length);
            i(str, 0, str.length(), 1, true, new d(str));
        }
    }

    private Object i(CharSequence charSequence, int i3, int i4, int i5, boolean z3, c cVar) {
        int iCharCount;
        e eVar = new e(this.f4640b.f(), this.f4642d, this.f4643e);
        int i6 = 0;
        boolean zB = true;
        int iCodePointAt = Character.codePointAt(charSequence, i3);
        loop0: while (true) {
            iCharCount = i3;
            while (i3 < i4 && i6 < i5 && zB) {
                int iA = eVar.a(iCodePointAt);
                if (iA == 1) {
                    iCharCount += Character.charCount(Character.codePointAt(charSequence, iCharCount));
                    if (iCharCount < i4) {
                        iCodePointAt = Character.codePointAt(charSequence, iCharCount);
                    }
                    i3 = iCharCount;
                } else if (iA == 2) {
                    i3 += Character.charCount(iCodePointAt);
                    if (i3 < i4) {
                        iCodePointAt = Character.codePointAt(charSequence, i3);
                    }
                } else if (iA == 3) {
                    if (z3 || !d(charSequence, iCharCount, i3, eVar.c())) {
                        zB = cVar.b(charSequence, iCharCount, i3, eVar.c());
                        i6++;
                    }
                }
            }
            break loop0;
        }
        if (eVar.e() && i6 < i5 && zB && (z3 || !d(charSequence, iCharCount, i3, eVar.b()))) {
            cVar.b(charSequence, iCharCount, i3, eVar.b());
        }
        return cVar.a();
    }

    CharSequence h(CharSequence charSequence, int i3, int i4, int i5, boolean z3) {
        r rVar;
        j[] jVarArr;
        boolean z4 = charSequence instanceof o;
        if (z4) {
            ((o) charSequence).a();
        }
        if (!z4) {
            try {
                rVar = charSequence instanceof Spannable ? new r((Spannable) charSequence) : (!(charSequence instanceof Spanned) || ((Spanned) charSequence).nextSpanTransition(i3 + (-1), i4 + 1, j.class) > i4) ? null : new r(charSequence);
            } finally {
                if (z4) {
                    ((o) charSequence).d();
                }
            }
        }
        if (rVar != null && (jVarArr = (j[]) rVar.getSpans(i3, i4, j.class)) != null && jVarArr.length > 0) {
            for (j jVar : jVarArr) {
                int spanStart = rVar.getSpanStart(jVar);
                int spanEnd = rVar.getSpanEnd(jVar);
                if (spanStart != i4) {
                    rVar.removeSpan(jVar);
                }
                i3 = Math.min(spanStart, i3);
                i4 = Math.max(spanEnd, i4);
            }
        }
        int i6 = i4;
        if (i3 != i6 && i3 < charSequence.length()) {
            if (i5 != Integer.MAX_VALUE && rVar != null) {
                i5 -= ((j[]) rVar.getSpans(0, rVar.length(), j.class)).length;
            }
            r rVar2 = (r) i(charSequence, i3, i6, i5, z3, new b(rVar, this.f4639a));
            if (rVar2 == null) {
                if (z4) {
                    ((o) charSequence).d();
                }
                return charSequence;
            }
            Spannable spannableB = rVar2.b();
            if (z4) {
                ((o) charSequence).d();
            }
            return spannableB;
        }
        return charSequence;
    }
}
