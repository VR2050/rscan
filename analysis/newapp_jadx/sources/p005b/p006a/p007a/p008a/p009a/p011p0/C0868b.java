package p005b.p006a.p007a.p008a.p009a.p011p0;

import android.text.TextUtils;
import android.text.TextWatcher;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: b.a.a.a.a.p0.b */
/* loaded from: classes2.dex */
public final class C0868b implements TextWatcher {

    /* renamed from: c */
    @NotNull
    public C0867a f304c = new C0867a();

    /* renamed from: e */
    public boolean f305e;

    /* renamed from: f */
    public boolean f306f;

    @NotNull
    /* renamed from: a */
    public final String m200a(@NotNull CharSequence s) {
        String str;
        char c2;
        Intrinsics.checkNotNullParameter(s, "s");
        this.f304c.f303a.setLength(0);
        int length = s.length();
        if (length > 0) {
            str = "";
            int i2 = 0;
            c2 = 0;
            while (true) {
                int i3 = i2 + 1;
                char charAt = s.charAt(i2);
                if (('0' <= charAt && charAt <= '9') || charAt == '*' || charAt == '#' || charAt == '+') {
                    if (c2 != 0) {
                        str = this.f304c.m199a(c2);
                    }
                    c2 = charAt;
                }
                if (i3 >= length) {
                    break;
                }
                i2 = i3;
            }
        } else {
            str = "";
            c2 = 0;
        }
        if (c2 != 0) {
            str = this.f304c.m199a(c2);
        }
        int length2 = str.length() - 1;
        int i4 = 0;
        boolean z = false;
        while (i4 <= length2) {
            boolean z2 = Intrinsics.compare((int) str.charAt(!z ? i4 : length2), 32) <= 0;
            if (z) {
                if (!z2) {
                    break;
                }
                length2--;
            } else if (z2) {
                i4++;
            } else {
                z = true;
            }
        }
        String obj = str.subSequence(i4, length2 + 1).toString();
        return TextUtils.isEmpty(obj) ? "" : obj;
    }

    /* JADX WARN: Removed duplicated region for block: B:65:0x007b A[Catch: all -> 0x00f1, TryCatch #0 {, blocks: (B:4:0x0005, B:6:0x0010, B:9:0x0018, B:14:0x001c, B:18:0x0022, B:21:0x002f, B:25:0x00af, B:27:0x00b3, B:41:0x00cf, B:46:0x00ec, B:48:0x004b, B:49:0x0051, B:52:0x005b, B:71:0x0085, B:74:0x008e, B:85:0x00a7, B:87:0x00a9, B:54:0x0060, B:65:0x007b), top: B:3:0x0005, inners: #1 }] */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0080 A[LOOP:1: B:52:0x005b->B:67:0x0080, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:68:0x007f A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:85:0x00a7 A[Catch: all -> 0x00f1, TryCatch #0 {, blocks: (B:4:0x0005, B:6:0x0010, B:9:0x0018, B:14:0x001c, B:18:0x0022, B:21:0x002f, B:25:0x00af, B:27:0x00b3, B:41:0x00cf, B:46:0x00ec, B:48:0x004b, B:49:0x0051, B:52:0x005b, B:71:0x0085, B:74:0x008e, B:85:0x00a7, B:87:0x00a9, B:54:0x0060, B:65:0x007b), top: B:3:0x0005, inners: #1 }] */
    /* JADX WARN: Removed duplicated region for block: B:88:0x00a9 A[SYNTHETIC] */
    @Override // android.text.TextWatcher
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public synchronized void afterTextChanged(@org.jetbrains.annotations.NotNull android.text.Editable r18) {
        /*
            Method dump skipped, instructions count: 244
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p006a.p007a.p008a.p009a.p011p0.C0868b.afterTextChanged(android.text.Editable):void");
    }

    @Override // android.text.TextWatcher
    public void beforeTextChanged(@Nullable CharSequence charSequence, int i2, int i3, int i4) {
        if (this.f305e || this.f306f) {
        }
    }

    @Override // android.text.TextWatcher
    public void onTextChanged(@Nullable CharSequence charSequence, int i2, int i3, int i4) {
        if (this.f305e || this.f306f) {
        }
    }
}
