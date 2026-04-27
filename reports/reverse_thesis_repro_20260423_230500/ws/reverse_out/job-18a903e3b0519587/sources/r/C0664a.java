package r;

import android.os.Bundle;
import android.text.style.ClickableSpan;
import android.view.View;

/* JADX INFO: renamed from: r.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0664a extends ClickableSpan {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f9923a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final v f9924b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final int f9925c;

    public C0664a(int i3, v vVar, int i4) {
        this.f9923a = i3;
        this.f9924b = vVar;
        this.f9925c = i4;
    }

    @Override // android.text.style.ClickableSpan
    public void onClick(View view) {
        Bundle bundle = new Bundle();
        bundle.putInt("ACCESSIBILITY_CLICKABLE_SPAN_ID", this.f9923a);
        this.f9924b.f0(this.f9925c, bundle);
    }
}
