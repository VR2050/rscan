package p005b.p006a.p007a.p008a.p014p.p015a;

import android.view.View;

/* renamed from: b.a.a.a.p.a.a */
/* loaded from: classes2.dex */
public final class ViewOnClickListenerC0910a implements View.OnClickListener {

    /* renamed from: c */
    public final a f367c;

    /* renamed from: e */
    public final int f368e;

    /* renamed from: b.a.a.a.p.a.a$a */
    public interface a {
        void _internalCallbackOnClick(int i2, View view);
    }

    public ViewOnClickListenerC0910a(a aVar, int i2) {
        this.f367c = aVar;
        this.f368e = i2;
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View view) {
        this.f367c._internalCallbackOnClick(this.f368e, view);
    }
}
