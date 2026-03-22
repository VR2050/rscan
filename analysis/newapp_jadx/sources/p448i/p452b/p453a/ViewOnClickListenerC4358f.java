package p448i.p452b.p453a;

import android.view.View;
import androidx.recyclerview.widget.RecyclerView;
import me.jingbin.library.ByRecyclerView;

/* renamed from: i.b.a.f */
/* loaded from: classes3.dex */
public class ViewOnClickListenerC4358f implements View.OnClickListener {

    /* renamed from: c */
    public final /* synthetic */ RecyclerView.ViewHolder f11253c;

    /* renamed from: e */
    public final /* synthetic */ ByRecyclerView f11254e;

    public ViewOnClickListenerC4358f(ByRecyclerView byRecyclerView, RecyclerView.ViewHolder viewHolder) {
        this.f11254e = byRecyclerView;
        this.f11253c = viewHolder;
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View view) {
        this.f11254e.f12640B.m5626a(view, this.f11253c.getLayoutPosition() - this.f11254e.getCustomTopItemViewCount());
    }
}
