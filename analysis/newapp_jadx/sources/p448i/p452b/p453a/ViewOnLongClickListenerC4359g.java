package p448i.p452b.p453a;

import android.view.View;
import androidx.recyclerview.widget.RecyclerView;
import me.jingbin.library.ByRecyclerView;

/* renamed from: i.b.a.g */
/* loaded from: classes3.dex */
public class ViewOnLongClickListenerC4359g implements View.OnLongClickListener {

    /* renamed from: c */
    public final /* synthetic */ RecyclerView.ViewHolder f11255c;

    /* renamed from: e */
    public final /* synthetic */ ByRecyclerView f11256e;

    public ViewOnLongClickListenerC4359g(ByRecyclerView byRecyclerView, RecyclerView.ViewHolder viewHolder) {
        this.f11256e = byRecyclerView;
        this.f11255c = viewHolder;
    }

    @Override // android.view.View.OnLongClickListener
    public boolean onLongClick(View view) {
        return this.f11256e.f12641C.m5627a(view, this.f11255c.getLayoutPosition() - this.f11256e.getCustomTopItemViewCount());
    }
}
