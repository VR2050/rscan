package com.jbzd.media.movecartoons.decoration;

import android.graphics.Canvas;
import android.graphics.Rect;
import android.view.View;
import androidx.recyclerview.widget.RecyclerView;
import com.drake.brv.BindingAdapter;
import com.jbzd.media.movecartoons.bean.response.ChatMsgBean;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p009a.C0847g0;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\u0018\u00002\u00020\u0001J/\u0010\u000b\u001a\u00020\n2\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0007\u001a\u00020\u00062\u0006\u0010\t\u001a\u00020\bH\u0016¢\u0006\u0004\b\u000b\u0010\fJ'\u0010\u000f\u001a\u00020\n2\u0006\u0010\u000e\u001a\u00020\r2\u0006\u0010\u0007\u001a\u00020\u00062\u0006\u0010\t\u001a\u00020\bH\u0016¢\u0006\u0004\b\u000f\u0010\u0010¨\u0006\u0011"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/decoration/TimeDecoration;", "Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "Landroid/graphics/Rect;", "outRect", "Landroid/view/View;", "view", "Landroidx/recyclerview/widget/RecyclerView;", "parent", "Landroidx/recyclerview/widget/RecyclerView$State;", "state", "", "getItemOffsets", "(Landroid/graphics/Rect;Landroid/view/View;Landroidx/recyclerview/widget/RecyclerView;Landroidx/recyclerview/widget/RecyclerView$State;)V", "Landroid/graphics/Canvas;", "c", "onDraw", "(Landroid/graphics/Canvas;Landroidx/recyclerview/widget/RecyclerView;Landroidx/recyclerview/widget/RecyclerView$State;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class TimeDecoration extends RecyclerView.ItemDecoration {
    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void getItemOffsets(@NotNull Rect outRect, @NotNull View view, @NotNull RecyclerView parent, @NotNull RecyclerView.State state) {
        int childAdapterPosition;
        View findViewByPosition;
        RecyclerView.ViewHolder findContainingViewHolder;
        Intrinsics.checkNotNullParameter(outRect, "outRect");
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(parent, "parent");
        Intrinsics.checkNotNullParameter(state, "state");
        super.getItemOffsets(outRect, view, parent, state);
        RecyclerView.LayoutManager layoutManager = parent.getLayoutManager();
        if (layoutManager == null || (childAdapterPosition = parent.getChildAdapterPosition(view)) == -1) {
            return;
        }
        RecyclerView.ViewHolder findContainingViewHolder2 = parent.findContainingViewHolder(view);
        Objects.requireNonNull(findContainingViewHolder2, "null cannot be cast to non-null type com.drake.brv.BindingAdapter.BindingViewHolder");
        Object m3942b = ((BindingAdapter.BindingViewHolder) findContainingViewHolder2).m3942b();
        if (!(m3942b instanceof Object)) {
            m3942b = null;
        }
        if (m3942b == null || childAdapterPosition == 0 || (findViewByPosition = layoutManager.findViewByPosition(childAdapterPosition - 1)) == null || (findContainingViewHolder = parent.findContainingViewHolder(findViewByPosition)) == null || !(findContainingViewHolder instanceof BindingAdapter.BindingViewHolder)) {
            return;
        }
        Object m3942b2 = ((BindingAdapter.BindingViewHolder) findContainingViewHolder).m3942b();
        Object obj = m3942b2 instanceof Object ? m3942b2 : null;
        if (obj == null) {
            return;
        }
        if (!(m3942b instanceof ChatMsgBean.MessageBean)) {
            outRect.set(0, 0, 0, 0);
            return;
        }
        if (obj instanceof ChatMsgBean.MessageBean) {
            C0847g0 c0847g0 = C0847g0.f249a;
            String str = ((ChatMsgBean.MessageBean) m3942b).time_label;
            Intrinsics.checkNotNullExpressionValue(str, "model.time_label");
            String str2 = ((ChatMsgBean.MessageBean) obj).time_label;
            Intrinsics.checkNotNullExpressionValue(str2, "preModel.time_label");
            if (C0847g0.m184a(str, str2)) {
                outRect.set(0, 0, 0, 0);
                return;
            }
        }
        outRect.set(0, (int) (0 + 0.0f), 0, 0);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.ItemDecoration
    public void onDraw(@NotNull Canvas c2, @NotNull RecyclerView parent, @NotNull RecyclerView.State state) {
        Object m3942b;
        RecyclerView.ViewHolder childViewHolder;
        Intrinsics.checkNotNullParameter(c2, "c");
        Intrinsics.checkNotNullParameter(parent, "parent");
        Intrinsics.checkNotNullParameter(state, "state");
        super.onDraw(c2, parent, state);
        int childCount = parent.getChildCount();
        c2.save();
        if (childCount > 0) {
            int i2 = 0;
            while (true) {
                int i3 = i2 + 1;
                RecyclerView.ViewHolder childViewHolder2 = parent.getChildViewHolder(parent.getChildAt(i2));
                Objects.requireNonNull(childViewHolder2, "null cannot be cast to non-null type com.drake.brv.BindingAdapter.BindingViewHolder");
                m3942b = ((BindingAdapter.BindingViewHolder) childViewHolder2).m3942b();
                if (!(m3942b instanceof Object)) {
                    m3942b = null;
                }
                if (m3942b == null) {
                    return;
                }
                if ((m3942b instanceof ChatMsgBean.MessageBean) && i2 > 0 && (childViewHolder = parent.getChildViewHolder(parent.getChildAt(i2 - 1))) != null && (childViewHolder instanceof BindingAdapter.BindingViewHolder)) {
                    Object m3942b2 = ((BindingAdapter.BindingViewHolder) childViewHolder).m3942b();
                    if (!(m3942b2 instanceof Object)) {
                        m3942b2 = null;
                    }
                    if (m3942b2 == null || !(m3942b2 instanceof ChatMsgBean.MessageBean)) {
                        break;
                    }
                    C0847g0 c0847g0 = C0847g0.f249a;
                    String str = ((ChatMsgBean.MessageBean) m3942b).time_label;
                    Intrinsics.checkNotNullExpressionValue(str, "model.time_label");
                    String str2 = ((ChatMsgBean.MessageBean) m3942b2).time_label;
                    Intrinsics.checkNotNullExpressionValue(str2, "preModel.time_label");
                    if (!C0847g0.m184a(str, str2)) {
                        break;
                    }
                }
                if (i3 >= childCount) {
                    break;
                } else {
                    i2 = i3;
                }
            }
            Intrinsics.stringPlus("无时间戳，暂时无法比较", ((ChatMsgBean.MessageBean) m3942b).time_label);
            throw null;
        }
        c2.restore();
    }
}
