package com.drake.brv.listener;

import android.graphics.Canvas;
import android.view.View;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.recyclerview.widget.RecyclerView;
import com.drake.brv.BindingAdapter;
import com.drake.brv.item.ItemDrag;
import com.drake.brv.item.ItemSwipe;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.TypeIntrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5310d1 = {"\u0000J\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0007\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\b\b\u0016\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\u0018\u0010\t\u001a\u00020\n2\u0006\u0010\u000b\u001a\u00020\f2\u0006\u0010\r\u001a\u00020\u000eH\u0016J\u0018\u0010\u000f\u001a\u00020\u00042\u0006\u0010\u000b\u001a\u00020\f2\u0006\u0010\r\u001a\u00020\u000eH\u0016J\u0010\u0010\u0010\u001a\u00020\u00112\u0006\u0010\r\u001a\u00020\u000eH\u0016J@\u0010\u0012\u001a\u00020\n2\u0006\u0010\u0013\u001a\u00020\u00142\u0006\u0010\u000b\u001a\u00020\f2\u0006\u0010\r\u001a\u00020\u000e2\u0006\u0010\u0015\u001a\u00020\u00112\u0006\u0010\u0016\u001a\u00020\u00112\u0006\u0010\u0017\u001a\u00020\u00042\u0006\u0010\u0018\u001a\u00020\u0019H\u0016J \u0010\u001a\u001a\u00020\n2\n\u0010\u001b\u001a\u00060\u0006R\u00020\u00072\n\u0010\u001c\u001a\u00060\u0006R\u00020\u0007H\u0016J \u0010\u001d\u001a\u00020\u00192\u0006\u0010\u000b\u001a\u00020\f2\u0006\u0010\u001b\u001a\u00020\u000e2\u0006\u0010\u001c\u001a\u00020\u000eH\u0016J\u001a\u0010\u001e\u001a\u00020\n2\b\u0010\r\u001a\u0004\u0018\u00010\u000e2\u0006\u0010\u0017\u001a\u00020\u0004H\u0016J\u0018\u0010\u001f\u001a\u00020\n2\u0006\u0010\r\u001a\u00020\u000e2\u0006\u0010 \u001a\u00020\u0004H\u0016R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082\u000e¢\u0006\u0002\n\u0000R\u0014\u0010\u0005\u001a\b\u0018\u00010\u0006R\u00020\u0007X\u0082\u000e¢\u0006\u0002\n\u0000R\u0014\u0010\b\u001a\b\u0018\u00010\u0006R\u00020\u0007X\u0082\u000e¢\u0006\u0002\n\u0000¨\u0006!"}, m5311d2 = {"Lcom/drake/brv/listener/DefaultItemTouchCallback;", "Landroidx/recyclerview/widget/ItemTouchHelper$Callback;", "()V", "lastActionState", "", "sourceViewHolder", "Lcom/drake/brv/BindingAdapter$BindingViewHolder;", "Lcom/drake/brv/BindingAdapter;", "targetViewHolder", "clearView", "", "recyclerView", "Landroidx/recyclerview/widget/RecyclerView;", "viewHolder", "Landroidx/recyclerview/widget/RecyclerView$ViewHolder;", "getMovementFlags", "getSwipeThreshold", "", "onChildDraw", "c", "Landroid/graphics/Canvas;", "dX", "dY", "actionState", "isCurrentlyActive", "", "onDrag", "source", "target", "onMove", "onSelectedChanged", "onSwiped", "direction", "brv_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* loaded from: classes.dex */
public class DefaultItemTouchCallback extends ItemTouchHelper.Callback {

    /* renamed from: a */
    public int f9010a;

    /* renamed from: b */
    @Nullable
    public BindingAdapter.BindingViewHolder f9011b;

    /* renamed from: c */
    @Nullable
    public BindingAdapter.BindingViewHolder f9012c;

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public void clearView(@NotNull RecyclerView recyclerView, @NotNull RecyclerView.ViewHolder viewHolder) {
        Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
        Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
        super.clearView(recyclerView, viewHolder);
        View findViewWithTag = viewHolder.itemView.findViewWithTag("swipe");
        if (findViewWithTag != null) {
            findViewWithTag.setTranslationX(0.0f);
        }
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public int getMovementFlags(@NotNull RecyclerView recyclerView, @NotNull RecyclerView.ViewHolder viewHolder) {
        int i2;
        Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
        Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
        int i3 = 0;
        if (viewHolder instanceof BindingAdapter.BindingViewHolder) {
            Object m3942b = ((BindingAdapter.BindingViewHolder) viewHolder).m3942b();
            int m1195a = m3942b instanceof ItemDrag ? ((ItemDrag) m3942b).m1195a() : 0;
            if (m3942b instanceof ItemSwipe) {
                i2 = ((ItemSwipe) m3942b).m1202a();
                i3 = m1195a;
                return ItemTouchHelper.Callback.makeMovementFlags(i3, i2);
            }
            i3 = m1195a;
        }
        i2 = 0;
        return ItemTouchHelper.Callback.makeMovementFlags(i3, i2);
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public float getSwipeThreshold(@NotNull RecyclerView.ViewHolder viewHolder) {
        Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
        return 1.0f;
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public void onChildDraw(@NotNull Canvas c2, @NotNull RecyclerView recyclerView, @NotNull RecyclerView.ViewHolder viewHolder, float dX, float dY, int actionState, boolean isCurrentlyActive) {
        Intrinsics.checkNotNullParameter(c2, "c");
        Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
        Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
        if (actionState != 1) {
            super.onChildDraw(c2, recyclerView, viewHolder, dX, dY, actionState, isCurrentlyActive);
            return;
        }
        View findViewWithTag = viewHolder.itemView.findViewWithTag("swipe");
        if (findViewWithTag != null) {
            findViewWithTag.setTranslationX(dX);
        } else {
            super.onChildDraw(c2, recyclerView, viewHolder, dX, dY, actionState, isCurrentlyActive);
        }
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public boolean onMove(@NotNull RecyclerView recyclerView, @NotNull RecyclerView.ViewHolder source, @NotNull RecyclerView.ViewHolder target) {
        Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(target, "target");
        BindingAdapter m4793Z = C4195m.m4793Z(recyclerView);
        int childLayoutPosition = recyclerView.getChildLayoutPosition(source.itemView);
        int childLayoutPosition2 = recyclerView.getChildLayoutPosition(target.itemView);
        List<Object> list = m4793Z.f8920v;
        if (!TypeIntrinsics.isMutableList(list)) {
            list = null;
        }
        if (list != null && (source instanceof BindingAdapter.BindingViewHolder) && (target instanceof BindingAdapter.BindingViewHolder)) {
            if ((m4793Z.m3933j(childLayoutPosition2) || m4793Z.m3932i(childLayoutPosition2)) ? false : true) {
                int m3929f = childLayoutPosition - m4793Z.m3929f();
                int m3929f2 = childLayoutPosition2 - m4793Z.m3929f();
                Object obj = list.get(m3929f);
                list.remove(m3929f);
                list.add(m3929f2, obj);
                m4793Z.notifyItemMoved(childLayoutPosition, childLayoutPosition2);
                this.f9011b = (BindingAdapter.BindingViewHolder) source;
                this.f9012c = (BindingAdapter.BindingViewHolder) target;
                return true;
            }
        }
        return false;
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public void onSelectedChanged(@Nullable RecyclerView.ViewHolder viewHolder, int actionState) {
        BindingAdapter.BindingViewHolder source;
        if (actionState != 0) {
            this.f9010a = actionState;
            return;
        }
        if (this.f9010a != 2 || (source = this.f9011b) == null || this.f9012c == null) {
            return;
        }
        Intrinsics.checkNotNull(source);
        BindingAdapter.BindingViewHolder target = this.f9012c;
        Intrinsics.checkNotNull(target);
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(target, "target");
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public void onSwiped(@NotNull RecyclerView.ViewHolder viewHolder, int direction) {
        Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
        RecyclerView.Adapter<? extends RecyclerView.ViewHolder> bindingAdapter = viewHolder.getBindingAdapter();
        BindingAdapter bindingAdapter2 = bindingAdapter instanceof BindingAdapter ? (BindingAdapter) bindingAdapter : null;
        if (bindingAdapter2 == null) {
            return;
        }
        int layoutPosition = viewHolder.getLayoutPosition();
        int m3929f = bindingAdapter2.m3929f();
        if (layoutPosition >= m3929f) {
            List<Object> list = bindingAdapter2.f8920v;
            List<Object> list2 = TypeIntrinsics.isMutableList(list) ? list : null;
            if (list2 != null) {
                list2.remove(layoutPosition - m3929f);
                bindingAdapter2.notifyItemRemoved(layoutPosition);
                return;
            }
            return;
        }
        Integer valueOf = Integer.valueOf(layoutPosition);
        if (bindingAdapter2.m3929f() == 0 || !bindingAdapter2.f8918t.contains(valueOf)) {
            return;
        }
        int indexOf = bindingAdapter2.f8918t.indexOf(valueOf);
        TypeIntrinsics.asMutableList(bindingAdapter2.f8918t).remove(valueOf);
        bindingAdapter2.notifyItemRemoved(indexOf);
    }
}
