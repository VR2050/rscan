package com.chad.library.adapter.base.dragswipe;

import android.graphics.Canvas;
import android.view.View;
import androidx.annotation.NonNull;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.R$id;
import java.util.Collections;
import java.util.Objects;
import kotlin.jvm.internal.Intrinsics;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1305e;
import p005b.p067b.p068a.p069a.p070a.p078m.C1316d;

/* loaded from: classes.dex */
public class DragAndSwipeCallback extends ItemTouchHelper.Callback {

    /* renamed from: a */
    public C1316d f8888a;

    /* renamed from: b */
    public float f8889b = 0.1f;

    /* renamed from: c */
    public float f8890c = 0.7f;

    /* renamed from: d */
    public int f8891d = 15;

    /* renamed from: e */
    public int f8892e = 32;

    public DragAndSwipeCallback(C1316d c1316d) {
        this.f8888a = c1316d;
    }

    /* renamed from: a */
    public final boolean m3910a(@NonNull RecyclerView.ViewHolder viewHolder) {
        int itemViewType = viewHolder.getItemViewType();
        return itemViewType == 268435729 || itemViewType == 268436002 || itemViewType == 268436275 || itemViewType == 268436821;
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public void clearView(@NonNull RecyclerView recyclerView, @NonNull RecyclerView.ViewHolder viewHolder) {
        super.clearView(recyclerView, viewHolder);
        if (m3910a(viewHolder)) {
            return;
        }
        View view = viewHolder.itemView;
        int i2 = R$id.BaseQuickAdapter_dragging_support;
        if (view.getTag(i2) != null && ((Boolean) viewHolder.itemView.getTag(i2)).booleanValue()) {
            C1316d c1316d = this.f8888a;
            if (c1316d != null) {
                Objects.requireNonNull(c1316d);
                Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
                InterfaceC1305e interfaceC1305e = c1316d.f1048f;
                if (interfaceC1305e != null) {
                    interfaceC1305e.m312a(viewHolder, c1316d.m322a(viewHolder));
                }
            }
            viewHolder.itemView.setTag(i2, Boolean.FALSE);
        }
        View view2 = viewHolder.itemView;
        int i3 = R$id.BaseQuickAdapter_swiping_support;
        if (view2.getTag(i3) == null || !((Boolean) viewHolder.itemView.getTag(i3)).booleanValue()) {
            return;
        }
        C1316d c1316d2 = this.f8888a;
        if (c1316d2 != null) {
            Objects.requireNonNull(c1316d2);
            Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
        }
        viewHolder.itemView.setTag(i3, Boolean.FALSE);
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public float getMoveThreshold(@NonNull RecyclerView.ViewHolder viewHolder) {
        return this.f8889b;
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public int getMovementFlags(@NonNull RecyclerView recyclerView, @NonNull RecyclerView.ViewHolder viewHolder) {
        return m3910a(viewHolder) ? ItemTouchHelper.Callback.makeMovementFlags(0, 0) : ItemTouchHelper.Callback.makeMovementFlags(this.f8891d, this.f8892e);
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public float getSwipeThreshold(@NonNull RecyclerView.ViewHolder viewHolder) {
        return this.f8890c;
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public boolean isItemViewSwipeEnabled() {
        C1316d c1316d = this.f8888a;
        if (c1316d != null) {
            Objects.requireNonNull(c1316d);
        }
        return false;
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public boolean isLongPressDragEnabled() {
        C1316d c1316d = this.f8888a;
        if (c1316d != null) {
            Objects.requireNonNull(c1316d);
        }
        return false;
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public void onChildDrawOver(@NonNull Canvas canvas, @NonNull RecyclerView recyclerView, @NonNull RecyclerView.ViewHolder viewHolder, float f2, float f3, int i2, boolean z) {
        super.onChildDrawOver(canvas, recyclerView, viewHolder, f2, f3, i2, z);
        if (i2 != 1 || m3910a(viewHolder)) {
            return;
        }
        View view = viewHolder.itemView;
        canvas.save();
        if (f2 > 0.0f) {
            canvas.clipRect(view.getLeft(), view.getTop(), view.getLeft() + f2, view.getBottom());
            canvas.translate(view.getLeft(), view.getTop());
        } else {
            canvas.clipRect(view.getRight() + f2, view.getTop(), view.getRight(), view.getBottom());
            canvas.translate(view.getRight() + f2, view.getTop());
        }
        C1316d c1316d = this.f8888a;
        canvas.restore();
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public boolean onMove(@NonNull RecyclerView recyclerView, @NonNull RecyclerView.ViewHolder viewHolder, @NonNull RecyclerView.ViewHolder viewHolder2) {
        return viewHolder.getItemViewType() == viewHolder2.getItemViewType();
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public void onMoved(@NonNull RecyclerView recyclerView, @NonNull RecyclerView.ViewHolder source, int i2, @NonNull RecyclerView.ViewHolder target, int i3, int i4, int i5) {
        super.onMoved(recyclerView, source, i2, target, i3, i4, i5);
        C1316d c1316d = this.f8888a;
        if (c1316d != null) {
            Intrinsics.checkNotNullParameter(source, "source");
            Intrinsics.checkNotNullParameter(target, "target");
            int m322a = c1316d.m322a(source);
            int m322a2 = c1316d.m322a(target);
            if (c1316d.m323b(m322a) && c1316d.m323b(m322a2)) {
                if (m322a >= m322a2) {
                    int i6 = m322a2 + 1;
                    if (i6 <= m322a) {
                        int i7 = m322a;
                        while (true) {
                            int i8 = i7 - 1;
                            Collections.swap(c1316d.f1043a.getData(), i7, i8);
                            if (i7 == i6) {
                                break;
                            } else {
                                i7 = i8;
                            }
                        }
                    }
                } else if (m322a < m322a2) {
                    int i9 = m322a;
                    while (true) {
                        int i10 = i9 + 1;
                        Collections.swap(c1316d.f1043a.getData(), i9, i10);
                        if (i10 >= m322a2) {
                            break;
                        } else {
                            i9 = i10;
                        }
                    }
                }
                c1316d.f1043a.notifyItemMoved(source.getAdapterPosition(), target.getAdapterPosition());
            }
            InterfaceC1305e interfaceC1305e = c1316d.f1048f;
            if (interfaceC1305e == null) {
                return;
            }
            interfaceC1305e.m313b(source, m322a, target, m322a2);
        }
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public void onSelectedChanged(RecyclerView.ViewHolder viewHolder, int i2) {
        if (i2 == 2 && !m3910a(viewHolder)) {
            C1316d c1316d = this.f8888a;
            if (c1316d != null) {
                Objects.requireNonNull(c1316d);
                Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
                InterfaceC1305e interfaceC1305e = c1316d.f1048f;
                if (interfaceC1305e != null) {
                    interfaceC1305e.m314c(viewHolder, c1316d.m322a(viewHolder));
                }
            }
            viewHolder.itemView.setTag(R$id.BaseQuickAdapter_dragging_support, Boolean.TRUE);
        } else if (i2 == 1 && !m3910a(viewHolder)) {
            C1316d c1316d2 = this.f8888a;
            if (c1316d2 != null) {
                Objects.requireNonNull(c1316d2);
                Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
            }
            viewHolder.itemView.setTag(R$id.BaseQuickAdapter_swiping_support, Boolean.TRUE);
        }
        super.onSelectedChanged(viewHolder, i2);
    }

    @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
    public void onSwiped(@NonNull RecyclerView.ViewHolder viewHolder, int i2) {
        C1316d c1316d;
        if (m3910a(viewHolder) || (c1316d = this.f8888a) == null) {
            return;
        }
        Objects.requireNonNull(c1316d);
        Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
        int m322a = c1316d.m322a(viewHolder);
        if (c1316d.m323b(m322a)) {
            c1316d.f1043a.getData().remove(m322a);
            c1316d.f1043a.notifyItemRemoved(viewHolder.getAdapterPosition());
        }
    }
}
