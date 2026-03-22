package p005b.p067b.p068a.p069a.p070a.p078m;

import android.view.View;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.dragswipe.DragAndSwipeCallback;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1305e;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1307g;

/* renamed from: b.b.a.a.a.m.d */
/* loaded from: classes.dex */
public class C1316d {

    /* renamed from: a */
    @NotNull
    public final BaseQuickAdapter<?, ?> f1043a;

    /* renamed from: b */
    public ItemTouchHelper f1044b;

    /* renamed from: c */
    public DragAndSwipeCallback f1045c;

    /* renamed from: d */
    @Nullable
    public View.OnTouchListener f1046d;

    /* renamed from: e */
    @Nullable
    public View.OnLongClickListener f1047e;

    /* renamed from: f */
    @Nullable
    public InterfaceC1305e f1048f;

    /* renamed from: g */
    @Nullable
    public InterfaceC1307g f1049g;

    /* renamed from: h */
    public boolean f1050h;

    public C1316d(@NotNull BaseQuickAdapter<?, ?> baseQuickAdapter) {
        Intrinsics.checkNotNullParameter(baseQuickAdapter, "baseQuickAdapter");
        this.f1043a = baseQuickAdapter;
        DragAndSwipeCallback dragAndSwipeCallback = new DragAndSwipeCallback(this);
        Intrinsics.checkNotNullParameter(dragAndSwipeCallback, "<set-?>");
        this.f1045c = dragAndSwipeCallback;
        ItemTouchHelper itemTouchHelper = new ItemTouchHelper(dragAndSwipeCallback);
        Intrinsics.checkNotNullParameter(itemTouchHelper, "<set-?>");
        this.f1044b = itemTouchHelper;
        this.f1050h = true;
    }

    /* renamed from: a */
    public final int m322a(@NotNull RecyclerView.ViewHolder viewHolder) {
        Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
        return viewHolder.getAdapterPosition() - this.f1043a.getHeaderLayoutCount();
    }

    /* renamed from: b */
    public final boolean m323b(int i2) {
        return i2 >= 0 && i2 < this.f1043a.getData().size();
    }

    public final void setMOnItemDragListener(@Nullable InterfaceC1305e interfaceC1305e) {
        this.f1048f = interfaceC1305e;
    }

    public final void setMOnItemSwipeListener(@Nullable InterfaceC1307g interfaceC1307g) {
        this.f1049g = interfaceC1307g;
    }

    public final void setMOnToggleViewLongClickListener(@Nullable View.OnLongClickListener onLongClickListener) {
        this.f1047e = onLongClickListener;
    }

    public final void setMOnToggleViewTouchListener(@Nullable View.OnTouchListener onTouchListener) {
        this.f1046d = onTouchListener;
    }

    public void setOnItemDragListener(@Nullable InterfaceC1305e interfaceC1305e) {
        this.f1048f = interfaceC1305e;
    }

    public void setOnItemSwipeListener(@Nullable InterfaceC1307g interfaceC1307g) {
        this.f1049g = interfaceC1307g;
    }
}
