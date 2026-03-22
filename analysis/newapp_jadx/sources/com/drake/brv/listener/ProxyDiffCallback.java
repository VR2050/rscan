package com.drake.brv.listener;

import androidx.recyclerview.widget.DiffUtil;
import com.drake.brv.listener.ItemDifferCallback;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5310d1 = {"\u0000,\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010 \n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\b\n\u0002\b\u0006\b\u0000\u0018\u00002\u00020\u0001B1\u0012\u0010\u0010\u0002\u001a\f\u0012\u0006\u0012\u0004\u0018\u00010\u0004\u0018\u00010\u0003\u0012\u0010\u0010\u0005\u001a\f\u0012\u0006\u0012\u0004\u0018\u00010\u0004\u0018\u00010\u0003\u0012\u0006\u0010\u0006\u001a\u00020\u0007¢\u0006\u0002\u0010\bJ\u0018\u0010\u000b\u001a\u00020\f2\u0006\u0010\r\u001a\u00020\u000e2\u0006\u0010\u000f\u001a\u00020\u000eH\u0016J\u0018\u0010\u0010\u001a\u00020\f2\u0006\u0010\r\u001a\u00020\u000e2\u0006\u0010\u000f\u001a\u00020\u000eH\u0016J\u001a\u0010\u0011\u001a\u0004\u0018\u00010\u00042\u0006\u0010\r\u001a\u00020\u000e2\u0006\u0010\u000f\u001a\u00020\u000eH\u0016J\b\u0010\u0012\u001a\u00020\u000eH\u0016J\b\u0010\u0013\u001a\u00020\u000eH\u0016R\u0011\u0010\u0006\u001a\u00020\u0007¢\u0006\b\n\u0000\u001a\u0004\b\t\u0010\nR\u0018\u0010\u0002\u001a\f\u0012\u0006\u0012\u0004\u0018\u00010\u0004\u0018\u00010\u0003X\u0082\u0004¢\u0006\u0002\n\u0000R\u0018\u0010\u0005\u001a\f\u0012\u0006\u0012\u0004\u0018\u00010\u0004\u0018\u00010\u0003X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u0014"}, m5311d2 = {"Lcom/drake/brv/listener/ProxyDiffCallback;", "Landroidx/recyclerview/widget/DiffUtil$Callback;", "newModels", "", "", "oldModels", "callback", "Lcom/drake/brv/listener/ItemDifferCallback;", "(Ljava/util/List;Ljava/util/List;Lcom/drake/brv/listener/ItemDifferCallback;)V", "getCallback", "()Lcom/drake/brv/listener/ItemDifferCallback;", "areContentsTheSame", "", "oldItemPosition", "", "newItemPosition", "areItemsTheSame", "getChangePayload", "getNewListSize", "getOldListSize", "brv_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* loaded from: classes.dex */
public final class ProxyDiffCallback extends DiffUtil.Callback {

    /* renamed from: a */
    @Nullable
    public final List<Object> f9013a;

    /* renamed from: b */
    @Nullable
    public final List<Object> f9014b;

    /* renamed from: c */
    @NotNull
    public final ItemDifferCallback f9015c;

    public ProxyDiffCallback(@Nullable List<? extends Object> list, @Nullable List<? extends Object> list2, @NotNull ItemDifferCallback callback) {
        Intrinsics.checkNotNullParameter(callback, "callback");
        this.f9013a = list;
        this.f9014b = list2;
        this.f9015c = callback;
    }

    @Override // androidx.recyclerview.widget.DiffUtil.Callback
    public boolean areContentsTheSame(int oldItemPosition, int newItemPosition) {
        List<Object> list = this.f9014b;
        if (list == null || this.f9013a == null) {
            return false;
        }
        Object obj = list.get(oldItemPosition);
        Object obj2 = this.f9013a.get(newItemPosition);
        return (obj == null || obj2 == null) ? obj == null && obj2 == null : this.f9015c.mo1205c(obj, obj2);
    }

    @Override // androidx.recyclerview.widget.DiffUtil.Callback
    public boolean areItemsTheSame(int oldItemPosition, int newItemPosition) {
        List<Object> list = this.f9014b;
        if (list == null || this.f9013a == null) {
            return false;
        }
        Object obj = list.get(oldItemPosition);
        Object obj2 = this.f9013a.get(newItemPosition);
        return (obj == null || obj2 == null) ? obj == null && obj2 == null : this.f9015c.mo1204b(obj, obj2);
    }

    @Override // androidx.recyclerview.widget.DiffUtil.Callback
    @Nullable
    public Object getChangePayload(int oldItemPosition, int newItemPosition) {
        List<Object> list = this.f9014b;
        if (list == null || this.f9013a == null) {
            return null;
        }
        Object obj = list.get(oldItemPosition);
        Object obj2 = this.f9013a.get(newItemPosition);
        if (obj == null || obj2 == null) {
            return null;
        }
        return this.f9015c.mo1203a(obj, obj2);
    }

    @Override // androidx.recyclerview.widget.DiffUtil.Callback
    public int getNewListSize() {
        List<Object> list = this.f9013a;
        if (list == null) {
            return 0;
        }
        return list.size();
    }

    @Override // androidx.recyclerview.widget.DiffUtil.Callback
    public int getOldListSize() {
        List<Object> list = this.f9014b;
        if (list == null) {
            return 0;
        }
        return list.size();
    }
}
