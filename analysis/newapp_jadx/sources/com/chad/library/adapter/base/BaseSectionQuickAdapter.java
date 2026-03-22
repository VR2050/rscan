package com.chad.library.adapter.base;

import android.view.ViewGroup;
import androidx.exifinterface.media.ExifInterface;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p067b.p068a.p069a.p070a.p074j.InterfaceC1297b;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000B\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0010!\n\u0002\u0010\u0000\n\u0002\b\u0003\b&\u0018\u0000*\b\b\u0000\u0010\u0002*\u00020\u0001*\b\b\u0001\u0010\u0004*\u00020\u00032\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00028\u00010\u0005J\u001f\u0010\t\u001a\u00020\b2\u0006\u0010\u0006\u001a\u00028\u00012\u0006\u0010\u0007\u001a\u00028\u0000H$¢\u0006\u0004\b\t\u0010\nJ\u0017\u0010\u000e\u001a\u00020\r2\u0006\u0010\f\u001a\u00020\u000bH\u0014¢\u0006\u0004\b\u000e\u0010\u000fJ\u001f\u0010\u0013\u001a\u00028\u00012\u0006\u0010\u0011\u001a\u00020\u00102\u0006\u0010\u0012\u001a\u00020\u000bH\u0014¢\u0006\u0004\b\u0013\u0010\u0014J\u001f\u0010\u0017\u001a\u00020\b2\u0006\u0010\u0015\u001a\u00028\u00012\u0006\u0010\u0016\u001a\u00020\u000bH\u0016¢\u0006\u0004\b\u0017\u0010\u0018J-\u0010\u0017\u001a\u00020\b2\u0006\u0010\u0015\u001a\u00028\u00012\u0006\u0010\u0016\u001a\u00020\u000b2\f\u0010\u001b\u001a\b\u0012\u0004\u0012\u00020\u001a0\u0019H\u0016¢\u0006\u0004\b\u0017\u0010\u001c¨\u0006\u001d"}, m5311d2 = {"Lcom/chad/library/adapter/base/BaseSectionQuickAdapter;", "Lb/b/a/a/a/j/b;", ExifInterface.GPS_DIRECTION_TRUE, "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "VH", "Lcom/chad/library/adapter/base/BaseMultiItemQuickAdapter;", "helper", "item", "", "c", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lb/b/a/a/a/j/b;)V", "", "type", "", "isFixedViewType", "(I)Z", "Landroid/view/ViewGroup;", "parent", "viewType", "onCreateDefViewHolder", "(Landroid/view/ViewGroup;I)Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "holder", "position", "onBindViewHolder", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;I)V", "", "", "payloads", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;ILjava/util/List;)V", "com.github.CymChad.brvah"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes.dex */
public abstract class BaseSectionQuickAdapter<T extends InterfaceC1297b, VH extends BaseViewHolder> extends BaseMultiItemQuickAdapter<T, VH> {
    /* renamed from: c */
    public abstract void m3909c(@NotNull VH helper, @NotNull T item);

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public boolean isFixedViewType(int type) {
        return super.isFixedViewType(type) || type == -99;
    }

    @Override // com.chad.library.adapter.base.BaseMultiItemQuickAdapter, com.chad.library.adapter.base.BaseQuickAdapter
    @NotNull
    public VH onCreateDefViewHolder(@NotNull ViewGroup parent, int viewType) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        VH vh = (VH) super.onCreateDefViewHolder(parent, viewType);
        if (viewType == -99) {
            setFullSpan(vh);
        }
        return vh;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.chad.library.adapter.base.BaseQuickAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
    public /* bridge */ /* synthetic */ void onBindViewHolder(RecyclerView.ViewHolder viewHolder, int i2, List list) {
        onBindViewHolder((BaseSectionQuickAdapter<T, VH>) viewHolder, i2, (List<Object>) list);
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.chad.library.adapter.base.BaseQuickAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
    public void onBindViewHolder(@NotNull VH holder, int position) {
        Intrinsics.checkNotNullParameter(holder, "holder");
        if (holder.getItemViewType() == -99) {
            m3909c(holder, (InterfaceC1297b) getItem(position - getHeaderLayoutCount()));
        } else {
            super.onBindViewHolder((BaseSectionQuickAdapter<T, VH>) holder, position);
        }
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void onBindViewHolder(@NotNull VH holder, int position, @NotNull List<Object> payloads) {
        Intrinsics.checkNotNullParameter(holder, "holder");
        Intrinsics.checkNotNullParameter(payloads, "payloads");
        if (payloads.isEmpty()) {
            onBindViewHolder((BaseSectionQuickAdapter<T, VH>) holder, position);
            return;
        }
        if (holder.getItemViewType() == -99) {
            InterfaceC1297b item = (InterfaceC1297b) getItem(position - getHeaderLayoutCount());
            Intrinsics.checkNotNullParameter(holder, "helper");
            Intrinsics.checkNotNullParameter(item, "item");
            Intrinsics.checkNotNullParameter(payloads, "payloads");
            return;
        }
        super.onBindViewHolder((BaseSectionQuickAdapter<T, VH>) holder, position, payloads);
    }
}
