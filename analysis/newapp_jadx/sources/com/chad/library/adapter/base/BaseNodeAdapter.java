package com.chad.library.adapter.base;

import android.view.ViewGroup;
import androidx.recyclerview.widget.DiffUtil;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p067b.p068a.p069a.p070a.p074j.p075c.AbstractC1298a;
import p005b.p067b.p068a.p069a.p070a.p074j.p075c.AbstractC1299b;
import p005b.p067b.p068a.p069a.p070a.p074j.p075c.InterfaceC1300c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000T\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u001e\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010!\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\b&\u0018\u00002\b\u0012\u0004\u0012\u00020\u00020\u0001J\u0017\u0010\u0005\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0005\u0010\u0006J/\u0010\f\u001a\b\u0012\u0004\u0012\u00020\u00020\u000b2\f\u0010\b\u001a\b\u0012\u0004\u0012\u00020\u00020\u00072\n\b\u0002\u0010\n\u001a\u0004\u0018\u00010\tH\u0002¢\u0006\u0004\b\f\u0010\rJ\u0017\u0010\u000f\u001a\u00020\t2\u0006\u0010\u000e\u001a\u00020\u0003H\u0014¢\u0006\u0004\b\u000f\u0010\u0010J\u001f\u0010\u0015\u001a\u00020\u00142\u0006\u0010\u0012\u001a\u00020\u00112\u0006\u0010\u0013\u001a\u00020\u0003H\u0014¢\u0006\u0004\b\u0015\u0010\u0016J\u001f\u0010\u0019\u001a\u00020\u00182\u000e\u0010\u0017\u001a\n\u0012\u0004\u0012\u00020\u0002\u0018\u00010\u000bH\u0016¢\u0006\u0004\b\u0019\u0010\u001aJ%\u0010\u001c\u001a\u00020\u00182\u0006\u0010\u0004\u001a\u00020\u00032\f\u0010\u001b\u001a\b\u0012\u0004\u0012\u00020\u00020\u0007H\u0016¢\u0006\u0004\b\u001c\u0010\u001dJ\u001d\u0010\u001c\u001a\u00020\u00182\f\u0010\u001b\u001a\b\u0012\u0004\u0012\u00020\u00020\u0007H\u0016¢\u0006\u0004\b\u001c\u0010\u001eJ\u0017\u0010\u001f\u001a\u00020\u00182\u0006\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u001f\u0010 J\u001d\u0010!\u001a\u00020\u00182\f\u0010\u001b\u001a\b\u0012\u0004\u0012\u00020\u00020\u0007H\u0016¢\u0006\u0004\b!\u0010\u001eJ\u001f\u0010\"\u001a\u00020\u00182\u000e\u0010\u001b\u001a\n\u0012\u0004\u0012\u00020\u0002\u0018\u00010\u000bH\u0016¢\u0006\u0004\b\"\u0010\u001aJ%\u0010\"\u001a\u00020\u00182\u0006\u0010$\u001a\u00020#2\f\u0010\u001b\u001a\b\u0012\u0004\u0012\u00020\u00020\u000bH\u0016¢\u0006\u0004\b\"\u0010%R&\u0010*\u001a\u0012\u0012\u0004\u0012\u00020\u00030&j\b\u0012\u0004\u0012\u00020\u0003`'8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b(\u0010)¨\u0006+"}, m5311d2 = {"Lcom/chad/library/adapter/base/BaseNodeAdapter;", "Lcom/chad/library/adapter/base/BaseProviderMultiAdapter;", "Lb/b/a/a/a/j/c/b;", "", "position", "h", "(I)I", "", "list", "", "isExpanded", "", "f", "(Ljava/util/Collection;Ljava/lang/Boolean;)Ljava/util/List;", "type", "isFixedViewType", "(I)Z", "Landroid/view/ViewGroup;", "parent", "viewType", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "onCreateDefViewHolder", "(Landroid/view/ViewGroup;I)Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "data", "", "setNewData", "(Ljava/util/List;)V", "newData", "addData", "(ILjava/util/Collection;)V", "(Ljava/util/Collection;)V", "remove", "(I)V", "replaceData", "setDiffNewData", "Landroidx/recyclerview/widget/DiffUtil$DiffResult;", "diffResult", "(Landroidx/recyclerview/widget/DiffUtil$DiffResult;Ljava/util/List;)V", "Ljava/util/HashSet;", "Lkotlin/collections/HashSet;", "b", "Ljava/util/HashSet;", "fullSpanNodeTypeSet", "com.github.CymChad.brvah"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes.dex */
public abstract class BaseNodeAdapter extends BaseProviderMultiAdapter<AbstractC1299b> {

    /* renamed from: b, reason: from kotlin metadata */
    @NotNull
    public final HashSet<Integer> fullSpanNodeTypeSet;

    public BaseNodeAdapter() {
        super(null);
        this.fullSpanNodeTypeSet = new HashSet<>();
    }

    /* renamed from: g */
    public static /* synthetic */ List m3900g(BaseNodeAdapter baseNodeAdapter, Collection collection, Boolean bool, int i2, Object obj) {
        int i3 = i2 & 2;
        return baseNodeAdapter.m3901f(collection, null);
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void addData(int i2, Object obj) {
        AbstractC1299b data = (AbstractC1299b) obj;
        Intrinsics.checkNotNullParameter(data, "data");
        addData(i2, (Collection<? extends AbstractC1299b>) CollectionsKt__CollectionsKt.arrayListOf(data));
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: f */
    public final List<AbstractC1299b> m3901f(Collection<? extends AbstractC1299b> list, Boolean isExpanded) {
        AbstractC1299b m310a;
        ArrayList arrayList = new ArrayList();
        for (AbstractC1299b abstractC1299b : list) {
            arrayList.add(abstractC1299b);
            if (abstractC1299b instanceof AbstractC1298a) {
                if (Intrinsics.areEqual(isExpanded, Boolean.TRUE) || ((AbstractC1298a) abstractC1299b).f1032a) {
                    List<AbstractC1299b> m309a = abstractC1299b.m309a();
                    if (!(m309a == null || m309a.isEmpty())) {
                        arrayList.addAll(m3901f(m309a, isExpanded));
                    }
                }
                if (isExpanded != null) {
                    ((AbstractC1298a) abstractC1299b).f1032a = isExpanded.booleanValue();
                }
            } else {
                List<AbstractC1299b> m309a2 = abstractC1299b.m309a();
                if (!(m309a2 == null || m309a2.isEmpty())) {
                    arrayList.addAll(m3901f(m309a2, isExpanded));
                }
            }
            if ((abstractC1299b instanceof InterfaceC1300c) && (m310a = ((InterfaceC1300c) abstractC1299b).m310a()) != null) {
                arrayList.add(m310a);
            }
        }
        return arrayList;
    }

    /* renamed from: h */
    public final int m3902h(int position) {
        int i2 = 0;
        if (position >= getData().size()) {
            return 0;
        }
        if (position < getData().size()) {
            AbstractC1299b abstractC1299b = getData().get(position);
            List<AbstractC1299b> m309a = abstractC1299b.m309a();
            if (!(m309a == null || m309a.isEmpty())) {
                if (!(abstractC1299b instanceof AbstractC1298a)) {
                    List<AbstractC1299b> m309a2 = abstractC1299b.m309a();
                    Intrinsics.checkNotNull(m309a2);
                    List m3900g = m3900g(this, m309a2, null, 2, null);
                    getData().removeAll(m3900g);
                    i2 = ((ArrayList) m3900g).size();
                } else if (((AbstractC1298a) abstractC1299b).f1032a) {
                    List<AbstractC1299b> m309a3 = abstractC1299b.m309a();
                    Intrinsics.checkNotNull(m309a3);
                    List m3900g2 = m3900g(this, m309a3, null, 2, null);
                    getData().removeAll(m3900g2);
                    i2 = ((ArrayList) m3900g2).size();
                }
            }
        }
        getData().remove(position);
        int i3 = i2 + 1;
        Object obj = (AbstractC1299b) getData().get(position);
        if (!(obj instanceof InterfaceC1300c) || ((InterfaceC1300c) obj).m310a() == null) {
            return i3;
        }
        getData().remove(position);
        return i3 + 1;
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public boolean isFixedViewType(int type) {
        return super.isFixedViewType(type) || this.fullSpanNodeTypeSet.contains(Integer.valueOf(type));
    }

    @Override // com.chad.library.adapter.base.BaseProviderMultiAdapter, com.chad.library.adapter.base.BaseQuickAdapter
    @NotNull
    public BaseViewHolder onCreateDefViewHolder(@NotNull ViewGroup parent, int viewType) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        BaseViewHolder onCreateDefViewHolder = super.onCreateDefViewHolder(parent, viewType);
        if (this.fullSpanNodeTypeSet.contains(Integer.valueOf(viewType))) {
            setFullSpan(onCreateDefViewHolder);
        }
        return onCreateDefViewHolder;
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void remove(int position) {
        notifyItemRangeRemoved(getHeaderLayoutCount() + position, m3902h(position));
        compatibilityDataSizeChanged(0);
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void replaceData(@NotNull Collection<? extends AbstractC1299b> newData) {
        Intrinsics.checkNotNullParameter(newData, "newData");
        if (Intrinsics.areEqual(newData, getData())) {
            return;
        }
        super.replaceData(m3900g(this, newData, null, 2, null));
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void setData(int i2, Object obj) {
        AbstractC1299b data = (AbstractC1299b) obj;
        Intrinsics.checkNotNullParameter(data, "data");
        int m3902h = m3902h(i2);
        List m3900g = m3900g(this, CollectionsKt__CollectionsKt.arrayListOf(data), null, 2, null);
        getData().addAll(i2, m3900g);
        ArrayList arrayList = (ArrayList) m3900g;
        if (m3902h == arrayList.size()) {
            notifyItemRangeChanged(getHeaderLayoutCount() + i2, m3902h);
        } else {
            notifyItemRangeRemoved(getHeaderLayoutCount() + i2, m3902h);
            notifyItemRangeInserted(getHeaderLayoutCount() + i2, arrayList.size());
        }
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void setDiffNewData(@Nullable List<AbstractC1299b> newData) {
        if (hasEmptyView()) {
            setNewData(newData);
            return;
        }
        if (newData == null) {
            newData = new ArrayList<>();
        }
        super.setDiffNewData(m3900g(this, newData, null, 2, null));
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void setNewData(@Nullable List<AbstractC1299b> data) {
        if (Intrinsics.areEqual(data, getData())) {
            return;
        }
        if (data == null) {
            data = new ArrayList<>();
        }
        super.setNewData(m3900g(this, data, null, 2, null));
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void addData(Object obj) {
        AbstractC1299b data = (AbstractC1299b) obj;
        Intrinsics.checkNotNullParameter(data, "data");
        addData((Collection<? extends AbstractC1299b>) CollectionsKt__CollectionsKt.arrayListOf(data));
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void setDiffNewData(@NotNull DiffUtil.DiffResult diffResult, @NotNull List<AbstractC1299b> newData) {
        Intrinsics.checkNotNullParameter(diffResult, "diffResult");
        Intrinsics.checkNotNullParameter(newData, "newData");
        if (hasEmptyView()) {
            setNewData(newData);
        } else {
            super.setDiffNewData(diffResult, m3900g(this, newData, null, 2, null));
        }
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void addData(int position, @NotNull Collection<? extends AbstractC1299b> newData) {
        Intrinsics.checkNotNullParameter(newData, "newData");
        super.addData(position, (Collection) m3900g(this, newData, null, 2, null));
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void addData(@NotNull Collection<? extends AbstractC1299b> newData) {
        Intrinsics.checkNotNullParameter(newData, "newData");
        super.addData((Collection) m3900g(this, newData, null, 2, null));
    }
}
